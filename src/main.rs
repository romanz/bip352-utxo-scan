use std::collections::HashMap;
use std::iter::once;
use std::path::PathBuf;

use clap::Parser;
use log::*;

use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use rayon::prelude::*;
use silentpayments::receiving::Label;

type Error = Box<dyn std::error::Error>;

use utxo::{Coin, Reader};

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Convert Bitcoin UTXO to DuckDB.
struct Args {
    /// Bitcoin UTXO file to read.
    #[arg(short = 'i')]
    input: PathBuf,
}

fn label_pubkey(
    secp: &Secp256k1<All>,
    label: &Label,
    spend_pubkey: &PublicKey,
) -> Result<PublicKey, Error> {
    let result = SecretKey::from_slice(&label.as_inner().to_be_bytes())?.public_key(secp);

    // check that the combined key with spend_key is valid
    result.combine(spend_pubkey)?;

    Ok(result)
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .format_timestamp_micros()
        .init();

    let mut prev = 0;

    let mut total_p2tr_coins = 0;
    let mut total_tweak_found = 0;
    let mut total_txs = 0;
    let mut total_coins = 0;

    let secp = Secp256k1::new();
    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let _scan_pk = scan_sk.public_key(&secp);
    let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let spend_pk = spend_sk.public_key(&secp);

    let labels = vec![Label::new(scan_sk, 0)];
    let labels = labels
        .into_iter()
        .map(|label| {
            let pk = label_pubkey(&secp, &label, &spend_pk)?;
            Ok((label, pk))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let reader = Reader::open(args.input)?;
    let index = bindex::IndexedChain::open("../bindex/__db_sptweaks/", reader.network)?;
    let mut tweaks = index.tweaks();

    let t = std::time::Instant::now();

    let mut items = reader.filter_map(|item| {
        let (txid, coins) = item.expect("utxo scan failed");
        total_txs += 1;
        total_coins += coins.len();
        let p2tr_coins: Vec<_> = coins
            .into_iter()
            .filter_map(|(_void, coin)| coin.script.is_p2tr().then_some(coin))
            .collect();

        if p2tr_coins.is_empty() {
            return None;
        }

        total_p2tr_coins += p2tr_coins.len();

        let found_tweaks = tweaks.scan(&txid).expect("tweak scan failed");
        if found_tweaks.len() > 1 {
            warn!("txid prefix collision: {}", txid);
        }
        total_tweak_found += found_tweaks.len();

        let curr = txid[0];
        if prev != curr {
            prev = curr;
            eprint!(".");
        }
        Some((txid, p2tr_coins, found_tweaks))
    });

    std::iter::from_fn(|| {
        let chunk: Vec<_> = items.by_ref().take(16 << 10).collect();
        (!chunk.is_empty()).then_some(chunk)
    })
    .par_bridge()
    .for_each(|chunk| {
        for (txid, p2tr_coins, found_tweaks) in chunk {
            for found in found_tweaks {
                let found_tweak = found.tweak();
                let shared = found_tweak.mul_tweak(&secp, &scan_sk.into()).unwrap();
                match scan_transaction(&secp, &spend_pk, &shared, &p2tr_coins, &labels) {
                    Ok(res) if res.is_empty() => (),
                    Ok(res) => info!("Found {}: {:?}", txid, res),
                    Err(e) => error!("Failed: {}", e),
                }
            }
        }
    });

    let us = t.elapsed().as_micros();
    info!("txs: {:.3} M", total_txs as f32 / 1e6);
    info!("tweaks: {:.3} M", total_tweak_found as f32 / 1e6);
    info!(
        "time per tweak: {:.3} [us]",
        us as f32 / total_tweak_found as f32
    );
    info!(
        "coins (p2tr): {:.3} M ({:.3} M)",
        total_coins as f32 / 1e6,
        total_p2tr_coins as f32 / 1e6
    );
    Ok(())
}

fn scan_transaction(
    secp: &Secp256k1<All>,
    spend_pubkey: &PublicKey,
    ecdh_shared_secret: &PublicKey,
    p2tr_coins: &[Coin],
    labels: &[(Label, PublicKey)],
) -> Result<HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>>, Error> {
    let xonly_pubkeys = p2tr_pubkeys(p2tr_coins);

    let mut result: HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>> = HashMap::new();
    for k in 0.. {
        let hash = SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
        let tweak: Scalar = SecretKey::from_slice(&hash)?.into();

        match scan_labels(secp, &xonly_pubkeys, labels, spend_pubkey, tweak)? {
            Some((label, p2tr_pubkey, tweak)) => {
                // add found entry and continue scanning
                result.entry(label).or_default().insert(p2tr_pubkey, tweak);
            }
            None => break, // not found - stop scanning
        }
    }
    Ok(result)
}

fn scan_labels(
    secp: &Secp256k1<All>,
    xonly_pubkeys: &[XOnlyPublicKey],
    labels: &[(Label, PublicKey)],
    spend_pubkey: &PublicKey,
    tweak: Scalar,
) -> Result<Option<(Option<Label>, XOnlyPublicKey, Scalar)>, Error> {
    let tweaked_pubkey = spend_pubkey.add_exp_tweak(secp, &tweak)?;

    for item in once(None).chain(labels.iter().map(Some)) {
        let (label, tweaked) = match item {
            None => (None, tweaked_pubkey), // no label -> no extra tweak
            Some((label, pk)) => (Some(label), tweaked_pubkey.combine(pk)?),
        };
        let (xonly_pubkey, _parity) = tweaked.x_only_public_key();
        if xonly_pubkeys.contains(&xonly_pubkey) {
            return Ok(Some((label.cloned(), xonly_pubkey, tweak)));
        }
    }
    Ok(None)
}

fn p2tr_pubkeys(coins: &[utxo::Coin]) -> Vec<XOnlyPublicKey> {
    coins
        .iter()
        .filter_map(|coin| {
            let script = &coin.script;
            assert!(script.is_p2tr());
            let bytes = &script.as_bytes()[2..];
            XOnlyPublicKey::from_slice(bytes).ok()
        })
        .collect()
}

use bitcoin::hashes::{sha256t_hash_newtype, Hash, HashEngine};

sha256t_hash_newtype! {
    struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    struct InputsHash(_);

    struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    struct LabelHash(_);

    struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    struct SharedSecretHash(_);
}

impl SharedSecretHash {
    pub(crate) fn from_ecdh_and_k(ecdh: &PublicKey, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}
