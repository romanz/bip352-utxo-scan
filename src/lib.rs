use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use bitcoin::{
    consensus::Decodable,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160},
    script::{PushBytesBuf, PushBytesError},
    BlockHash, PublicKey, ScriptBuf, Txid, VarInt,
};

type Error = Box<dyn std::error::Error>;

/// Bitcoin Core varint != `rust-bitcoin`` VarInt
fn decode_varint<R: bitcoin::io::Read>(r: &mut R) -> Result<u64, Error> {
    let mut n = 0u64;
    // TODO: add checks
    let mut buf = [0u8; 1];
    loop {
        r.read_exact(&mut buf)?;
        let b = buf[0];
        n = (n << 7) | (b & 0x7F) as u64;
        if b & 0x80 != 0 {
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

pub struct Coin {
    pub height: u64,
    pub coinbase: bool,
    pub amount: u64,
    pub script: ScriptBuf,
}

fn decode_coin<R: bitcoin::io::Read>(r: &mut R) -> Result<Coin, Error> {
    let code = decode_varint(r)?;
    let height = code >> 1;
    let coinbase = (code & 1) != 0;
    let amount = decompress_amount(decode_varint(r)?);

    let script = decode_script(r)?;
    Ok(Coin {
        height,
        coinbase,
        amount,
        script,
    })
}

fn decompress_amount(mut x: u64) -> u64 {
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if x == 0 {
        return 0;
    }
    x -= 1;
    // x = 10*(9*n + d - 1) + e
    let mut e = x % 10;
    x /= 10;
    let mut n;
    if e < 9 {
        // x = 9*n + d - 1
        let d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    while e > 0 {
        n *= 10;
        e -= 1;
    }
    n
}

const SPECIAL_SCRIPTS: usize = 6;

fn decode_script<R: bitcoin::io::Read>(r: &mut R) -> Result<ScriptBuf, Error> {
    let len: usize = decode_varint(r)?.try_into()?;
    Ok(if len < SPECIAL_SCRIPTS {
        let script_type = len as u8;
        let size = match script_type {
            0 | 1 => 20,
            2..=5 => 32,
            _ => unreachable!(),
        };
        let mut compressed = vec![0u8; size];
        r.read_exact(&mut compressed)?;
        decompress_script(script_type, compressed)?
    } else {
        let size = len - SPECIAL_SCRIPTS;
        let mut buf = vec![0u8; size];
        r.read_exact(&mut buf)?;
        ScriptBuf::from_bytes(buf)
    })
}

fn decompress_script(script_type: u8, mut bytes: Vec<u8>) -> Result<ScriptBuf, Error> {
    let builder = bitcoin::blockdata::script::Builder::new();
    let script = match script_type {
        0 => builder
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(into_push_bytes(bytes)?)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG),
        1 => builder
            .push_opcode(OP_HASH160)
            .push_slice(into_push_bytes(bytes)?)
            .push_opcode(OP_EQUAL),
        2 | 3 => {
            bytes.insert(0, script_type);
            builder
                .push_slice(into_push_bytes(bytes)?)
                .push_opcode(OP_CHECKSIG)
        }
        4 | 5 => {
            bytes.insert(0, script_type - 2);
            let mut pubkey = PublicKey::from_slice(&bytes)?;
            pubkey.compressed = false;
            builder.push_key(&pubkey).push_opcode(OP_CHECKSIG)
        }
        _ => unreachable!(),
    }
    .into_script();
    assert!(script.is_p2pk() || script.is_p2pkh() || script.is_p2sh());
    Ok(script)
}

fn into_push_bytes(bytes: Vec<u8>) -> Result<PushBytesBuf, PushBytesError> {
    bytes.try_into()
}

pub struct Reader {
    pub network: bitcoin::network::Network,
    pub block_hash: BlockHash,
    num_utxos: usize,
    input: BufReader<File>,
}

impl Reader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut input = BufReader::new(File::open(path)?);
        let mut bytes = [0u8; 5];
        input.read_exact(&mut bytes)?;
        if &bytes != b"utxo\xFF" {
            return Err(format!("Unsupported magic: {bytes:?}").into());
        }

        let mut bytes = [0u8; 2];
        input.read_exact(&mut bytes)?;
        let version = u16::from_le_bytes(bytes);
        if version != 2 {
            return Err(format!("Unsupported UTXO version: {version}").into());
        }

        let mut bytes = [0u8; 4];
        input.read_exact(&mut bytes)?;
        let network: bitcoin::network::Network =
            bitcoin::p2p::Magic::from_bytes(bytes).try_into()?;

        let mut bytes = [0u8; 32];
        input.read_exact(&mut bytes)?;
        let block_hash = BlockHash::from_byte_array(bytes);

        let mut bytes = [0u8; 8];
        input.read_exact(&mut bytes)?;
        let num_utxos = u64::from_le_bytes(bytes).try_into().unwrap();

        Ok(Self {
            network,
            block_hash,
            num_utxos,
            input,
        })
    }

    fn read(&mut self) -> Result<(Txid, Vec<(u32, Coin)>), Error> {
        let txid = Txid::consensus_decode(&mut self.input)?;
        let num_coins = VarInt::consensus_decode(&mut self.input)?.0;
        assert!(num_coins > 0 && num_coins < 1_000_000);
        let mut coins = Vec::with_capacity(num_coins.try_into().unwrap());
        for _ in 0..num_coins {
            let vout = VarInt::consensus_decode(&mut self.input)?;
            let coin = decode_coin(&mut self.input)?;
            coins.push((vout.0.try_into().unwrap(), coin));
        }
        Ok((txid, coins))
    }
}

impl Iterator for Reader {
    type Item = Result<(Txid, Vec<(u32, Coin)>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num_utxos == 0 {
            return None;
        }
        Some(self.read().map(|(txid, coins)| {
            self.num_utxos = self
                .num_utxos
                .checked_sub(coins.len())
                .expect("too many coins");
            (txid, coins)
        }))
    }
}
