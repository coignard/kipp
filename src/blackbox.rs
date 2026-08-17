use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"KIPP";
const VERSION: u8 = 1;
const KEY_LEN: usize = 32;

const VERSION_AT: usize = MAGIC.len();
const FINGERPRINT_AT: usize = VERSION_AT + 1;
const CHALLENGE_AT: usize = FINGERPRINT_AT + KEY_LEN;
const HEADER_LEN: usize = CHALLENGE_AT + KEY_LEN;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const LEN_PREFIX: usize = 4;
const SEQ_LEN: usize = 8;
const AAD_LEN: usize = SEQ_LEN + TAG_LEN;
const MAX_FRAME: u32 = 1 << 20;
const ZSTD_LEVEL: i32 = 19;

const FLAG_RAW: u8 = 0;
const FLAG_ZSTD: u8 = 1;

pub type DataKey = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Who {
    User,
    Kipp,
}

impl Who {
    pub fn toggled(self) -> Self {
        match self {
            Who::User => Who::Kipp,
            Who::Kipp => Who::User,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Record {
    #[serde(rename = "s")]
    SessionStart {
        #[serde(rename = "t")]
        started: i64,
    },
    #[serde(rename = "m")]
    Message {
        #[serde(rename = "t")]
        ts: i64,
        #[serde(rename = "w")]
        who: Who,
        #[serde(rename = "x")]
        text: String,
    },
}

#[derive(Debug, Clone)]
pub struct Message {
    pub ts: i64,
    pub who: Who,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct SessionSlice {
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone, Copy)]
struct FrameLoc {
    offset: u64,
    len: u32,
    tag: [u8; TAG_LEN],
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub fingerprint: [u8; KEY_LEN],
    pub challenge: [u8; KEY_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..VERSION_AT].copy_from_slice(&MAGIC);
        out[VERSION_AT] = VERSION;
        out[FINGERPRINT_AT..CHALLENGE_AT].copy_from_slice(&self.fingerprint);
        out[CHALLENGE_AT..HEADER_LEN].copy_from_slice(&self.challenge);
        out
    }

    fn decode(raw: &[u8; HEADER_LEN]) -> Result<Self> {
        ensure!(raw[..VERSION_AT] == MAGIC, "not a kipp blackbox file");
        ensure!(
            raw[VERSION_AT] == VERSION,
            "unsupported blackbox version {}",
            raw[VERSION_AT]
        );
        let mut fingerprint = [0u8; KEY_LEN];
        let mut challenge = [0u8; KEY_LEN];
        fingerprint.copy_from_slice(&raw[FINGERPRINT_AT..CHALLENGE_AT]);
        challenge.copy_from_slice(&raw[CHALLENGE_AT..HEADER_LEN]);
        Ok(Self {
            fingerprint,
            challenge,
        })
    }
}

pub struct Blackbox {
    file: File,
    header: Header,
    frames: Vec<FrameLoc>,
    end: u64,
}

impl Blackbox {
    pub fn open_or_create(path: &Path, fingerprint: [u8; KEY_LEN]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;

        let size = file.metadata()?.len();
        let header = if size == 0 {
            let mut challenge = [0u8; KEY_LEN];
            rand::rng().fill_bytes(&mut challenge);
            let header = Header {
                fingerprint,
                challenge,
            };
            file.write_all(&header.encode())?;
            file.sync_all()?;
            sync_parent(path)?;
            header
        } else {
            ensure!(size >= HEADER_LEN as u64, "blackbox file is truncated");
            let mut raw = [0u8; HEADER_LEN];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut raw)?;
            Header::decode(&raw)?
        };

        let mut store = Self {
            file,
            header,
            frames: Vec::new(),
            end: HEADER_LEN as u64,
        };
        store.rebuild_index()?;
        Ok(store)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    pub fn matches_key(&self, fingerprint: &[u8; KEY_LEN]) -> bool {
        use subtle::ConstantTimeEq;
        self.header.fingerprint.ct_eq(fingerprint).into()
    }

    fn rebuild_index(&mut self) -> Result<()> {
        self.frames.clear();
        let size = self.file.metadata()?.len();
        let mut offset = HEADER_LEN as u64;
        self.file.seek(SeekFrom::Start(offset))?;

        let mut prefix = [0u8; LEN_PREFIX];
        let mut tag = [0u8; TAG_LEN];

        loop {
            if size - offset < (LEN_PREFIX + NONCE_LEN + TAG_LEN) as u64 {
                break;
            }
            if self.file.read_exact(&mut prefix).is_err() {
                break;
            }
            let len = u32::from_le_bytes(prefix);
            if len < TAG_LEN as u32 || len > MAX_FRAME {
                break;
            }
            let body = NONCE_LEN as u64 + u64::from(len);
            if size - offset - (LEN_PREFIX as u64) < body {
                break;
            }
            let next = offset + LEN_PREFIX as u64 + body;
            self.file.seek(SeekFrom::Start(next - TAG_LEN as u64))?;
            if self.file.read_exact(&mut tag).is_err() {
                break;
            }
            self.frames.push(FrameLoc { offset, len, tag });
            offset = next;
            self.file.seek(SeekFrom::Start(offset))?;
        }

        self.end = offset;
        if offset < size {
            self.file.set_len(offset)?;
            self.file.sync_all()?;
        }
        Ok(())
    }

    fn aad(&self, index: usize) -> [u8; AAD_LEN] {
        let mut aad = [0u8; AAD_LEN];
        aad[..SEQ_LEN].copy_from_slice(&(index as u64).to_le_bytes());
        if index > 0 {
            aad[SEQ_LEN..].copy_from_slice(&self.frames[index - 1].tag);
        }
        aad
    }

    fn read_frame(&mut self, index: usize) -> Result<(Vec<u8>, Vec<u8>)> {
        let loc = self.frames[index];
        let mut nonce = vec![0u8; NONCE_LEN];
        let mut ct = vec![0u8; loc.len as usize];
        self.file
            .seek(SeekFrom::Start(loc.offset + LEN_PREFIX as u64))?;
        self.file.read_exact(&mut nonce)?;
        self.file.read_exact(&mut ct)?;
        Ok((nonce, ct))
    }

    fn decrypt(&mut self, key: &DataKey, index: usize) -> Result<Record> {
        ensure!(index < self.frames.len(), "frame {index} out of range");
        let aad = self.aad(index);
        let (nonce, ct) = self.read_frame(index)?;
        let plain = cipher(key)
            .decrypt(
                &xnonce(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("frame {index} failed authentication"))?;
        decode_payload(&plain)
    }

    pub fn append(&mut self, key: &DataKey, record: &Record) -> Result<usize> {
        let plain = encode_payload(record)?;
        let index = self.frames.len();
        let aad = self.aad(index);

        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);

        let ct = cipher(key)
            .encrypt(
                &xnonce(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("frame encryption failed"))?;
        ensure!(ct.len() <= MAX_FRAME as usize, "record too large");

        let mut framed = Vec::with_capacity(LEN_PREFIX + NONCE_LEN + ct.len());
        framed.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&ct);

        self.file.seek(SeekFrom::Start(self.end))?;
        self.file.write_all(&framed)?;
        self.file.sync_all()?;

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&ct[ct.len() - TAG_LEN..]);
        self.frames.push(FrameLoc {
            offset: self.end,
            len: ct.len() as u32,
            tag,
        });
        self.end += framed.len() as u64;
        Ok(index)
    }

    pub fn load_all(&mut self, key: &DataKey) -> Result<Vec<SessionSlice>> {
        let mut records = Vec::with_capacity(self.frames.len());
        for index in 0..self.frames.len() {
            records.push(self.decrypt(key, index)?);
        }
        Ok(group(records))
    }

    pub fn verify_key(&mut self, key: &DataKey) -> Result<()> {
        if self.frames.is_empty() {
            return Ok(());
        }
        self.decrypt(key, 0)
            .map(|_| ())
            .context("wrong key for this archive")
    }
}

fn cipher(key: &DataKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.as_slice()).expect("data key is 32 bytes")
}

fn xnonce(bytes: &[u8]) -> XNonce {
    XNonce::try_from(bytes).expect("nonce is 24 bytes")
}

fn group(records: Vec<Record>) -> Vec<SessionSlice> {
    let mut out: Vec<SessionSlice> = Vec::new();
    for record in records {
        match record {
            Record::SessionStart { .. } => out.push(SessionSlice {
                messages: Vec::new(),
            }),
            Record::Message { ts, who, text } => {
                if let Some(current) = out.last_mut() {
                    current.messages.push(Message { ts, who, text });
                }
            }
        }
    }
    out
}

fn encode_payload(record: &Record) -> Result<Vec<u8>> {
    let mut cbor = Vec::new();
    ciborium::into_writer(record, &mut cbor).context("serializing record")?;
    let squeezed = zstd::bulk::compress(&cbor, ZSTD_LEVEL).ok();
    let mut out = Vec::new();
    match squeezed {
        Some(bytes) if bytes.len() < cbor.len() => {
            out.push(FLAG_ZSTD);
            out.extend_from_slice(&bytes);
        }
        _ => {
            out.push(FLAG_RAW);
            out.extend_from_slice(&cbor);
        }
    }
    Ok(out)
}

fn decode_payload(plain: &[u8]) -> Result<Record> {
    let (&flag, body) = plain.split_first().context("empty frame payload")?;
    let cbor = match flag {
        FLAG_RAW => body.to_vec(),
        FLAG_ZSTD => {
            zstd::bulk::decompress(body, MAX_FRAME as usize).context("decompressing frame")?
        }
        other => bail!("unknown payload flag {other}"),
    };
    ciborium::from_reader(cbor.as_slice()).context("deserializing record")
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
