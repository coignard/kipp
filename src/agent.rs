use anyhow::{Context, Result, bail, ensure};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

use crate::blackbox::DataKey;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";
const SSHSIG_NAMESPACE: &str = "kipp.blackbox";
const SSHSIG_HASH: &str = "sha512";

const HKDF_INFO: &[u8] = b"kipp/v1/data";
const ED25519: &str = "ssh-ed25519";
const MAX_AGENT_MESSAGE: u32 = 256 * 1024;
const KEY_LEN: usize = 32;

pub fn fingerprint(key_blob: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&Sha256::digest(key_blob));
    out
}

fn key_algorithm(key_blob: &[u8]) -> Result<String> {
    let mut reader = Reader::new(key_blob);
    let algorithm = reader.string()?;
    String::from_utf8(algorithm.to_vec()).context("key algorithm is not utf-8")
}

pub fn ensure_supported(key_blob: &[u8]) -> Result<()> {
    let algorithm = key_algorithm(key_blob)?;
    ensure!(
        algorithm == ED25519,
        "key must be ssh-ed25519, not {algorithm}"
    );
    Ok(())
}

pub async fn derive_key<T: AsyncRead + AsyncWrite + Unpin>(
    agent: &mut T,
    key_blob: &[u8],
    challenge: &[u8; KEY_LEN],
) -> Result<DataKey> {
    ensure_supported(key_blob)?;
    ensure_loaded(agent, key_blob).await?;
    let mut signature = sign(agent, key_blob, challenge).await?;
    let key = expand(&signature, challenge);
    signature.zeroize();
    Ok(key)
}

pub async fn derive_key_checked<T: AsyncRead + AsyncWrite + Unpin>(
    agent: &mut T,
    key_blob: &[u8],
    challenge: &[u8; KEY_LEN],
) -> Result<DataKey> {
    ensure_supported(key_blob)?;
    ensure_loaded(agent, key_blob).await?;
    let mut first = sign(agent, key_blob, challenge).await?;
    let mut second = sign(agent, key_blob, challenge).await?;
    let stable: bool = first.ct_eq(&second).into();
    let key = expand(&first, challenge);
    first.zeroize();
    second.zeroize();
    ensure!(stable, "agent signatures are not deterministic");
    Ok(key)
}

fn expand(signature: &[u8], challenge: &[u8; KEY_LEN]) -> DataKey {
    let hk = Hkdf::<Sha512>::new(Some(challenge.as_slice()), signature);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO, key.as_mut_slice())
        .expect("valid hkdf length");
    key
}

async fn ensure_loaded<T: AsyncRead + AsyncWrite + Unpin>(
    agent: &mut T,
    key_blob: &[u8],
) -> Result<()> {
    let response = roundtrip(agent, &[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
    let mut reader = Reader::new(&response);
    match reader.byte()? {
        SSH_AGENT_IDENTITIES_ANSWER => {}
        other => bail!("agent refused to list identities (response type {other})"),
    }
    let count = reader.u32()?;
    let mut present = false;
    for _ in 0..count {
        let blob = reader.string()?;
        let _comment = reader.string()?;
        present |= blob == key_blob;
    }
    ensure!(present, "key not loaded in ssh-agent, run ssh-add");
    Ok(())
}

async fn sign<T: AsyncRead + AsyncWrite + Unpin>(
    agent: &mut T,
    key_blob: &[u8],
    challenge: &[u8; KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    let blob = sshsig_blob(challenge);

    let mut request = Vec::new();
    request.push(SSH_AGENTC_SIGN_REQUEST);
    put_string(&mut request, key_blob);
    put_string(&mut request, &blob);
    request.extend_from_slice(&0u32.to_be_bytes());

    let response = roundtrip(agent, &request).await?;
    let mut reader = Reader::new(&response);
    match reader.byte()? {
        SSH_AGENT_SIGN_RESPONSE => {}
        other => bail!("agent declined to sign (response type {other})"),
    }
    let signature = reader.string()?;

    let mut inner = Reader::new(signature);
    let algorithm = inner.string()?;
    ensure!(
        algorithm == ED25519.as_bytes(),
        "agent returned a non-ed25519 signature"
    );

    Ok(Zeroizing::new(signature.to_vec()))
}

fn sshsig_blob(challenge: &[u8; KEY_LEN]) -> Vec<u8> {
    let digest = Sha512::digest(challenge);
    let mut blob = Vec::new();
    blob.extend_from_slice(SSHSIG_MAGIC);
    put_string(&mut blob, SSHSIG_NAMESPACE.as_bytes());
    put_string(&mut blob, &[]);
    put_string(&mut blob, SSHSIG_HASH.as_bytes());
    put_string(&mut blob, &digest);
    blob
}

async fn roundtrip<T: AsyncRead + AsyncWrite + Unpin>(
    agent: &mut T,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut framed = Vec::with_capacity(size_of::<u32>() + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    agent
        .write_all(&framed)
        .await
        .context("writing ssh agent request")?;
    agent.flush().await.context("flushing ssh agent request")?;

    let mut prefix = [0u8; size_of::<u32>()];
    agent
        .read_exact(&mut prefix)
        .await
        .context("reading ssh agent reply length")?;
    let len = u32::from_be_bytes(prefix);
    ensure!(
        len > 0 && len <= MAX_AGENT_MESSAGE,
        "ssh agent reply length {len} is out of range"
    );

    let mut body = vec![0u8; len as usize];
    agent
        .read_exact(&mut body)
        .await
        .context("reading ssh agent reply")?;
    Ok(body)
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let value = *self.buf.get(self.at).context("truncated ssh wire data")?;
        self.at += 1;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32> {
        let end = self.at + size_of::<u32>();
        let slice = self
            .buf
            .get(self.at..end)
            .context("truncated ssh wire integer")?;
        self.at = end;
        Ok(u32::from_be_bytes(
            slice.try_into().expect("slice is four bytes"),
        ))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self.at + len;
        let slice = self
            .buf
            .get(self.at..end)
            .context("truncated ssh wire string")?;
        self.at = end;
        Ok(slice)
    }
}
