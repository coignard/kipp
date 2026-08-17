mod agent;
mod blackbox;
mod config;
mod input;
mod server;
mod text;
mod view;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use rand::Rng;
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use zeroize::Zeroize;

use crate::blackbox::Blackbox;
use crate::config::Config;
use crate::server::{Ctx, Listener};

const HOST_KEY: &str = "ssh_host_ed25519_key";
const AUTHORIZED: &str = "authorized_keys";
const ARCHIVE: &str = "blackbox.bin";

#[derive(Debug, Parser)]
#[command(
    name = "kipp",
    version,
    override_usage = "kipp [-cdpb]",
    help_template = "usage: {usage}\n"
)]
struct Cli {
    #[arg(short = 'c', long, env = "KIPP_CONFIG", default_value = "kipp.toml")]
    config: PathBuf,

    #[arg(short = 'd', long, env = "KIPP_DATA", default_value = "data")]
    data: PathBuf,

    #[arg(short = 'p', long, env = "KIPP_PORT")]
    port: Option<u16>,

    #[arg(short = 'b', long, env = "KIPP_BIND")]
    bind: Option<IpAddr>,
}

fn main() -> Result<()> {
    harden();
    let cli = Cli::parse();

    let mut config = Config::load(&cli.config)?;
    if let Some(port) = cli.port {
        config.server.port = port;
    }
    if let Some(bind) = cli.bind {
        config.server.bind = bind;
    }

    std::fs::create_dir_all(&cli.data)
        .with_context(|| format!("creating {}", cli.data.display()))?;

    let host_key = load_host_key(&cli.data.join(HOST_KEY))?;
    let allowed = load_allowlist(&cli.data.join(AUTHORIZED))?;
    let owner = *allowed.first().context("authorized_keys is empty")?;
    let store = Blackbox::open_or_create(&cli.data.join(ARCHIVE), owner)?;

    let ctx = Arc::new(Ctx::new(config, allowed, store));
    let address = (ctx.config.server.bind, ctx.config.server.port);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async move {
        eprintln!("kipp listening on {}:{}", address.0, address.1);
        let listener = Listener::new(Arc::clone(&ctx));
        tokio::select! {
            result = listener.serve(host_key) => result,
            _ = shutdown() => {
                eprintln!("kipp shutting down");
                Ok(())
            }
        }
    })
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(_) => return std::future::pending().await,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(stream) => stream,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

fn harden() {
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

fn load_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return PrivateKey::from_openssh(&text)
            .with_context(|| format!("parsing {}", path.display()));
    }

    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    seed.zeroize();
    let encoded = key
        .to_openssh(LineEnding::LF)
        .context("encoding host key")?;
    std::fs::write(path, encoded.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    restrict(path)?;
    eprintln!("kipp generated a new host key at {}", path.display());
    Ok(key)
}

fn restrict(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
}

fn load_allowlist(path: &Path) -> Result<Vec<[u8; 32]>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut allowed = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = PublicKey::from_openssh(line)
            .with_context(|| format!("parsing a key in {}", path.display()))?;
        let blob = key.to_bytes().context("encoding public key")?;
        agent::ensure_supported(&blob)?;
        allowed.push(agent::fingerprint(&blob));
    }

    if allowed.is_empty() {
        bail!("{} contains no usable ed25519 keys", path.display());
    }
    Ok(allowed)
}
