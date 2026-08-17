use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

const MIN_TEXT_WIDTH: u16 = 20;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: Server,
    pub ui: Ui,
    pub session: Session,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub bind: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ui {
    pub text_width: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Session {
    pub idle_timeout_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_max: usize,
    pub timezone: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind: IpAddr::from([0, 0, 0, 0]),
            port: 2222,
        }
    }
}

impl Default for Ui {
    fn default() -> Self {
        Self { text_width: 72 }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 1800,
            keepalive_interval_secs: 30,
            keepalive_max: 3,
            timezone: "UTC".into(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let config: Self =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                config.validate()?;
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.ui.text_width >= MIN_TEXT_WIDTH,
            "ui.text_width must be at least {MIN_TEXT_WIDTH}"
        );
        anyhow::ensure!(
            self.session.idle_timeout_secs > 0,
            "session.idle_timeout_secs must be positive"
        );
        anyhow::ensure!(
            jiff::tz::TimeZone::get(&self.session.timezone).is_ok(),
            "session.timezone is not a known IANA zone",
        );
        Ok(())
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.session.idle_timeout_secs)
    }

    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(self.session.keepalive_interval_secs)
    }

    pub fn timezone(&self) -> jiff::tz::TimeZone {
        jiff::tz::TimeZone::get(&self.session.timezone).unwrap_or(jiff::tz::TimeZone::UTC)
    }
}
