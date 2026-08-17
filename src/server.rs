use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::{TerminalOptions, Viewport};
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Handle, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Instant, interval_at, timeout};

use crate::agent;
use crate::blackbox::{Blackbox, DataKey, Record, SessionSlice, Who};
use crate::config::Config;
use crate::input::{Event, Parser};
use crate::text::Editor;
use crate::view::{self, Composer, Frame, Layout, Row};

const ALT_SCREEN_ON: &str = "\x1b[?1049h";
const ALT_SCREEN_OFF: &str = "\x1b[?1049l";
const CURSOR_HIDE: &str = "\x1b[?25l";
const CURSOR_SHOW: &str = "\x1b[?25h";
const PASTE_ON: &str = "\x1b[?2004h";
const PASTE_OFF: &str = "\x1b[?2004l";
const MOUSE_ON: &str = "\x1b[?1000h";
const MOUSE_OFF: &str = "\x1b[?1000l";
const SGR_MOUSE_ON: &str = "\x1b[?1006h";
const SGR_MOUSE_OFF: &str = "\x1b[?1006l";
const KITTY_KEYS_PUSH: &str = "\x1b[>1u";
const KITTY_KEYS_POP: &str = "\x1b[<u";

const ENTER_UI: [&str; 6] = [
    ALT_SCREEN_ON,
    CURSOR_HIDE,
    PASTE_ON,
    MOUSE_ON,
    SGR_MOUSE_ON,
    KITTY_KEYS_PUSH,
];
const LEAVE_UI: [&str; 6] = [
    KITTY_KEYS_POP,
    SGR_MOUSE_OFF,
    MOUSE_OFF,
    PASTE_OFF,
    CURSOR_SHOW,
    ALT_SCREEN_OFF,
];
const EVICTED: &str = "\r[session is terminating]\r\n";
const TIMED_OUT: &str = "\r[session timed out]\r\n";
const HANDOVER_GRACE: Duration = Duration::from_secs(2);
const SCROLL_STEP: usize = 3;
const DEFAULT_SIZE: (u16, u16) = (80, 24);
const INPUT_QUEUE: usize = 64;
const TICK: Duration = Duration::from_secs(1);

pub struct Ctx {
    pub config: Config,
    allowed: Vec<[u8; 32]>,
    blackbox: Mutex<Blackbox>,
    live: Mutex<Option<Live>>,
}

struct Live {
    evict: oneshot::Sender<oneshot::Sender<Carry>>,
}

#[derive(Debug, Default, Clone)]
struct Carry {
    text: String,
    cursor: usize,
    who: Option<Who>,
    scroll: usize,
}

impl Ctx {
    pub fn new(config: Config, allowed: Vec<[u8; 32]>, blackbox: Blackbox) -> Self {
        Self {
            config,
            allowed,
            blackbox: Mutex::new(blackbox),
            live: Mutex::new(None),
        }
    }

    fn permits(&self, fingerprint: &[u8; 32]) -> bool {
        self.allowed
            .iter()
            .any(|entry| bool::from(entry.ct_eq(fingerprint)))
    }

    async fn evict_current(&self) -> Carry {
        let previous = self.live.lock().await.take();
        let Some(live) = previous else {
            return Carry::default();
        };
        let (tx, rx) = oneshot::channel();
        if live.evict.send(tx).is_err() {
            return Carry::default();
        }
        timeout(HANDOVER_GRACE, rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default()
    }

    async fn install(&self, live: Live) {
        *self.live.lock().await = Some(live);
    }
}

pub struct Listener {
    ctx: Arc<Ctx>,
}

impl Listener {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }

    pub async fn serve(mut self, key: PrivateKey) -> Result<()> {
        let config = russh::server::Config {
            keys: vec![key],
            inactivity_timeout: Some(self.ctx.config.idle_timeout()),
            keepalive_interval: Some(self.ctx.config.keepalive_interval()),
            keepalive_max: self.ctx.config.session.keepalive_max,
            ..Default::default()
        };
        let address = (self.ctx.config.server.bind, self.ctx.config.server.port);
        self.run_on_address(Arc::new(config), address)
            .await
            .context("ssh listener failed")
    }
}

impl russh::server::Server for Listener {
    type Handler = Connection;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Connection {
        Connection {
            ctx: Arc::clone(&self.ctx),
            username: String::new(),
            key_blob: Vec::new(),
            channel: None,
            size: DEFAULT_SIZE,
            agent_requested: false,
            sender: None,
        }
    }
}

pub struct Connection {
    ctx: Arc<Ctx>,
    username: String,
    key_blob: Vec<u8>,
    channel: Option<ChannelId>,
    size: (u16, u16),
    agent_requested: bool,
    sender: Option<mpsc::Sender<Incoming>>,
}

#[derive(Debug)]
enum Incoming {
    Bytes(Vec<u8>),
    Resize(u16, u16),
}

impl russh::server::Handler for Connection {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let blob = key.to_bytes().map_err(|_| russh::Error::Inconsistent)?;
        let fingerprint = agent::fingerprint(&blob);
        if !self.ctx.permits(&fingerprint) {
            return Ok(Auth::reject());
        }
        self.username = user.to_owned();
        self.key_blob = blob;
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel = Some(channel.id());
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.agent_requested = true;
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        columns: u32,
        rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.size = (columns.max(1) as u16, rows.max(1) as u16);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        columns: u32,
        rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.size = (columns.max(1) as u16, rows.max(1) as u16);
        if let Some(sender) = &self.sender {
            let _ = sender.try_send(Incoming::Resize(self.size.0, self.size.1));
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();

        if !self.agent_requested {
            refuse(&handle, channel, "agent forwarding required, use ssh -A").await;
            return Ok(());
        }

        let (sender, receiver) = mpsc::channel(INPUT_QUEUE);
        self.sender = Some(sender);

        let ctx = Arc::clone(&self.ctx);
        let key_blob = self.key_blob.clone();
        let username = self.username.clone();
        let size = self.size;

        tokio::spawn(async move {
            let agent = match handle.channel_open_agent().await {
                Ok(channel) => channel.into_stream(),
                Err(_) => {
                    refuse(&handle, channel, "cannot reach ssh-agent").await;
                    return;
                }
            };

            let outcome = run(
                ctx,
                handle.clone(),
                channel,
                agent,
                key_blob,
                username,
                size,
                receiver,
            )
            .await;
            if let Err(error) = outcome {
                let message = format!("\r\nkipp: {error}\r\n");
                let _ = handle.data(channel, LEAVE_UI.concat()).await;
                let _ = handle.data(channel, message.into_bytes()).await;
            }
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channel != Some(channel) {
            return Ok(());
        }
        if let Some(sender) = &self.sender {
            let _ = sender.send(Incoming::Bytes(data.to_vec())).await;
        }
        Ok(())
    }
}

async fn refuse(handle: &Handle, channel: ChannelId, message: &str) {
    let text = format!("kipp: {message}\r\n");
    let _ = handle.data(channel, text.into_bytes()).await;
    let _ = handle.close(channel).await;
}

#[derive(Clone, Default)]
struct Outbox(Arc<StdMutex<Vec<u8>>>);

impl std::io::Write for Outbox {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("outbox mutex")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Outbox {
    fn drain(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().expect("outbox mutex"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: Arc<Ctx>,
    handle: Handle,
    channel: ChannelId,
    mut agent: S,
    key_blob: Vec<u8>,
    username: String,
    size: (u16, u16),
    mut incoming: mpsc::Receiver<Incoming>,
) -> Result<()> {
    let (key, mut sessions) = {
        let mut store = ctx.blackbox.lock().await;
        let fingerprint = agent::fingerprint(&key_blob);
        if !store.matches_key(&fingerprint) {
            bail!("archive belongs to a different key");
        }
        let challenge = store.header().challenge;
        let key: DataKey = if store.frame_count() == 0 {
            agent::derive_key_checked(&mut agent, &key_blob, &challenge).await?
        } else {
            agent::derive_key(&mut agent, &key_blob, &challenge).await?
        };
        store.verify_key(&key)?;
        let mut sessions = store.load_all(&key)?;
        sessions.push(SessionSlice {
            messages: Vec::new(),
        });
        (key, sessions)
    };

    let carry = ctx.evict_current().await;
    let (evict_tx, mut evict_rx) = oneshot::channel();
    ctx.install(Live { evict: evict_tx }).await;

    let zone = ctx.config.timezone();
    let mut today = jiff::Timestamp::now().to_zoned(zone.clone()).date();

    let outbox = Outbox::default();
    let mut area = Rect::new(0, 0, size.0, size.1);
    let mut terminal = Terminal::with_options(
        CrosstermBackend::new(outbox.clone()),
        TerminalOptions {
            viewport: Viewport::Fixed(area),
        },
    )?;

    let mut editor = Editor::default();
    editor.restore(carry.text, carry.cursor);
    let mut who = carry.who.unwrap_or(Who::User);
    let mut scroll = carry.scroll;

    let dated = |ts: i64| {
        jiff::Timestamp::from_millisecond(ts)
            .map(|t| t.to_zoned(zone.clone()).date())
            .unwrap_or(today)
            != today
    };
    let wide = sessions
        .iter()
        .flat_map(|s| &s.messages)
        .any(|m| dated(m.ts));

    let mut parser = Parser::default();
    let mut layout = Layout::new(&username, ctx.config.ui.text_width, area.width, wide);
    let mut composer = Composer::new(zone.clone(), today, layout);
    let mut rows = composer.rows(&sessions, true);
    let mut started: Option<i64> = None;
    let mut timed_out = false;

    handle.data(channel, ENTER_UI.concat()).await.ok();

    let mut ticker = interval_at(Instant::now() + TICK, TICK);
    let idle = ctx.config.idle_timeout();
    let mut deadline = Instant::now() + idle;
    let mut dirty = true;

    let evicted = 'session: loop {
        if dirty {
            let now = jiff::Timestamp::now().to_zoned(zone.clone());
            let clock = format!("{:02}:{:02}:{:02}", now.hour(), now.minute(), now.second());
            let frame = Frame {
                rows: &rows,
                scroll,
                layout,
                editor: &editor,
                who,
                user: &username,
                clock,
            };
            let mut cursor = (0u16, 0u16);
            terminal.draw(|f| {
                cursor = view::draw(f.buffer_mut(), area, &frame);
                f.set_cursor_position(cursor);
            })?;
            let mut painted = outbox.drain();
            painted.extend_from_slice(CURSOR_SHOW.as_bytes());
            if !painted.is_empty() {
                handle.data(channel, painted).await.ok();
            }
            dirty = false;
        }

        tokio::select! {
            biased;

            carrier = &mut evict_rx => break 'session carrier.ok(),

            message = incoming.recv() => {
                let Some(message) = message else { break 'session None };
                deadline = Instant::now() + idle;
                match message {
                    Incoming::Resize(columns, lines) => {
                        area = Rect::new(0, 0, columns, lines);
                        terminal.resize(area)?;
                        layout =
                            Layout::new(&username, ctx.config.ui.text_width, area.width, wide);
                        composer = Composer::new(zone.clone(), today, layout);
                        rows = composer.rows(&sessions, true);
                        dirty = true;
                    }
                    Incoming::Bytes(bytes) => {
                        for event in parser.feed(&bytes) {
                            let action = apply(
                                event,
                                &mut editor,
                                &mut who,
                                &mut scroll,
                                &rows,
                                layout,
                                area.height,
                            );
                            match action {
                                Action::Quit => break 'session None,
                                Action::Send => {
                                    let text = editor.take();
                                    let trimmed = text.trim_end().to_owned();
                                    if trimmed.is_empty() {
                                        continue;
                                    }
                                    let ts = jiff::Timestamp::now().as_millisecond();
                                    let mut store = ctx.blackbox.lock().await;
                                    if started.is_none() {
                                        store.append(&key, &Record::SessionStart { started: ts })?;
                                        started = Some(ts);
                                    }
                                    store.append(
                                        &key,
                                        &Record::Message { ts, who, text: trimmed.clone() },
                                    )?;
                                    drop(store);
                                    if let Some(current) = sessions.last_mut() {
                                        current.messages.push(crate::blackbox::Message {
                                            ts,
                                            who,
                                            text: trimmed,
                                        });
                                    }
                                    rows = composer.rows(&sessions, true);
                                    scroll = 0;
                                    who = who.toggled();
                                }
                                Action::Redraw => {}
                                Action::Ignore => continue,
                            }
                            dirty = true;
                        }
                    }
                }
            }

            _ = ticker.tick() => {
                let current = jiff::Timestamp::now().to_zoned(zone.clone()).date();
                if current != today {
                    today = current;
                    composer = Composer::new(zone.clone(), today, layout);
                    rows = composer.rows(&sessions, true);
                    dirty = true;
                } else if scroll == 0 {
                    dirty = true;
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
                timed_out = true;
                break 'session None;
            }
        }
    };

    handle.data(channel, LEAVE_UI.concat()).await.ok();

    if let Some(carrier) = evicted {
        handle.data(channel, EVICTED.as_bytes()).await.ok();
        let (cursor, text) = (editor.cursor(), editor.text().to_owned());
        let _ = carrier.send(Carry {
            text,
            cursor,
            who: Some(who),
            scroll,
        });
    } else {
        let notice = if timed_out { TIMED_OUT } else { EVICTED };
        handle.data(channel, notice.as_bytes()).await.ok();
        *ctx.live.lock().await = None;
    }

    Ok(())
}

enum Action {
    Ignore,
    Redraw,
    Send,
    Quit,
}

fn apply(
    event: Event,
    editor: &mut Editor,
    who: &mut Who,
    scroll: &mut usize,
    rows: &[Row],
    layout: Layout,
    height: u16,
) -> Action {
    let width = layout.text_width as usize;
    let ceiling = rows.len().saturating_sub(height.saturating_sub(1) as usize);

    match event {
        Event::Text(text) => {
            editor.insert(&text);
            *scroll = 0;
            Action::Redraw
        }
        Event::Enter => Action::Send,
        Event::NewLine => {
            editor.insert("\n");
            *scroll = 0;
            Action::Redraw
        }
        Event::Backspace => {
            editor.backspace();
            Action::Redraw
        }
        Event::Delete => {
            editor.delete();
            Action::Redraw
        }
        Event::Left => {
            editor.left();
            Action::Redraw
        }
        Event::Right => {
            editor.right();
            Action::Redraw
        }
        Event::Home => {
            editor.home(width);
            Action::Redraw
        }
        Event::End => {
            editor.end(width);
            Action::Redraw
        }
        Event::Tab => {
            *who = who.toggled();
            Action::Redraw
        }
        Event::Escape => Action::Quit,
        Event::Up => {
            if editor.up(width) {
                Action::Redraw
            } else {
                scroll_up(scroll, ceiling, 1)
            }
        }
        Event::Down => {
            if *scroll > 0 {
                *scroll = scroll.saturating_sub(1);
                Action::Redraw
            } else if editor.down(width) {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        Event::ScrollUp => scroll_up(scroll, ceiling, SCROLL_STEP),
        Event::ScrollDown => {
            *scroll = scroll.saturating_sub(SCROLL_STEP);
            Action::Redraw
        }
        Event::PageUp => scroll_up(scroll, ceiling, height as usize / 2),
        Event::PageDown => {
            *scroll = scroll.saturating_sub(height as usize / 2);
            Action::Redraw
        }
        Event::Interrupt => {
            if editor.text().is_empty() {
                Action::Quit
            } else {
                editor.clear();
                Action::Redraw
            }
        }
        Event::Eof => {
            if editor.text().is_empty() {
                Action::Quit
            } else {
                Action::Ignore
            }
        }
    }
}

fn scroll_up(scroll: &mut usize, ceiling: usize, step: usize) -> Action {
    *scroll = (*scroll + step.max(1)).min(ceiling);
    Action::Redraw
}
