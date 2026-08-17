const ESC: u8 = 0x1b;
const CR: u8 = 0x0d;
const LF: u8 = 0x0a;
const TAB: u8 = 0x09;
const BS: u8 = 0x08;
const DEL: u8 = 0x7f;
const CTRL_C: u8 = 0x03;
const CTRL_D: u8 = 0x04;
const MAX_CSI: usize = 32;

const KEY_ENTER: u16 = 13;
const KEY_ESC: u16 = 27;
const KEY_TAB: u16 = 9;
const KEY_BS: u16 = 127;
const KEY_BS_ALT: u16 = 8;
const KEY_C: u16 = 99;
const KEY_D: u16 = 100;
const MOD_CTRL: u16 = 4;

const PASTE_START: u16 = 200;
const PASTE_END: u16 = 201;

const WHEEL_UP: u16 = 64;
const WHEEL_DOWN: u16 = 65;

const VT_HOME_A: u16 = 1;
const VT_HOME_B: u16 = 7;
const VT_END_A: u16 = 4;
const VT_END_B: u16 = 8;
const VT_DELETE: u16 = 3;
const VT_PGUP: u16 = 5;
const VT_PGDN: u16 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Text(String),
    Enter,
    NewLine,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    Escape,
    Interrupt,
    Eof,
    ScrollUp,
    ScrollDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    Csi,
    Utf8,
}

#[derive(Debug)]
pub struct Parser {
    state: State,
    sequence: Vec<u8>,
    utf8: Vec<u8>,
    pending: usize,
    pasting: bool,
    paste: String,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            state: State::Ground,
            sequence: Vec::with_capacity(16),
            utf8: Vec::with_capacity(4),
            pending: 0,
            pasting: false,
            paste: String::new(),
        }
    }
}

impl Parser {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        for &byte in bytes {
            self.step(byte, &mut events);
        }
        events
    }

    fn step(&mut self, byte: u8, events: &mut Vec<Event>) {
        match self.state {
            State::Ground => self.ground(byte, events),
            State::Escape => {
                if byte == b'[' {
                    self.sequence.clear();
                    self.state = State::Csi;
                } else {
                    self.state = State::Ground;
                }
            }
            State::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    self.sequence.push(byte);
                    let sequence = std::mem::take(&mut self.sequence);
                    self.state = State::Ground;
                    self.csi(&sequence, events);
                } else if self.sequence.len() < MAX_CSI {
                    self.sequence.push(byte);
                } else {
                    self.sequence.clear();
                    self.state = State::Ground;
                }
            }
            State::Utf8 => {
                if byte & 0xc0 != 0x80 {
                    self.utf8.clear();
                    self.pending = 0;
                    self.state = State::Ground;
                    self.step(byte, events);
                    return;
                }
                self.utf8.push(byte);
                self.pending -= 1;
                if self.pending == 0 {
                    let decoded = std::str::from_utf8(&self.utf8).map(str::to_owned);
                    self.utf8.clear();
                    self.state = State::Ground;
                    if let Ok(text) = decoded {
                        self.emit_text(&text, events);
                    }
                }
            }
        }
    }

    fn ground(&mut self, byte: u8, events: &mut Vec<Event>) {
        match byte {
            ESC => self.state = State::Escape,
            CR | LF => {
                if self.pasting {
                    self.paste.push('\n');
                } else {
                    events.push(Event::Enter);
                }
            }
            TAB => {
                if self.pasting {
                    self.paste.push('\t');
                } else {
                    events.push(Event::Tab);
                }
            }
            DEL | BS if !self.pasting => events.push(Event::Backspace),
            CTRL_C if !self.pasting => events.push(Event::Interrupt),
            CTRL_D if !self.pasting => events.push(Event::Eof),
            0x00..=0x1f => {}
            0x20..=0x7f => self.emit_text(&(byte as char).to_string(), events),
            0xc0..=0xdf => self.begin_utf8(byte, 1),
            0xe0..=0xef => self.begin_utf8(byte, 2),
            0xf0..=0xf7 => self.begin_utf8(byte, 3),
            _ => {}
        }
    }

    fn begin_utf8(&mut self, lead: u8, pending: usize) {
        self.utf8.clear();
        self.utf8.push(lead);
        self.pending = pending;
        self.state = State::Utf8;
    }

    fn emit_text(&mut self, text: &str, events: &mut Vec<Event>) {
        if self.pasting {
            self.paste.push_str(text);
        } else {
            match events.last_mut() {
                Some(Event::Text(buffer)) => buffer.push_str(text),
                _ => events.push(Event::Text(text.to_owned())),
            }
        }
    }

    fn csi(&mut self, sequence: &[u8], events: &mut Vec<Event>) {
        let (body, final_byte) = sequence.split_at(sequence.len() - 1);
        let final_byte = final_byte[0];

        if body.first() == Some(&b'<') {
            self.mouse(&body[1..], final_byte, events);
            return;
        }

        let params = parse_params(body);

        match (final_byte, params.as_slice()) {
            (b'~', [PASTE_START]) => {
                self.pasting = true;
                self.paste.clear();
            }
            (b'~', [PASTE_END]) => {
                self.pasting = false;
                let pasted = std::mem::take(&mut self.paste);
                if !pasted.is_empty() {
                    events.push(Event::Text(pasted));
                }
            }
            _ if self.pasting => {}
            (b'u', [code, rest @ ..]) => {
                let modifiers = rest.first().copied().unwrap_or(1);
                if let Some(event) = key_u(*code, modifiers) {
                    events.push(event);
                }
            }
            (b'~', [KEY_ESC, modifiers, KEY_ENTER]) => events.push(enter_with(*modifiers)),
            (b'A', _) => events.push(Event::Up),
            (b'B', _) => events.push(Event::Down),
            (b'C', _) => events.push(Event::Right),
            (b'D', _) => events.push(Event::Left),
            (b'H', _) => events.push(Event::Home),
            (b'F', _) => events.push(Event::End),
            (b'~', [VT_HOME_A, ..]) | (b'~', [VT_HOME_B, ..]) => events.push(Event::Home),
            (b'~', [VT_END_A, ..]) | (b'~', [VT_END_B, ..]) => events.push(Event::End),
            (b'~', [VT_DELETE, ..]) => events.push(Event::Delete),
            (b'~', [VT_PGUP, ..]) => events.push(Event::PageUp),
            (b'~', [VT_PGDN, ..]) => events.push(Event::PageDown),
            _ => {}
        }
    }

    fn mouse(&mut self, body: &[u8], final_byte: u8, events: &mut Vec<Event>) {
        if final_byte != b'M' || self.pasting {
            return;
        }
        match parse_params(body).first() {
            Some(&WHEEL_UP) => events.push(Event::ScrollUp),
            Some(&WHEEL_DOWN) => events.push(Event::ScrollDown),
            _ => {}
        }
    }
}

fn enter_with(modifiers: u16) -> Event {
    if modifiers > 1 {
        Event::NewLine
    } else {
        Event::Enter
    }
}

fn key_u(code: u16, modifiers: u16) -> Option<Event> {
    let ctrl = (modifiers.saturating_sub(1)) & MOD_CTRL != 0;
    match code {
        KEY_ENTER => Some(enter_with(modifiers)),
        KEY_ESC => Some(Event::Escape),
        KEY_TAB => Some(Event::Tab),
        KEY_BS | KEY_BS_ALT => Some(Event::Backspace),
        KEY_C if ctrl => Some(Event::Interrupt),
        KEY_D if ctrl => Some(Event::Eof),
        _ => None,
    }
}

fn parse_params(body: &[u8]) -> Vec<u16> {
    body.split(|byte| *byte == b';')
        .map(|chunk| {
            chunk
                .iter()
                .filter(|byte| byte.is_ascii_digit())
                .fold(0u16, |acc, byte| {
                    acc.saturating_mul(10)
                        .saturating_add(u16::from(byte - b'0'))
                })
        })
        .collect()
}
