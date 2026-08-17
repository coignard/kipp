use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};

use crate::blackbox::{SessionSlice, Who};
use crate::text::{self, Editor};

const DATE_LEN: usize = 10;
const TIME_LEN: usize = 8;
const DATE_GAP: usize = 1;
const LABEL_PAD: usize = 4;
const INPUT_DIVISOR: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub who_width: u16,
    pub text_width: u16,
    pub gutter: u16,
    pub wide: bool,
}

impl Layout {
    pub fn new(user: &str, configured_width: u16, terminal_width: u16, wide: bool) -> Self {
        let who_width = user.chars().count().max("kipp".chars().count()) as u16;
        let gutter = if wide {
            wide_gutter(who_width)
        } else {
            narrow_gutter(who_width)
        };
        let total = configured_width.min(terminal_width);
        let text_width = total.saturating_sub(gutter).max(1);
        Self {
            who_width,
            text_width,
            gutter,
            wide,
        }
    }

    fn span(&self) -> u16 {
        self.gutter + self.text_width
    }
}

fn narrow_gutter(who_width: u16) -> u16 {
    TIME_LEN as u16 + 1 + who_width + 1 + 1 + 1
}

fn wide_gutter(who_width: u16) -> u16 {
    narrow_gutter(who_width) + (DATE_LEN + DATE_GAP) as u16
}

#[derive(Debug, Clone)]
pub enum Row {
    Line {
        date: Option<Date>,
        time: Option<String>,
        who: Option<Who>,
        text: String,
    },
    SessionBreak,
    DayBreak(Date),
    ArchiveStart,
}

pub struct Composer {
    zone: TimeZone,
    today: Date,
    layout: Layout,
}

impl Composer {
    pub fn new(zone: TimeZone, today: Date, layout: Layout) -> Self {
        Self {
            zone,
            today,
            layout,
        }
    }

    pub fn rows(&self, sessions: &[SessionSlice], complete: bool) -> Vec<Row> {
        let mut rows = Vec::new();
        if complete {
            rows.push(Row::ArchiveStart);
        }

        let mut day: Option<Date> = None;
        let mut pending_break = false;
        let mut first = true;

        for session in sessions {
            if !first {
                pending_break = true;
            }
            first = false;

            for message in &session.messages {
                let zoned = self.zoned(message.ts);
                let date = zoned.date();
                if day != Some(date) {
                    if day.is_some() {
                        rows.push(Row::DayBreak(date));
                    }
                    day = Some(date);
                    pending_break = false;
                } else if pending_break {
                    rows.push(Row::SessionBreak);
                    pending_break = false;
                }
                self.push_message(&mut rows, date, &zoned, message.who, &message.text);
            }
        }

        if pending_break {
            match day {
                Some(last) if last != self.today => rows.push(Row::DayBreak(self.today)),
                _ => rows.push(Row::SessionBreak),
            }
        }
        rows
    }

    fn push_message(
        &self,
        rows: &mut Vec<Row>,
        date: Date,
        zoned: &jiff::Zoned,
        who: Who,
        body: &str,
    ) {
        let stamp = format!(
            "{:02}:{:02}:{:02}",
            zoned.hour(),
            zoned.minute(),
            zoned.second()
        );
        let shown = (date != self.today).then_some(date);
        let width = self.layout.text_width as usize;

        for (index, range) in text::wrap(body, width).into_iter().enumerate() {
            let content = text::visible(body, &range).to_owned();
            if index == 0 {
                rows.push(Row::Line {
                    date: shown,
                    time: Some(stamp.clone()),
                    who: Some(who),
                    text: content,
                });
            } else {
                rows.push(Row::Line {
                    date: shown,
                    time: None,
                    who: None,
                    text: content,
                });
            }
        }
    }

    fn zoned(&self, ts: i64) -> jiff::Zoned {
        Timestamp::from_millisecond(ts)
            .unwrap_or(Timestamp::UNIX_EPOCH)
            .to_zoned(self.zone.clone())
    }
}

fn session_separator(width: u16) -> String {
    let width = width as usize;
    let mut out = "- ".repeat(width / 2);
    if width % 2 == 1 {
        out.push('-');
    }
    out
}

fn day_separator(date: Date, width: u16) -> String {
    let label = date.strftime("%Y-%m-%d").to_string();
    let total = width as usize;
    let overlay = label.chars().count() + LABEL_PAD;
    if total <= overlay {
        return label;
    }
    let side = (total - overlay) / 2;
    let dashes = "- ".repeat(side.div_ceil(2));
    let flank = &dashes[..side];
    let mut out = String::with_capacity(total);
    out.push_str(flank);
    out.push_str("  ");
    out.push_str(&label);
    out.push_str("  ");
    out.push_str(flank);
    while text::display_width(&out) < total {
        out.push(' ');
    }
    out
}

pub struct Frame<'a> {
    pub rows: &'a [Row],
    pub scroll: usize,
    pub layout: Layout,
    pub editor: &'a Editor,
    pub who: Who,
    pub user: &'a str,
    pub clock: String,
}

pub fn draw(buffer: &mut Buffer, area: Rect, frame: &Frame<'_>) -> (u16, u16) {
    let text_width = frame.layout.text_width;
    let input_lines = frame
        .editor
        .line_count(text_width as usize)
        .min(area.height as usize / INPUT_DIVISOR)
        .max(1);
    let history_height = area.height.saturating_sub(input_lines as u16);

    let end = frame.rows.len().saturating_sub(frame.scroll);
    let start = end.saturating_sub(history_height as usize);
    let window = &frame.rows[start..end];

    let gutter = frame.layout.gutter;

    let top = area.y + history_height.saturating_sub(window.len() as u16);
    for (offset, row) in window.iter().enumerate() {
        let y = top + offset as u16;
        paint(buffer, area.x, y, row, frame, gutter);
    }

    let input_y = area.y + history_height;
    paint_input(buffer, area.x, input_y, input_lines as u16, frame, gutter)
}

fn paint(buffer: &mut Buffer, x: u16, y: u16, row: &Row, frame: &Frame<'_>, gutter: u16) {
    let span = frame.layout.span();
    match row {
        Row::SessionBreak => {
            buffer.set_string(x, y, session_separator(span), Style::default());
        }
        Row::DayBreak(date) => {
            buffer.set_string(x, y, day_separator(*date, span), Style::default());
        }
        Row::ArchiveStart => {
            buffer.set_string(x, y, "", Style::default());
        }
        Row::Line {
            date,
            time,
            who,
            text,
        } => {
            let name = who.map(|w| speaker(w, frame));
            let prefix = gutter_text(*date, time.as_deref(), name, frame.layout);
            let style = line_style(*who);
            buffer.set_string(x, y, &prefix, style);
            buffer.set_string(x + gutter, y, text, style);
        }
    }
}

fn paint_input(
    buffer: &mut Buffer,
    x: u16,
    y: u16,
    height: u16,
    frame: &Frame<'_>,
    gutter: u16,
) -> (u16, u16) {
    let width = frame.layout.text_width as usize;
    let body = frame.editor.text();
    let lines = text::wrap(body, width);
    let (cursor_line, cursor_column) = frame.editor.position(width);

    let skip = cursor_line.saturating_sub(height.saturating_sub(1) as usize);
    let style = line_style(Some(frame.who));

    for (offset, range) in lines.iter().skip(skip).take(height as usize).enumerate() {
        let index = skip + offset;
        let row_y = y + offset as u16;
        let prefix = if index == 0 {
            gutter_text(
                None,
                Some(&frame.clock),
                Some(speaker(frame.who, frame)),
                frame.layout,
            )
        } else {
            gutter_text(None, None, None, frame.layout)
        };
        buffer.set_string(x, row_y, &prefix, style);
        buffer.set_string(x + gutter, row_y, text::visible(body, range), style);
    }

    (
        x + gutter + cursor_column as u16,
        y + (cursor_line - skip) as u16,
    )
}

fn speaker<'a>(who: Who, frame: &Frame<'a>) -> &'a str {
    match who {
        Who::User => frame.user,
        Who::Kipp => "kipp",
    }
}

fn line_style(who: Option<Who>) -> Style {
    match who {
        Some(Who::Kipp) => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    }
}

fn gutter_text(
    date: Option<Date>,
    time: Option<&str>,
    who: Option<&str>,
    layout: Layout,
) -> String {
    let mut out = String::new();
    if layout.wide {
        match date {
            Some(value) => out.push_str(&value.strftime("%Y-%m-%d").to_string()),
            None => out.push_str(&" ".repeat(DATE_LEN)),
        }
        out.push(' ');
    }
    match time {
        Some(value) => out.push_str(value),
        None => out.push_str(&" ".repeat(TIME_LEN)),
    }
    out.push(' ');
    let name = who.unwrap_or("");
    out.push_str(name);
    for _ in text::display_width(name)..layout.who_width as usize {
        out.push(' ');
    }
    out.push(' ');
    out.push('|');
    out.push(' ');
    out
}
