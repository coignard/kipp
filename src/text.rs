use std::ops::Range;

use unicode_linebreak::{BreakOpportunity, linebreaks};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub fn display_width(text: &str) -> usize {
    text.width()
}

pub fn wrap(text: &str, width: usize) -> Vec<Range<usize>> {
    let width = width.max(1);
    let mut lines: Vec<Range<usize>> = Vec::new();
    if text.is_empty() {
        lines.push(0..0);
        return lines;
    }

    let mut line_start = 0usize;
    let mut cursor = 0usize;
    let mut used = 0usize;

    for (index, opportunity) in linebreaks(text) {
        let segment = &text[cursor..index];
        let visible = segment.trim_end();
        let visible_width = display_width(visible);

        if used > 0 && used + visible_width > width {
            lines.push(line_start..cursor);
            line_start = cursor;
            used = 0;
        }

        if visible_width > width {
            let mut chunk_start = cursor;
            let mut chunk_used = used;
            for (offset, grapheme) in segment.grapheme_indices(true) {
                let at = cursor + offset;
                let grapheme_width = display_width(grapheme);
                if chunk_used + grapheme_width > width && at > chunk_start {
                    lines.push(chunk_start..at);
                    chunk_start = at;
                    chunk_used = 0;
                }
                chunk_used += grapheme_width;
            }
            line_start = chunk_start;
            used = chunk_used;
        } else {
            used += display_width(segment);
        }

        cursor = index;

        if opportunity == BreakOpportunity::Mandatory && index < text.len() {
            lines.push(line_start..cursor);
            line_start = cursor;
            used = 0;
        }
    }

    lines.push(line_start..text.len());
    lines
}

pub fn visible<'a>(text: &'a str, range: &Range<usize>) -> &'a str {
    text[range.clone()].trim_end_matches(['\n', '\r'])
}

#[derive(Debug, Default)]
pub struct Editor {
    text: String,
    cursor: usize,
}

impl Editor {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn take(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.text)
    }

    pub fn restore(&mut self, text: String, cursor: usize) {
        self.cursor = cursor.min(text.len());
        self.text = text;
        self.snap();
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    pub fn insert(&mut self, fragment: &str) {
        let cleaned: String = fragment
            .chars()
            .filter(|c| *c == '\n' || !c.is_control())
            .collect();
        if cleaned.is_empty() {
            return;
        }
        self.text.insert_str(self.cursor, &cleaned);
        self.cursor += cleaned.len();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = self.prev_boundary(self.cursor);
        self.text.replace_range(start..self.cursor, "");
        self.cursor = start;
    }

    pub fn delete(&mut self) {
        if self.cursor >= self.text.len() {
            return;
        }
        let end = self.next_boundary(self.cursor);
        self.text.replace_range(self.cursor..end, "");
    }

    pub fn left(&mut self) {
        self.cursor = self.prev_boundary(self.cursor);
    }

    pub fn right(&mut self) {
        self.cursor = self.next_boundary(self.cursor);
    }

    pub fn home(&mut self, width: usize) {
        let lines = wrap(&self.text, width);
        if let Some(line) = self.line_of(&lines) {
            self.cursor = lines[line].start;
        }
    }

    pub fn end(&mut self, width: usize) {
        let lines = wrap(&self.text, width);
        if let Some(line) = self.line_of(&lines) {
            let range = &lines[line];
            self.cursor = visible(&self.text, range).len() + range.start;
        }
    }

    pub fn up(&mut self, width: usize) -> bool {
        self.step(width, true)
    }

    pub fn down(&mut self, width: usize) -> bool {
        self.step(width, false)
    }

    pub fn position(&self, width: usize) -> (usize, usize) {
        let lines = wrap(&self.text, width);
        let line = self.line_of(&lines).unwrap_or(0);
        let column = display_width(&self.text[lines[line].start..self.cursor]);
        (line, column)
    }

    pub fn line_count(&self, width: usize) -> usize {
        wrap(&self.text, width).len()
    }

    fn step(&mut self, width: usize, up: bool) -> bool {
        let lines = wrap(&self.text, width);
        let Some(line) = self.line_of(&lines) else {
            return false;
        };
        let target = if up {
            if line == 0 {
                return false;
            }
            line - 1
        } else {
            if line + 1 >= lines.len() {
                return false;
            }
            line + 1
        };
        let column = display_width(&self.text[lines[line].start..self.cursor]);
        self.cursor = offset_at_column(&self.text, &lines[target], column);
        true
    }

    fn line_of(&self, lines: &[Range<usize>]) -> Option<usize> {
        if lines.is_empty() {
            return None;
        }
        let found = lines
            .iter()
            .position(|range| self.cursor >= range.start && self.cursor < range.end);
        Some(found.unwrap_or(lines.len() - 1))
    }

    fn snap(&mut self) {
        while self.cursor < self.text.len() && !self.text.is_char_boundary(self.cursor) {
            self.cursor += 1;
        }
    }

    fn prev_boundary(&self, at: usize) -> usize {
        self.text[..at]
            .grapheme_indices(true)
            .next_back()
            .map(|(index, _)| index)
            .unwrap_or(0)
    }

    fn next_boundary(&self, at: usize) -> usize {
        self.text[at..]
            .graphemes(true)
            .next()
            .map(|grapheme| at + grapheme.len())
            .unwrap_or(self.text.len())
    }
}

fn offset_at_column(text: &str, range: &Range<usize>, column: usize) -> usize {
    let slice = visible(text, range);
    let mut used = 0usize;
    for (offset, grapheme) in slice.grapheme_indices(true) {
        let next = used + display_width(grapheme);
        if next > column {
            return range.start + offset;
        }
        used = next;
    }
    range.start + slice.len()
}
