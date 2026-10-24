//! Reading and sanitising a process's command line for display to a human
//! approving an access request.
//!
//! The command line is attacker-influenced text shown on a trusted approval
//! screen, so control and bidirectional-override characters are neutralised.
//! Secrets are deliberately *not* redacted.

use std::{fs::File, io::Read, path::Path};

/// Maximum number of bytes read from `/proc/<pid>/cmdline`.
pub const MAX_CMDLINE_READ_BYTES: u64 = 4096;
/// Maximum number of characters in the formatted command line (including the
/// ellipsis marker when truncated).
pub const MAX_CMDLINE_CHARS: usize = 1000;

const ELLIPSIS: char = '…';
const REPLACEMENT: char = '\u{FFFD}';

/// Read the command line of `pid` from the procfs at `proc_root`.
/// Missing, unreadable or empty (kernel threads, zombies) yields an empty string.
pub fn read_command_line(proc_root: &Path, pid: u32) -> String {
    let path = proc_root.join(pid.to_string()).join("cmdline");
    let Ok(file) = File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    if file
        .take(MAX_CMDLINE_READ_BYTES)
        .read_to_end(&mut buf)
        .is_err()
    {
        return String::new();
    }
    format_command_line(&buf)
}

/// Turn raw NUL-separated `cmdline` bytes into a single safe display string.
pub fn format_command_line(raw: &[u8]) -> String {
    let args: Vec<_> = raw
        .split(|&b| b == 0)
        // trailing NUL yields one empty tail element; drop empties at the end only
        .collect();
    let end = args
        .iter()
        .rposition(|a| !a.is_empty())
        .map_or(0, |i| i + 1);
    let joined = args[..end]
        .iter()
        .map(|a| String::from_utf8_lossy(a))
        .collect::<Vec<_>>()
        .join(" ");
    truncate_chars(neutralise(&joined), MAX_CMDLINE_CHARS)
}

fn is_bidi_or_separator(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'                  // Arabic letter mark
        | '\u{200E}' | '\u{200F}'   // LRM, RLM
        | '\u{202A}'..='\u{202E}'   // embeddings and overrides
        | '\u{2066}'..='\u{2069}'   // isolates
        | '\u{2028}' | '\u{2029}'   // line / paragraph separators
    )
}

/// Replace control characters (newline, ESC, C1, ...) and bidi controls with U+FFFD.
fn neutralise(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_bidi_or_separator(c) {
                REPLACEMENT
            } else {
                c
            }
        })
        .collect()
}

fn truncate_chars(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push(ELLIPSIS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_nul_separated_args() {
        assert_eq!(
            format_command_line(b"ssh\0-p\x002222\0host.invalid\0"),
            "ssh -p 2222 host.invalid"
        );
    }

    #[test]
    fn empty_and_all_nul_inputs_are_empty() {
        assert_eq!(format_command_line(b""), "");
        assert_eq!(format_command_line(b"\0\0\0"), "");
    }

    #[test]
    fn preserves_empty_middle_arguments() {
        assert_eq!(format_command_line(b"prog\0\0arg\0"), "prog  arg");
    }

    #[test]
    fn invalid_utf8_is_lossy_not_error() {
        let out = format_command_line(b"prog\0\xff\xfe\0");
        assert!(out.starts_with("prog "));
        assert!(out.contains('\u{FFFD}'));
    }

    #[test]
    fn control_characters_are_neutralised() {
        let out = format_command_line(b"echo\0line1\nline2\0\x1b[31mred\0tab\there\0\x7f\xc2\x85");
        assert!(!out.chars().any(|c| c.is_control()), "{out:?}");
        assert!(out.contains("line1\u{FFFD}line2"));
        assert!(out.contains("\u{FFFD}[31mred"));
    }

    #[test]
    fn bidi_controls_are_neutralised() {
        let input = "a\u{202E}b\u{2066}c\u{200F}d\u{2028}e";
        let out = format_command_line(input.as_bytes());
        assert_eq!(out, "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e");
    }

    #[test]
    fn ordinary_unicode_is_preserved() {
        assert_eq!(
            format_command_line("echo\0héllo\0日本語".as_bytes()),
            "echo héllo 日本語"
        );
    }

    #[test]
    fn long_command_lines_are_truncated_with_ellipsis() {
        let raw = "a".repeat(5000);
        let out = format_command_line(raw.as_bytes());
        assert_eq!(out.chars().count(), MAX_CMDLINE_CHARS);
        assert!(out.ends_with(ELLIPSIS));
    }

    #[test]
    fn exactly_max_chars_is_not_truncated() {
        let raw = "b".repeat(MAX_CMDLINE_CHARS);
        let out = format_command_line(raw.as_bytes());
        assert_eq!(out, raw);
    }

    #[test]
    fn multibyte_truncation_does_not_split_characters() {
        let raw = "é".repeat(2000);
        let out = format_command_line(raw.as_bytes());
        assert_eq!(out.chars().count(), MAX_CMDLINE_CHARS);
    }

    #[test]
    fn missing_pid_yields_empty_string() {
        assert_eq!(read_command_line(Path::new("/proc"), u32::MAX), "");
        assert_eq!(
            read_command_line(Path::new("/nonexistent-proc-root"), 1),
            ""
        );
    }

    #[test]
    fn reads_own_command_line() {
        let out = read_command_line(Path::new("/proc"), std::process::id());
        assert!(!out.is_empty());
    }
}
