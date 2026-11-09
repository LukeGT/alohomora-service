//! Builds the process chain (caller and all its ancestors) shown to the
//! approver, within the size budget of the push notification.

use serde::{Deserialize, Serialize};

use crate::{
    process_cmdline::read_command_line_uncapped,
    process_tree::{ChainEnd, ProcTree},
};

/// Maximum number of chain entries (caller included).
pub const MAX_CHAIN_ENTRIES: usize = 16;
/// Maximum characters of each entry's command line.
pub const MAX_ENTRY_CMDLINE_CHARS: usize = 200;
/// Maximum serialized size of the entry list in bytes (FCM allows 4096 total).
pub const MAX_CHAIN_BYTES: usize = 2500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub comm: String,
    pub cmdline: String,
    /// Characters (code points) cut from the sanitised cmdline, by the per-entry
    /// cap and by size-budget shortening; 0 if nothing was cut. The kept text
    /// then ends in a single `…` marker that is not counted as kept. If the
    /// `/proc` read itself stopped at 4096 bytes, counting starts from what was read.
    #[serde(default)]
    pub truncated_chars: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandChain {
    pub entries: Vec<ChainEntry>,
    pub end: ChainEnd,
}

/// Chain for the caller `pid`: caller first, then each ancestor up to pid 1.
/// `process_name` is used as the caller's `comm` if its `/proc` entry is gone.
pub fn command_chain_for_caller(
    tree: &ProcTree,
    pid: u32,
    process_name: Option<&str>,
) -> CommandChain {
    let (walked, end) = tree.walk(pid, MAX_CHAIN_ENTRIES);
    let mut entries: Vec<ChainEntry> = walked
        .into_iter()
        .map(|e| {
            let (cmdline, truncated_chars) =
                cap_cmdline(read_command_line_uncapped(tree.root(), e.pid));
            ChainEntry {
                pid: e.pid,
                ppid: Some(e.ppid),
                cmdline,
                comm: e.comm,
                truncated_chars,
            }
        })
        .collect();
    if entries.is_empty() {
        entries.push(ChainEntry {
            pid,
            ppid: None,
            comm: process_name.unwrap_or_default().to_string(),
            cmdline: String::new(),
            truncated_chars: 0,
        });
    }
    fit_budget(&mut entries);
    CommandChain { entries, end }
}

/// Apply the per-entry cap, returning the kept text and the chars cut.
fn cap_cmdline(full: String) -> (String, u32) {
    let total = full.chars().count();
    if total <= MAX_ENTRY_CMDLINE_CHARS {
        return (full, 0);
    }
    let kept = MAX_ENTRY_CMDLINE_CHARS - 1;
    let mut text: String = full.chars().take(kept).collect();
    text.push('…');
    (text, (total - kept) as u32)
}

fn serialized_len(entries: &[ChainEntry]) -> usize {
    serde_json::to_string(entries).map_or(usize::MAX, |s| s.len())
}

/// Shorten the longest command lines until the chain fits [`MAX_CHAIN_BYTES`].
/// Entries, pids and comms are never dropped.
fn fit_budget(entries: &mut [ChainEntry]) {
    loop {
        let size = serialized_len(entries);
        if size <= MAX_CHAIN_BYTES {
            return;
        }
        let Some(longest) = entries
            .iter_mut()
            .filter(|e| e.cmdline.chars().count() > 1)
            .max_by_key(|e| e.cmdline.chars().count())
        else {
            return;
        };
        let len = longest.cmdline.chars().count();
        let step = ((size - MAX_CHAIN_BYTES) / 4).max(1);
        let target = len.saturating_sub(step).max(1);
        // The marker `…` of an already truncated entry is not kept text.
        let prev_kept = len - usize::from(longest.truncated_chars > 0);
        let mut shortened: String = longest.cmdline.chars().take(target - 1).collect();
        shortened.push('…');
        longest.truncated_chars += (prev_kept - (target - 1)) as u32;
        longest.cmdline = shortened;
    }
}

/// Convenience wrapper over the real `/proc`.
pub fn system_command_chain_for_caller(pid: u32, process_name: Option<&str>) -> CommandChain {
    command_chain_for_caller(&ProcTree::system(), pid, process_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::fs;

    fn add(dir: &TempDir, pid: u32, comm: &str, ppid: u32, cmdline: &[u8]) {
        let p = dir.path().join(pid.to_string());
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("stat"), format!("{pid} ({comm}) S {ppid} 0 0\n")).unwrap();
        fs::write(p.join("cmdline"), cmdline).unwrap();
    }

    fn pids(c: &CommandChain) -> Vec<u32> {
        c.entries.iter().map(|e| e.pid).collect()
    }

    #[test]
    fn normal_chain_to_pid_1() {
        let dir = TempDir::new();
        add(&dir, 1, "systemd", 0, b"/sbin/init\0");
        add(&dir, 10, "bash", 1, b"-bash\0");
        add(&dir, 60, "ssh", 10, b"ssh\0-p\x002222\0host.invalid\0");
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 60, Some("ssh"));
        assert_eq!(pids(&c), [60, 10, 1]);
        assert_eq!(c.end, ChainEnd::Root);
        assert_eq!(c.entries[0].cmdline, "ssh -p 2222 host.invalid");
        assert_eq!(c.entries[0].comm, "ssh");
        assert_eq!(c.entries[0].ppid, Some(10));
        assert_eq!(c.entries[2].ppid, Some(0));
    }

    #[test]
    fn parent_exited() {
        let dir = TempDir::new();
        add(&dir, 60, "ssh", 10, b"ssh\0host.invalid\0");
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 60, None);
        assert_eq!(pids(&c), [60]);
        assert_eq!(c.end, ChainEnd::ParentExited);
    }

    #[test]
    fn cycle() {
        let dir = TempDir::new();
        add(&dir, 2, "a", 3, b"a\0");
        add(&dir, 3, "b", 4, b"b\0");
        add(&dir, 4, "c", 2, b"c\0");
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 2, None);
        assert_eq!(pids(&c), [2, 3, 4]);
        assert_eq!(c.end, ChainEnd::Cycle);
    }

    #[test]
    fn more_than_16_entries_is_depth_limited() {
        let dir = TempDir::new();
        for p in 2..=30u32 {
            add(&dir, p, "p", p + 1, b"p\0");
        }
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 2, None);
        assert_eq!(c.entries.len(), MAX_CHAIN_ENTRIES);
        assert_eq!(c.end, ChainEnd::DepthLimit);
    }

    #[test]
    fn exactly_16_entries_ending_at_root_is_root() {
        let dir = TempDir::new();
        for p in 1..=16u32 {
            add(&dir, p, "p", p - 1, b"p\0");
        }
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 16, None);
        assert_eq!(c.entries.len(), 16);
        assert_eq!(c.end, ChainEnd::Root);
    }

    #[test]
    fn size_budget_shortens_longest_cmdlines_only() {
        let dir = TempDir::new();
        let long = format!("{}\0", "x".repeat(900));
        for p in 1..=16u32 {
            add(&dir, p, "worker", p - 1, long.as_bytes());
        }
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 16, None);
        assert_eq!(c.entries.len(), 16);
        assert!(serde_json::to_string(&c.entries).unwrap().len() <= MAX_CHAIN_BYTES);
        for e in &c.entries {
            assert!(e.cmdline.chars().count() <= MAX_ENTRY_CMDLINE_CHARS);
            assert!(e.cmdline.ends_with('…'));
            assert_eq!(e.comm, "worker");
        }
        assert_eq!(pids(&c), (1..=16).rev().collect::<Vec<_>>());
    }

    #[test]
    fn multibyte_cmdlines_fit_budget() {
        let mut entries: Vec<ChainEntry> = (0..16u32)
            .map(|i| ChainEntry {
                pid: 100 - i,
                ppid: Some(99 - i),
                comm: "worker".into(),
                truncated_chars: 0,
                cmdline: if i % 2 == 0 {
                    "\u{4e2d}\u{6587}".repeat(100)
                } else {
                    "\u{1F600}".repeat(200)
                },
            })
            .collect();
        assert!(serde_json::to_string(&entries).unwrap().len() > MAX_CHAIN_BYTES);
        fit_budget(&mut entries);
        assert!(serde_json::to_string(&entries).unwrap().len() <= MAX_CHAIN_BYTES);
        assert_eq!(entries.len(), 16);
        assert!(entries.iter().any(|e| e.truncated_chars > 0));
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.comm, "worker");
            // kept chars (without the marker) plus cut chars is the original 200
            if e.truncated_chars > 0 {
                assert!(e.cmdline.ends_with('…'));
                assert_eq!(
                    e.cmdline.chars().count() - 1 + e.truncated_chars as usize,
                    200,
                    "{i}"
                );
            } else {
                assert_eq!(e.cmdline.chars().count(), 200, "{i}");
            }
        }
    }

    #[test]
    fn untruncated_entries_report_zero() {
        let dir = TempDir::new();
        add(&dir, 1, "init", 0, b"init\0");
        add(&dir, 5, "tool", 1, b"tool\0--flag\0");
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 5, None);
        assert!(c.entries.iter().all(|e| e.truncated_chars == 0));
    }

    #[test]
    fn per_entry_cap_counts_cut_chars_from_full_cmdline() {
        let dir = TempDir::new();
        add(&dir, 1, "init", 0, b"init\0");
        // 500 chars: beyond the old 1000-char display cap is covered below
        add(
            &dir,
            5,
            "tool",
            1,
            format!("{}\0", "x".repeat(500)).as_bytes(),
        );
        add(
            &dir,
            6,
            "big",
            5,
            format!("{}\0", "y".repeat(3000)).as_bytes(),
        );
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 6, None);
        assert_eq!(
            c.entries[0].cmdline.chars().count(),
            MAX_ENTRY_CMDLINE_CHARS
        );
        assert_eq!(c.entries[0].truncated_chars, 3000 - 199);
        assert_eq!(c.entries[1].truncated_chars, 500 - 199);
        assert_eq!(c.entries[2].truncated_chars, 0);
    }

    #[test]
    fn proc_read_limit_is_the_counting_base() {
        let dir = TempDir::new();
        add(&dir, 1, "init", 0, b"init\0");
        // /proc reads stop at 4096 bytes, so that is what gets counted
        add(&dir, 5, "huge", 1, "z".repeat(10_000).as_bytes());
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 5, None);
        assert_eq!(c.entries[0].truncated_chars, 4096 - 199);
    }

    #[test]
    fn budget_shortening_adds_to_truncated_chars() {
        let dir = TempDir::new();
        // 16 entries of 900 chars: cap cuts 701 each, the budget cuts more
        let long = format!("{}\0", "x".repeat(900));
        for p in 1..=16u32 {
            add(&dir, p, "worker", p - 1, long.as_bytes());
        }
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 16, None);
        for e in &c.entries {
            assert_eq!(
                e.cmdline.chars().count() - 1 + e.truncated_chars as usize,
                900
            );
            assert!(e.truncated_chars > 701);
        }
    }

    #[test]
    fn short_cmdlines_are_untouched_by_budget() {
        let dir = TempDir::new();
        add(&dir, 1, "init", 0, b"init\0");
        add(&dir, 5, "tool", 1, b"tool\0--flag\0");
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 5, None);
        assert_eq!(c.entries[0].cmdline, "tool --flag");
    }

    #[test]
    fn injection_in_argv_is_neutralised() {
        let dir = TempDir::new();
        add(&dir, 1, "init", 0, b"init\0");
        add(
            &dir,
            5,
            "evil",
            1,
            "evil\n\u{202E}approved\0\u{2066}x\0".as_bytes(),
        );
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 5, None);
        let line = &c.entries[0].cmdline;
        assert!(!line.contains('\n'));
        assert!(!line.contains('\u{202E}') && !line.contains('\u{2066}'));
        assert!(line.contains('\u{FFFD}'));
        let json = serde_json::to_string(&c.entries).unwrap();
        assert!(!json.contains("\\n"));
    }

    #[test]
    fn caller_exited() {
        let dir = TempDir::new();
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 9999, Some("sudo-auth"));
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].pid, 9999);
        assert_eq!(c.entries[0].ppid, None);
        assert_eq!(c.entries[0].comm, "sudo-auth");
        assert_eq!(c.entries[0].cmdline, "");
        assert_eq!(c.end, ChainEnd::ParentExited);
    }

    #[test]
    fn sudo_chain_shows_all_layers() {
        let dir = TempDir::new();
        add(&dir, 1, "systemd", 0, b"/sbin/init\0");
        add(&dir, 10, "bash", 1, b"-bash\0");
        let sudo = b"sudo\0systemctl\0restart\0example.service\0";
        add(&dir, 20, "sudo", 10, sudo);
        add(&dir, 30, "sudo", 20, sudo);
        add(
            &dir,
            40,
            "sudo-alohomora",
            30,
            b"/bin/bash\0/usr/local/bin/sudo-alohomora-auth\0",
        );
        add(
            &dir,
            50,
            "sudo-auth",
            40,
            b"sudo-auth\0lookup\0service\0sudo\0",
        );
        let tree = ProcTree::with_root(dir.path());
        let c = command_chain_for_caller(&tree, 50, Some("sudo-auth"));
        assert_eq!(pids(&c), [50, 40, 30, 20, 10, 1]);
        assert_eq!(
            c.entries[3].cmdline,
            "sudo systemctl restart example.service"
        );
        assert_eq!(c.end, ChainEnd::Root);
    }
}
