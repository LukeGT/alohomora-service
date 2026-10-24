//! Generic, read-only inspection of the Linux process tree via `/proc`.
//!
//! This module only knows how to walk parent links; it carries no policy about
//! which ancestors are interesting. Callers supply predicates.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

/// Maximum number of ancestors visited, guarding against pathological trees.
pub const MAX_ANCESTOR_DEPTH: usize = 64;

/// The subset of `/proc/<pid>/stat` we care about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    /// Kernel `comm` (executable name, truncated by the kernel to 15 bytes).
    pub comm: String,
}

/// A view of a procfs mount. `ProcTree::system()` reads the real `/proc`;
/// tests can point it at a synthetic directory.
#[derive(Debug, Clone)]
pub struct ProcTree {
    root: PathBuf,
}

impl ProcTree {
    pub fn system() -> Self {
        Self::with_root("/proc")
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Read and parse `<root>/<pid>/stat`. Returns `None` if the process is
    /// gone or the file cannot be parsed.
    pub fn entry(&self, pid: u32) -> Option<ProcessEntry> {
        let raw = fs::read(self.root.join(pid.to_string()).join("stat")).ok()?;
        parse_stat(pid, &raw)
    }

    pub fn parent_pid(&self, pid: u32) -> Option<u32> {
        self.entry(pid).map(|e| e.ppid)
    }

    /// Iterate over the ancestors of `pid` (parent first), excluding `pid`
    /// itself. Stops at the root of the tree (ppid 0), at an unreadable
    /// process, on a cycle, or after [`MAX_ANCESTOR_DEPTH`] ancestors.
    pub fn ancestors(&self, pid: u32) -> Ancestors<'_> {
        Ancestors {
            tree: self,
            next: self.parent_pid(pid),
            seen: HashSet::from([pid]),
            remaining: MAX_ANCESTOR_DEPTH,
        }
    }

    /// First ancestor (nearest first) for which `pred` returns true.
    pub fn find_ancestor(
        &self,
        pid: u32,
        mut pred: impl FnMut(&ProcessEntry) -> bool,
    ) -> Option<ProcessEntry> {
        self.ancestors(pid).find(|e| pred(e))
    }
}

pub struct Ancestors<'a> {
    tree: &'a ProcTree,
    next: Option<u32>,
    seen: HashSet<u32>,
    remaining: usize,
}

impl Iterator for Ancestors<'_> {
    type Item = ProcessEntry;

    fn next(&mut self) -> Option<ProcessEntry> {
        let pid = self.next.take()?;
        if pid == 0 || self.remaining == 0 || !self.seen.insert(pid) {
            return None;
        }
        self.remaining -= 1;
        let entry = self.tree.entry(pid)?;
        self.next = Some(entry.ppid);
        Some(entry)
    }
}

/// Parse the contents of a `/proc/<pid>/stat` file.
///
/// Format: `pid (comm) state ppid ...`. `comm` may itself contain spaces and
/// parentheses, so it is delimited by the first `(` and the *last* `)`.
fn parse_stat(pid: u32, raw: &[u8]) -> Option<ProcessEntry> {
    let open = raw.iter().position(|&b| b == b'(')?;
    let close = raw.iter().rposition(|&b| b == b')')?;
    if close < open {
        return None;
    }
    let comm = String::from_utf8_lossy(&raw[open + 1..close]).into_owned();
    let rest = std::str::from_utf8(&raw[close + 1..]).ok()?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next()?.parse().ok()?;
    Some(ProcessEntry { pid, ppid, comm })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn fake_proc(entries: &[(u32, &str, u32)]) -> (TempDir, ProcTree) {
        let dir = TempDir::new();
        for (pid, comm, ppid) in entries {
            let p = dir.path().join(pid.to_string());
            fs::create_dir_all(&p).unwrap();
            fs::write(
                p.join("stat"),
                format!("{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0\n"),
            )
            .unwrap();
        }
        let tree = ProcTree::with_root(dir.path());
        (dir, tree)
    }

    #[test]
    fn parses_simple_stat() {
        let e = parse_stat(42, b"42 (bash) S 7 42 42 0").unwrap();
        assert_eq!(
            e,
            ProcessEntry {
                pid: 42,
                ppid: 7,
                comm: "bash".into()
            }
        );
    }

    #[test]
    fn parses_comm_with_spaces_and_parens() {
        let e = parse_stat(5, b"5 (my (weird) prog) R 99 5 5 0").unwrap();
        assert_eq!(e.comm, "my (weird) prog");
        assert_eq!(e.ppid, 99);
    }

    #[test]
    fn rejects_malformed_stat() {
        assert!(parse_stat(1, b"").is_none());
        assert!(parse_stat(1, b"1 bash S 0").is_none());
        assert!(parse_stat(1, b"1 (bash)").is_none());
        assert!(parse_stat(1, b"1 (bash) S notanumber").is_none());
        assert!(parse_stat(1, b") (").is_none());
    }

    #[test]
    fn parent_pid_and_missing_process() {
        let (_d, tree) = fake_proc(&[(10, "child", 5), (5, "parent", 1)]);
        assert_eq!(tree.parent_pid(10), Some(5));
        assert_eq!(tree.parent_pid(999), None);
    }

    #[test]
    fn ancestors_walk_up_nearest_first_and_stop_at_root() {
        let (_d, tree) = fake_proc(&[(30, "leaf", 20), (20, "mid", 10), (10, "top", 0)]);
        let comms: Vec<_> = tree.ancestors(30).map(|e| e.comm).collect();
        assert_eq!(comms, ["mid", "top"]);
    }

    #[test]
    fn ancestors_stop_at_missing_parent() {
        let (_d, tree) = fake_proc(&[(30, "leaf", 20)]);
        assert_eq!(tree.ancestors(30).count(), 0);
        assert_eq!(tree.ancestors(12345).count(), 0);
    }

    #[test]
    fn ancestors_survive_cycles() {
        let (_d, tree) = fake_proc(&[(1, "a", 2), (2, "b", 3), (3, "c", 1)]);
        let pids: Vec<_> = tree.ancestors(1).map(|e| e.pid).collect();
        assert_eq!(pids, [2, 3]);
    }

    #[test]
    fn ancestors_respect_depth_limit() {
        let n = (MAX_ANCESTOR_DEPTH as u32) + 20;
        let entries: Vec<(u32, &str, u32)> = (1..=n).map(|p| (p, "p", p + 1)).collect();
        let (_d, tree) = fake_proc(&entries);
        assert_eq!(tree.ancestors(1).count(), MAX_ANCESTOR_DEPTH);
    }

    #[test]
    fn find_ancestor_returns_nearest_match() {
        let (_d, tree) = fake_proc(&[
            (40, "secret-tool", 30),
            (30, "wrapper", 20),
            (20, "sudo", 15),
            (15, "sudo", 10),
            (10, "bash", 0),
        ]);
        let found = tree.find_ancestor(40, |e| e.comm == "sudo").unwrap();
        assert_eq!(found.pid, 20);
        assert!(tree.find_ancestor(40, |e| e.comm == "nope").is_none());
        // the starting process itself is never considered
        assert!(tree
            .find_ancestor(40, |e| e.comm == "secret-tool")
            .is_none());
    }

    #[test]
    fn system_tree_sees_current_process() {
        let tree = ProcTree::system();
        let me = tree.entry(std::process::id()).unwrap();
        assert_eq!(tree.parent_pid(me.pid), Some(me.ppid));
        assert!(!me.comm.is_empty());
    }
}
