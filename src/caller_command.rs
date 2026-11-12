//! Builds the process chain (caller and all its ancestors) shown to the
//! approver, within the size budget of the push notification.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    process_cmdline::{neutralise, read_cmdline_raw, sanitise_command_line, truncate_chars},
    process_tree::{ChainEnd, ProcTree},
};

// Limits mirrored by the relay (alohomora-web-service `index.js`, constants of the
// same names). The relay rejects anything over them instead of trimming, so
// keep both sides in sync; the `worst_case_*` test below guarantees that what
// this service produces always passes the relay.

/// Maximum number of chain entries (caller included).
pub const MAX_CHAIN_ENTRIES: usize = 16;
/// Maximum code points of each entry's command line.
pub const MAX_ENTRY_CMDLINE_CHARS: usize = 200;
/// Maximum code points of a reported real executable path.
pub const MAX_SPOOF_EXE_CHARS: usize = 60;
/// Maximum code points of each entry's `comm`.
pub const MAX_COMM_CHARS: usize = 32;
/// Maximum serialized size of the entry list in bytes.
pub const MAX_CHAIN_BYTES: usize = 2500;
/// Maximum serialized size of the whole FCM data payload in bytes.
pub const MAX_FCM_DATA_BYTES: usize = 4096;
/// Service-side only: maximum size of the chain once embedded as an escaped JSON
/// string value in the FCM data (quotes and backslashes double in size), leaving
/// room for the other fields so the data payload stays within [`MAX_FCM_DATA_BYTES`].
pub const MAX_CHAIN_EMBEDDED_BYTES: usize = 2600;

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
    /// Kernel-backed evidence that the displayed `cmdline`/`comm` is not what runs.
    /// Absent when nothing suspicious was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spoof: Option<Spoof>,
}

/// Spoofing evidence for one process. At least one field is set whenever this
/// is present (see [`Spoof::detect`]); unset fields are omitted when serialised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spoof {
    /// Real executable path (`/proc/<pid>/exe`), present when `argv[0]` names a
    /// different program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The argument area was remapped (`arg_end != env_start`), so `cmdline`
    /// may show memory the program chose rather than its real arguments.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub args_moved: bool,
}

impl Spoof {
    fn detect(tree: &ProcTree, pid: u32, raw_cmdline: &[u8]) -> Option<Self> {
        let argv0 = raw_cmdline
            .split(|&b| b == 0)
            .next()
            .filter(|a| !a.is_empty())
            .map(String::from_utf8_lossy);
        let exe = tree
            .exe(pid)
            .zip(argv0)
            .filter(|(exe, argv0)| argv0_mismatches_exe(tree, pid, argv0, exe))
            .map(|(exe, _)| {
                truncate_chars(neutralise(&exe.to_string_lossy()), MAX_SPOOF_EXE_CHARS)
            });
        let args_moved = tree.arg_area_moved(pid) == Some(true);
        (exe.is_some() || args_moved).then_some(Self { exe, args_moved })
    }
}

/// `longer` is `shorter` plus a version/suffix: the remainder after the shared
/// prefix is empty or starts with a digit, `.`, `-` or `_` (so `s` does not
/// excuse `ssh`).
fn is_name_variant(shorter: &str, longer: &str) -> bool {
    longer.strip_prefix(shorter).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
    })
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// True when `argv0` cannot plausibly be a name of the program at `exe`.
/// Lenient on purpose: login shells (`-bash`), versioned names (`python3` vs
/// `python3.12`, either prefix of the other) and symlinks are fine.
fn argv0_mismatches_exe(tree: &ProcTree, pid: u32, argv0: &str, exe: &Path) -> bool {
    let exe_name = exe
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let exe_name = exe_name.strip_suffix(" (deleted)").unwrap_or(&exe_name);
    // setproctitle-style `sshd: user/0` keeps the program name as first token.
    let first_token = argv0.split(' ').next().unwrap_or(argv0);
    let first_token = first_token.strip_suffix(':').unwrap_or(first_token);
    let arg_name = base_name(first_token).trim_start_matches('-');
    if arg_name.is_empty() || exe_name.is_empty() {
        return false;
    }
    if is_name_variant(arg_name, exe_name) || is_name_variant(exe_name, arg_name) {
        return false;
    }
    !resolves_like_a_shell_to_exe(tree, pid, first_token)
}

/// Path inside the process's own mount namespace, reached through `/proc/<pid>/root`.
fn in_jail(jail: &Path, inner: &Path) -> PathBuf {
    jail.join(inner.strip_prefix("/").unwrap_or(inner))
}

/// Would `argv0` run the program behind `/proc/<pid>/exe`? Resolves it as execvp would
/// (absolute; relative against the process cwd; bare names through `PATH` from its
/// environment, first executable hit wins) through `/proc/<pid>/root`, then compares
/// the files by (device, inode), which avoids host-vs-jail path confusion. Anything
/// unreadable means no rescue.
///
/// This adds no bypass: a caller can always name its binary like the program it
/// imitates, so the name check only catches renames, not impostor binaries.
fn resolves_like_a_shell_to_exe(tree: &ProcTree, pid: u32, argv0: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let proc_dir = tree.pid_dir(pid);
    let jail = proc_dir.join("root");
    let Ok(wanted) = std::fs::metadata(proc_dir.join("exe")).map(|m| (m.dev(), m.ino())) else {
        return false;
    };
    let cwd = || std::fs::read_link(proc_dir.join("cwd")).ok();
    let found = if argv0.starts_with('/') {
        Some(PathBuf::from(argv0))
    } else if argv0.contains('/') {
        cwd().map(|c| c.join(argv0))
    } else {
        path_dirs(&proc_dir).and_then(|dirs| {
            dirs.into_iter()
                .filter_map(|d| {
                    if d.as_os_str().is_empty() {
                        cwd()
                    } else if d.is_absolute() {
                        Some(d)
                    } else {
                        cwd().map(|c| c.join(d))
                    }
                })
                .map(|d| d.join(argv0))
                .find(|c| is_executable_file(&in_jail(&jail, c)))
        })
    };
    found
        .and_then(|f| std::fs::metadata(in_jail(&jail, &f)).ok())
        .is_some_and(|m| (m.dev(), m.ino()) == wanted)
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Directories of `PATH` in `<proc_dir>/environ`; `None` if unreadable or unset.
fn path_dirs(proc_dir: &Path) -> Option<Vec<PathBuf>> {
    let mut raw = Vec::new();
    std::fs::File::open(proc_dir.join("environ"))
        .ok()?
        .take(1 << 20)
        .read_to_end(&mut raw)
        .ok()?;
    let value = raw
        .split(|&b| b == 0)
        .find_map(|kv| kv.strip_prefix(b"PATH="))?;
    let value = String::from_utf8_lossy(value).into_owned();
    Some(value.split(':').map(PathBuf::from).collect())
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
            let raw = read_cmdline_raw(tree.root(), e.pid);
            let (cmdline, truncated_chars) = cap_cmdline(sanitise_command_line(&raw));
            ChainEntry {
                pid: e.pid,
                ppid: Some(e.ppid),
                cmdline,
                comm: clean_comm(&e.comm),
                truncated_chars,
                spoof: Spoof::detect(tree, e.pid, &raw),
            }
        })
        .collect();
    if entries.is_empty() {
        entries.push(ChainEntry {
            pid,
            ppid: None,
            comm: clean_comm(process_name.unwrap_or_default()),
            cmdline: String::new(),
            truncated_chars: 0,
            spoof: None,
        });
    }
    fit_budget(&mut entries);
    CommandChain { entries, end }
}

/// Neutralise control/bidi characters (kernel comm is attacker-settable) and cap length.
fn clean_comm(comm: &str) -> String {
    neutralise(comm).chars().take(MAX_COMM_CHARS).collect()
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

/// Bytes by which the chain exceeds the budget (0 when it fits): both the plain
/// serialized size and the size embedded as a string value in the FCM data count.
fn excess_bytes(entries: &[ChainEntry]) -> usize {
    let Ok(plain) = serde_json::to_string(entries) else {
        return usize::MAX;
    };
    let embedded = serde_json::to_string(&plain).map_or(usize::MAX, |s| s.len());
    plain
        .len()
        .saturating_sub(MAX_CHAIN_BYTES)
        .max(embedded.saturating_sub(MAX_CHAIN_EMBEDDED_BYTES))
}

/// Shorten the longest command lines until the chain fits [`MAX_CHAIN_BYTES`].
/// Entries, pids and comms are never dropped.
fn fit_budget(entries: &mut [ChainEntry]) {
    loop {
        let excess = excess_bytes(entries);
        if excess == 0 {
            return;
        }
        let Some(longest) = entries
            .iter_mut()
            .filter(|e| e.cmdline.chars().count() > 1)
            .max_by_key(|e| e.cmdline.chars().count())
        else {
            shorten_longest_exe(entries, excess);
            debug_assert_eq!(
                excess_bytes(entries),
                0,
                "chain cannot be made to fit the budget"
            );
            return;
        };
        let len = longest.cmdline.chars().count();
        let step = (excess / 4).max(1);
        let target = len.saturating_sub(step).max(1);
        // The marker `…` of an already truncated entry is not kept text.
        let prev_kept = len - usize::from(longest.truncated_chars > 0);
        let mut shortened: String = longest.cmdline.chars().take(target - 1).collect();
        shortened.push('…');
        longest.truncated_chars += (prev_kept - (target - 1)) as u32;
        longest.cmdline = shortened;
    }
}

/// Last resort once every cmdline is down to its marker: shrink reported
/// executable paths (never dropping the spoof flag itself) until the chain fits.
fn shorten_longest_exe(entries: &mut [ChainEntry], excess: usize) {
    loop {
        let Some(exe) = entries
            .iter_mut()
            .filter_map(|e| e.spoof.as_mut()?.exe.as_mut())
            .filter(|x| x.chars().count() > 2)
            .max_by_key(|x| x.chars().count())
        else {
            // Nothing left to trim: reduce every remaining exe to the bare marker
            // (the flag itself is kept), the most that can be saved safely.
            for exe in entries
                .iter_mut()
                .filter_map(|e| e.spoof.as_mut()?.exe.as_mut())
            {
                *exe = "…".into();
            }
            return;
        };
        let len = exe.chars().count();
        let target = len.saturating_sub((excess / 4).max(1)).max(2);
        *exe = exe.chars().take(target - 1).chain(Some('…')).collect();
        if excess_bytes(entries) == 0 {
            return;
        }
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
                spoof: None,
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

    use std::os::unix::fs::symlink;

    /// A stat line with fields 48-51 set to `area` (fields 3..=47 are filler).
    fn add_spoofable(dir: &TempDir, pid: u32, ppid: u32, argv0: &str, exe: &str, area: &str) {
        let p = dir.path().join(pid.to_string());
        fs::create_dir_all(&p).unwrap();
        let filler = ["0"; 43].join(" ");
        fs::write(
            p.join("stat"),
            format!("{pid} (x y) S {ppid} {filler} {area}\n"),
        )
        .unwrap();
        fs::write(p.join("cmdline"), format!("{argv0}\0arg\0")).unwrap();
        symlink(exe, p.join("exe")).unwrap();
        symlink("/", p.join("root")).unwrap();
        symlink("/", p.join("cwd")).unwrap();
    }

    /// Process 5 inside a fake rootfs: usr/bin/dash, usr/bin/sh -> dash, an
    /// unrelated usr/local/bin/sh, work/tool and work/alias -> tool; cwd /work.
    fn jailed(argv0: &str, exe_in_jail: &str, environ: &[u8]) -> Option<Spoof> {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let fsroot = dir.path().join("rootfs");
        let exe = fsroot.join(exe_in_jail.trim_start_matches('/'));
        add_spoofable(&dir, 5, 0, argv0, exe.to_str().unwrap(), CONTIGUOUS);
        for d in ["usr/bin", "usr/local/bin", "work"] {
            fs::create_dir_all(fsroot.join(d)).unwrap();
        }
        for f in ["usr/bin/dash", "usr/local/bin/sh", "work/tool"] {
            fs::write(fsroot.join(f), b"").unwrap();
            fs::set_permissions(fsroot.join(f), fs::Permissions::from_mode(0o755)).unwrap();
        }
        symlink("dash", fsroot.join("usr/bin/sh")).unwrap();
        symlink("tool", fsroot.join("work/alias")).unwrap();
        let p = dir.path().join("5");
        for l in ["root", "cwd"] {
            fs::remove_file(p.join(l)).unwrap();
        }
        symlink(&fsroot, p.join("root")).unwrap();
        symlink("/work", p.join("cwd")).unwrap();
        fs::write(p.join("environ"), environ).unwrap();
        let tree = ProcTree::with_root(dir.path());
        command_chain_for_caller(&tree, 5, None).entries[0]
            .spoof
            .clone()
    }

    #[test]
    fn bare_name_found_on_path_as_symlink_to_exe_is_not_flagged() {
        assert_eq!(
            jailed("sh", "/usr/bin/dash", b"HOME=/x\0PATH=/usr/bin\0"),
            None
        );
    }

    #[test]
    fn bare_name_missing_from_path_is_flagged() {
        let got = jailed("sh", "/usr/bin/dash", b"PATH=/opt:/usr/local\0");
        assert!(got.is_some_and(|s| s.exe.is_some()));
    }

    #[test]
    fn environ_without_path_skips_the_rescue() {
        assert!(jailed("sh", "/usr/bin/dash", b"HOME=/x\0").is_some());
    }

    #[test]
    fn unreadable_environ_skips_the_rescue() {
        let dir = TempDir::new();
        add_spoofable(&dir, 5, 0, "sh", "/usr/bin/dash", CONTIGUOUS);
        let tree = ProcTree::with_root(dir.path());
        assert!(command_chain_for_caller(&tree, 5, None).entries[0]
            .spoof
            .is_some());
    }

    #[test]
    fn relative_argv0_resolves_against_cwd() {
        assert_eq!(jailed("./alias", "/work/tool", b""), None);
        assert!(jailed("./other", "/work/tool", b"").is_some());
    }

    #[test]
    fn earlier_path_dir_with_a_different_binary_wins() {
        let environ = b"PATH=/usr/local/bin:/usr/bin\0";
        assert!(jailed("sh", "/usr/bin/dash", environ).is_some());
    }

    fn spoof_of(argv0: &str, exe: &str, area: &str) -> Option<Spoof> {
        let dir = TempDir::new();
        add_spoofable(&dir, 5, 0, argv0, exe, area);
        let tree = ProcTree::with_root(dir.path());
        command_chain_for_caller(&tree, 5, None).entries[0]
            .spoof
            .clone()
    }

    const CONTIGUOUS: &str = "100 200 200 300";

    #[test]
    fn matching_argv0_is_not_flagged() {
        assert_eq!(spoof_of("ssh", "/usr/bin/ssh", CONTIGUOUS), None);
        assert_eq!(spoof_of("/usr/bin/ssh", "/usr/bin/ssh", CONTIGUOUS), None);
    }

    #[test]
    fn legitimate_variants_are_not_flagged() {
        assert_eq!(spoof_of("-bash", "/usr/bin/bash", CONTIGUOUS), None);
        assert_eq!(spoof_of("python3", "/usr/bin/python3.12", CONTIGUOUS), None);
        assert_eq!(spoof_of("python3.12", "/usr/bin/python3", CONTIGUOUS), None);
        assert_eq!(
            spoof_of("sshd", "/usr/sbin/sshd (deleted)", CONTIGUOUS),
            None
        );
    }

    #[test]
    fn argv0_symlink_to_exe_is_not_flagged() {
        let dir = TempDir::new();
        let real = dir.path().join("realtool");
        fs::write(&real, b"").unwrap();
        let link = dir.path().join("friendly");
        symlink(&real, &link).unwrap();
        let got = spoof_of(link.to_str().unwrap(), real.to_str().unwrap(), CONTIGUOUS);
        assert_eq!(got, None);
    }

    #[test]
    fn bare_prefix_does_not_excuse_a_different_program() {
        assert!(spoof_of("ssh", "/usr/bin/s", CONTIGUOUS).is_some());
        assert!(spoof_of("s", "/usr/bin/ssh", CONTIGUOUS).is_some());
        assert!(spoof_of("pythonista", "/usr/bin/python", CONTIGUOUS).is_some());
    }

    #[test]
    fn setproctitle_argv0_matches_on_first_token() {
        assert_eq!(
            spoof_of("sshd: ubuntu@pts/0", "/usr/sbin/sshd", CONTIGUOUS),
            None
        );
        assert_eq!(
            spoof_of(
                "sshd: ubuntu@pts/0",
                "/usr/lib/openssh/sshd-session",
                CONTIGUOUS
            ),
            None
        );
        assert_eq!(
            spoof_of("sshd-session: u [priv]", "/usr/sbin/sshd", CONTIGUOUS),
            None
        );
        assert!(spoof_of("sshd: ubuntu@pts/0", "/tmp/evil", CONTIGUOUS).is_some());
    }

    #[test]
    fn different_argv0_is_flagged_with_real_exe() {
        let got = spoof_of("ssh", "/tmp/evil", CONTIGUOUS);
        assert_eq!(
            got,
            Some(Spoof {
                exe: Some("/tmp/evil".into()),
                args_moved: false
            })
        );
    }

    #[test]
    fn exe_path_is_neutralised() {
        let got = spoof_of("ssh", "/tmp/e\nvil", CONTIGUOUS).unwrap();
        assert_eq!(got.exe.as_deref(), Some("/tmp/e\u{FFFD}vil"));
    }

    #[test]
    fn moved_arg_area_is_flagged() {
        let got = spoof_of("ssh", "/usr/bin/ssh", "100 200 900 1000");
        assert_eq!(
            got,
            Some(Spoof {
                exe: None,
                args_moved: true
            })
        );
    }

    #[test]
    fn both_checks_can_fire() {
        let got = spoof_of("ssh", "/tmp/evil", "100 200 900 1000").unwrap();
        assert!(got.exe.is_some() && got.args_moved);
    }

    #[test]
    fn unreadable_exe_and_missing_fields_are_not_flagged() {
        let dir = TempDir::new();
        add(&dir, 5, "kthread", 0, b"whatever\0");
        let tree = ProcTree::with_root(dir.path());
        assert_eq!(
            command_chain_for_caller(&tree, 5, None).entries[0].spoof,
            None
        );
    }

    #[test]
    fn spoof_is_omitted_from_json_when_absent_and_old_json_parses() {
        let none = serde_json::to_string(&spoof_of("ssh", "/usr/bin/ssh", CONTIGUOUS)).unwrap();
        assert_eq!(none, "null");
        let entry: ChainEntry =
            serde_json::from_str(r#"{"pid":1,"ppid":0,"comm":"a","cmdline":"b"}"#).unwrap();
        assert_eq!(entry.spoof, None);
        assert!(!serde_json::to_string(&entry).unwrap().contains("spoof"));
        let moved = Spoof {
            exe: None,
            args_moved: true,
        };
        assert_eq!(
            serde_json::to_string(&moved).unwrap(),
            r#"{"args_moved":true}"#
        );
    }

    /// Everything the relay forwards besides the chain, at realistic (generous) sizes.
    fn fcm_data_with(entries: &[ChainEntry]) -> serde_json::Value {
        serde_json::json!({
            "request_uuid": "6fbbce84-5aef-43c3-8cc7-469cbfd83109",
            "encrypted_blob": "A".repeat(344),
            "service_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "uid": "4294967295",
            "username": "u".repeat(32),
            "pid": "4294967295",
            "process_name": "p".repeat(15),
            "access_timestamp_ms": "1760000000000",
            "ephemeral_public_key": "B".repeat(700),
            "service_name": "s".repeat(64),
            "command_chain": serde_json::to_string(entries).unwrap(),
            "chain_end": "depth_limit",
        })
    }

    fn assert_relay_accepts(entries: &[ChainEntry]) {
        assert!(entries.len() <= MAX_CHAIN_ENTRIES);
        for e in entries {
            assert!(e.cmdline.chars().count() <= MAX_ENTRY_CMDLINE_CHARS);
            assert!(e.comm.chars().count() <= MAX_COMM_CHARS);
        }
        assert!(serde_json::to_string(entries).unwrap().len() <= MAX_CHAIN_BYTES);
        let data = serde_json::to_string(&fcm_data_with(entries)).unwrap();
        assert!(
            data.len() <= MAX_FCM_DATA_BYTES,
            "data is {} bytes",
            data.len()
        );
    }

    #[test]
    fn worst_case_chains_always_pass_the_relay_limits() {
        let dir = TempDir::new();
        let cases: [(&str, String); 3] = [
            ("emoji", "\u{1F600}".repeat(300)),
            ("cjk", "\u{4e2d}\u{6587}".repeat(300)),
            // quotes and backslashes double again when embedded in the FCM data
            ("escapes", "\"\\".repeat(300)),
        ];
        for (n, (name, text)) in cases.iter().enumerate() {
            let root = dir.path().join(format!("case{n}"));
            std::fs::create_dir_all(&root).unwrap();
            for p in 1..=20u32 {
                let pid = 4_000_000_000 + p;
                let d = root.join(pid.to_string());
                std::fs::create_dir_all(&d).unwrap();
                let ppid = if p == 1 { 0 } else { 4_000_000_000 + p - 1 };
                std::fs::write(
                    d.join("stat"),
                    format!("{pid} (\u{4e2d}\u{6587}\u{1F600}comm) S {ppid} 0 0\n"),
                )
                .unwrap();
                std::fs::write(d.join("cmdline"), format!("{text}\0")).unwrap();
                std::os::unix::fs::symlink(format!("/x{}", "\u{1F600}".repeat(300)), d.join("exe"))
                    .unwrap();
            }
            let tree = ProcTree::with_root(&root);
            let chain = command_chain_for_caller(&tree, 4_000_000_020, None);
            assert_eq!(chain.entries.len(), MAX_CHAIN_ENTRIES, "{name}");
            assert_eq!(chain.end, ChainEnd::DepthLimit, "{name}");
            assert!(chain.entries.iter().all(|e| e.spoof.is_some()), "{name}");
            assert_relay_accepts(&chain.entries);
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
