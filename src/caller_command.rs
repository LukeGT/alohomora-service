//! Policy deciding which command line is shown to the approver for a caller.

use crate::{process_cmdline::read_command_line, process_tree::ProcTree};

/// `comm` of the PAM helper (a symlink to `secret-tool`) spawned by
/// `sudo-alohomora-auth`. Its own command line says nothing useful.
const SUDO_AUTH_COMM: &str = "sudo-auth";
const SUDO_COMM: &str = "sudo";

/// Command line to display for the caller `pid` whose `comm` is `process_name`.
///
/// For the sudo PAM helper the intermediate wrapper/PAM processes are skipped
/// and the nearest `sudo` ancestor's command line is used instead, so the
/// approver sees what is actually being run with elevated privileges.
/// Returns an empty string when nothing can be determined.
pub fn command_line_for_caller(tree: &ProcTree, pid: u32, process_name: Option<&str>) -> String {
    let target = if process_name == Some(SUDO_AUTH_COMM) {
        tree.find_ancestor(pid, |e| e.comm == SUDO_COMM)
            .map_or(pid, |e| e.pid)
    } else {
        pid
    };
    read_command_line(tree.root(), target)
}

/// Convenience wrapper over the real `/proc`.
pub fn system_command_line_for_caller(pid: u32, process_name: Option<&str>) -> String {
    command_line_for_caller(&ProcTree::system(), pid, process_name)
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

    fn sudo_tree() -> (TempDir, ProcTree) {
        let dir = TempDir::new();
        add(&dir, 10, "bash", 1, b"-bash\0");
        add(
            &dir,
            20,
            "sudo",
            10,
            b"sudo\0systemctl\0restart\0example.service\0",
        );
        add(
            &dir,
            30,
            "sudo",
            20,
            b"sudo\0systemctl\0restart\0example.service\0",
        );
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
        add(&dir, 60, "ssh", 10, b"ssh\0-p\x002222\0host.invalid\0");
        let tree = ProcTree::with_root(dir.path());
        (dir, tree)
    }

    #[test]
    fn ordinary_caller_uses_own_command_line() {
        let (_d, tree) = sudo_tree();
        assert_eq!(
            command_line_for_caller(&tree, 60, Some("ssh")),
            "ssh -p 2222 host.invalid"
        );
    }

    #[test]
    fn sudo_auth_uses_nearest_sudo_ancestor() {
        let (_d, tree) = sudo_tree();
        assert_eq!(
            command_line_for_caller(&tree, 50, Some("sudo-auth")),
            "sudo systemctl restart example.service"
        );
    }

    #[test]
    fn sudo_auth_without_sudo_ancestor_falls_back_to_own() {
        let dir = TempDir::new();
        add(&dir, 5, "bash", 0, b"bash\0");
        add(&dir, 6, "sudo-auth", 5, b"sudo-auth\0lookup\0");
        let tree = ProcTree::with_root(dir.path());
        assert_eq!(
            command_line_for_caller(&tree, 6, Some("sudo-auth")),
            "sudo-auth lookup"
        );
    }

    #[test]
    fn unknown_or_exited_pid_is_empty() {
        let (_d, tree) = sudo_tree();
        assert_eq!(command_line_for_caller(&tree, 9999, None), "");
        assert_eq!(command_line_for_caller(&tree, 9999, Some("sudo-auth")), "");
    }
}
