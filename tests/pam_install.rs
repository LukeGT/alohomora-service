//! pam/install.sh, check.sh and uninstall.sh against a temporary prefix, as the
//! current user: nothing outside the prefix is touched.

use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const REPO: &str = env!("CARGO_MANIFEST_DIR");
const BINARIES: [&str; 5] = [
    "pass-secret-service",
    "alohomora-sudo-approve",
    "alohomora-setup",
    "alohomora-local-device",
    "alohomora-unlock",
];

fn temp_dir(tag: &str) -> PathBuf {
    // Directories the tests pre-create must not trip the writability check.
    unsafe { libc::umask(0o022) };
    let dir = std::env::temp_dir().join(format!("alhm_pam_{tag}_{}", nanoid::nanoid!()));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn script(name: &str, args: &[&str]) -> std::process::Output {
    Command::new("bash")
        .args(["-c", "umask 022; exec \"$0\" \"$@\""])
        .arg(format!("{REPO}/pam/{name}"))
        .args(args)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .unwrap()
}

fn fake_binaries() -> PathBuf {
    let bin = temp_dir("bin");
    for name in BINARIES {
        fs::write(bin.join(name), "#!/bin/sh\n").unwrap();
        fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

fn install_into(prefix: &Path, bin: &Path) {
    let out = script(
        "install.sh",
        &[
            "--prefix",
            prefix.to_str().unwrap(),
            "--bin-dir",
            bin.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{out:?}");
}

fn check(prefix: &Path) -> std::process::Output {
    let uid = fs::metadata(prefix).unwrap().uid().to_string();
    script(
        "check.sh",
        &["--prefix", prefix.to_str().unwrap(), "--owner-uid", &uid],
    )
}

fn failures(out: &std::process::Output) -> String {
    assert!(!out.status.success(), "check unexpectedly passed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn install_replaces_links_with_real_files_that_pass_the_check() {
    let (prefix, bin) = (temp_dir("root"), fake_binaries());
    let outside = temp_dir("repo").join("pam-sudo");
    fs::write(&outside, "user editable\n").unwrap();
    fs::create_dir_all(prefix.join("etc/pam.d")).unwrap();
    symlink(&outside, prefix.join("etc/pam.d/sudo")).unwrap();
    fs::create_dir_all(prefix.join("usr/local/bin")).unwrap();
    symlink(&outside, prefix.join("usr/local/bin/sudo-alohomora-auth")).unwrap();

    install_into(&prefix, &bin);

    let pam = prefix.join("etc/pam.d/sudo");
    assert!(!fs::symlink_metadata(&pam).unwrap().is_symlink());
    assert_eq!(fs::metadata(&pam).unwrap().mode() & 0o777, 0o644);
    // The installer replaces the link; it must not write through it.
    assert_eq!(fs::read_to_string(&outside).unwrap(), "user editable\n");
    assert!(!prefix.join("usr/local/bin/sudo-alohomora-auth").exists());
    let helper = prefix.join("usr/local/lib/alohomora/sudo-alohomora-auth");
    assert_eq!(fs::metadata(&helper).unwrap().mode() & 0o777, 0o755);
    let out = check(&prefix);
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn check_fails_on_links_writable_files_and_writable_parents() {
    let (prefix, bin) = (temp_dir("root"), fake_binaries());
    install_into(&prefix, &bin);
    let helper = prefix.join("usr/local/lib/alohomora/sudo-alohomora-auth");

    fs::set_permissions(&helper, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(failures(&check(&prefix)).contains("sudo-alohomora-auth is group/world-writable"));
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

    let dir = prefix.join("usr/local/lib/alohomora");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(failures(&check(&prefix)).contains("lib/alohomora is group/world-writable"));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    fs::remove_file(&helper).unwrap();
    symlink("/bin/true", &helper).unwrap();
    assert!(failures(&check(&prefix)).contains("is a symlink"));
    fs::remove_file(&helper).unwrap();
    fs::write(&helper, "").unwrap();

    let unit = prefix.join("etc/systemd/system/alohomora-service.service");
    let text = fs::read_to_string(&unit).unwrap();
    fs::write(&unit, format!("{text}\nExecStart=/home/ubuntu/x\n")).unwrap();
    let text = fs::read_to_string(&unit).unwrap();
    fs::write(
        &unit,
        text.replace(
            "ExecStart=/usr/local/lib/alohomora/pass-secret-service\n",
            "",
        ),
    )
    .unwrap();
    assert!(failures(&check(&prefix)).contains("does not run"));
}

#[test]
fn uninstall_restores_the_backup_or_a_working_stock_file() {
    let (prefix, bin) = (temp_dir("root"), fake_binaries());
    let pam = prefix.join("etc/pam.d/sudo");
    fs::create_dir_all(pam.parent().unwrap()).unwrap();
    fs::write(&pam, "distro file\n").unwrap();
    install_into(&prefix, &bin);
    assert_eq!(
        fs::read_to_string(prefix.join("etc/pam.d/sudo.orig")).unwrap(),
        "distro file\n"
    );
    // A second install must not back up our own file over the distro's.
    install_into(&prefix, &bin);

    let root = prefix.to_str().unwrap();
    let out = script("uninstall.sh", &["--prefix", root]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read_to_string(&pam).unwrap(), "distro file\n");
    assert!(!prefix
        .join("usr/local/lib/alohomora/sudo-alohomora-auth")
        .exists());
    assert!(prefix
        .join("usr/local/lib/alohomora/pass-secret-service")
        .exists());

    // No backup, as on a host installed by an older version: still a usable PAM file.
    install_into(&prefix, &bin);
    fs::remove_file(prefix.join("etc/pam.d/sudo.orig")).unwrap();
    assert!(script("uninstall.sh", &["--prefix", root]).status.success());
    let stock = fs::read_to_string(&pam).unwrap();
    assert!(stock.contains("@include common-auth") && !stock.contains("alohomora"));
}
