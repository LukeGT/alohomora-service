//! End-to-end tests of the Secret Service Unlock/Prompt flow on a private
//! `dbus-daemon`, using a local (virtual) device answered in-process. Uses
//! temporary key/pass/gpg directories; nothing reaches a phone or the real
//! session bus. Tests run one at a time (they share process environment and
//! are timing-sensitive).

mod common;

use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command as StdCommand, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use futures_util::StreamExt;
use pass_secret_service::{
    auth_gate::AuthGate, config::AppConfig, dbus_server::service::Service, http_server, key_store,
    local_device, pass::PasswordStore,
};
use rsa::RsaPrivateKey;
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, OnceCell},
    task::JoinHandle,
    time::Instant,
};
use zbus::{
    fdo::IntrospectableProxy,
    message::Type as MessageType,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
    Connection, MatchRule, MessageStream,
};

const SERVICE: &str = "org.freedesktop.secrets";
const BASE_PATH: &str = "/org/freedesktop/secrets";
const DEFAULT_ALIAS: &str = "/org/freedesktop/secrets/aliases/default";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
const REQUIRED_TOOLS: [&str; 4] = ["dbus-daemon", "secret-tool", "gpg", "gpgconf"];

/// Process-wide temp root (key dir, gpg home), removed at exit.
static ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
static DEVICE: OnceCell<common::RegisteredDevice> = OnceCell::const_new();
/// Run the harness-based tests one at a time.
static SERIAL: AsyncMutex<()> = AsyncMutex::const_new(());

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
}

extern "C" fn cleanup_root() {
    if let Some(Ok(root)) = ROOT.get() {
        let _ = StdCommand::new("gpgconf")
            .args(["--kill", "gpg-agent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // the exiting gpg-agent may still be deleting its sockets: retry
        for _ in 0..20 {
            if std::fs::remove_dir_all(root).is_ok() || !root.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Set up the shared environment exactly once, before any test thread reads
/// it; `Err` names the missing tool.
fn root() -> Result<&'static Path, String> {
    ROOT.get_or_init(|| {
        if let Some(tool) = REQUIRED_TOOLS.iter().find(|t| !on_path(t)) {
            return Err(format!("`{tool}` is not installed"));
        }
        let root = std::env::temp_dir().join(format!("alhm-prompt-{}", nanoid::nanoid!(8)));
        let gnupg = root.join("gnupg");
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::create_dir_all(&gnupg).unwrap();
        std::fs::set_permissions(&gnupg, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        std::env::set_var("ALOHOMORA_KEY_DIR", root.join("keys"));
        std::env::set_var("GNUPGHOME", &gnupg);
        std::env::set_var("HOME", &root);
        // never reach a real push service, even by accident
        std::env::set_var("ALOHOMORA_NOTIFICATION_URL", "http://127.0.0.1:9/");
        unsafe { libc::atexit(cleanup_root) };
        Ok(root)
    })
    .as_deref()
    .map_err(Clone::clone)
}

async fn device(root: &Path) -> &'static common::RegisteredDevice {
    DEVICE
        .get_or_init(|| async {
            common::register_local_device(&root.join("keys"), &test_config(60)).await
        })
        .await
}

fn test_config(timeout_secs: u64) -> AppConfig {
    AppConfig {
        domain: "test.example.com".into(),
        external_port: 443,
        internal_port: 19969,
        web_service_url: "http://127.0.0.1:9".into(),
        use_relay: false,
        authorization_timeout: Duration::from_secs(timeout_secs),
    }
}

/// A private bus daemon, killed on drop and if the test process dies.
struct BusDaemon(Child);

impl BusDaemon {
    fn start(dir: &Path) -> (Self, String) {
        let config = dir.join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                dir.join("bus").display()
            ),
        )
        .unwrap();
        // no <servicedir>: nothing (e.g. a real keyring) can be auto-activated
        let mut command = StdCommand::new("dbus-daemon");
        command
            .arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--print-address"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // must not hold the test runner's output pipes open
            .stderr(Stdio::null());
        // SAFETY: prctl is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        (Self(child), address.trim().to_string())
    }
}

impl Drop for BusDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Answers parked local-device challenges after `delay` (never if `None`).
struct Approver {
    delay: Arc<Mutex<Option<Duration>>>,
    challenges: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Approver {
    fn spawn(gate: AuthGate, device_key: RsaPrivateKey, delay: Option<Duration>) -> Self {
        let delay = Arc::new(Mutex::new(delay));
        let challenges = Arc::new(AtomicUsize::new(0));
        let (delay_ref, count) = (delay.clone(), challenges.clone());
        let device_key = Arc::new(device_key);
        let task = tokio::spawn(async move {
            let mut seen = std::collections::HashSet::new();
            loop {
                for challenge in gate.pending_local_challenges().await {
                    if !seen.insert(challenge.request_uuid.clone()) {
                        continue;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let Some(delay) = *delay_ref.lock().unwrap() else {
                        continue;
                    };
                    let (gate, key) = (gate.clone(), device_key.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let response = tokio::task::spawn_blocking(move || {
                            local_device::answer_challenge(&key, &challenge).unwrap()
                        })
                        .await
                        .unwrap();
                        // fails harmlessly if the request was cancelled meanwhile
                        let _ = http_server::process_authenticate_request(&gate, response).await;
                    });
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        Self {
            delay,
            challenges,
            task,
        }
    }

    fn set_delay(&self, delay: Option<Duration>) {
        *self.delay.lock().unwrap() = delay;
    }

    fn challenges(&self) -> usize {
        self.challenges.load(Ordering::SeqCst)
    }
}

impl Drop for Approver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Harness {
    address: String,
    gate: AuthGate,
    approver: Approver,
    _service_connection: Connection,
    _bus: BusDaemon,
    dir: PathBuf,
    // dropped last: the next test starts only after this one is torn down
    _serial: AsyncMutexGuard<'static, ()>,
}

impl Harness {
    /// `None` (with a SKIPPED message) if a required tool is missing.
    async fn start(timeout_secs: u64, approve_after: Option<Duration>) -> Option<Self> {
        let root = match root() {
            Ok(root) => root,
            Err(reason) => {
                eprintln!("SKIPPED secret_service_prompt test: {reason}");
                return None;
            }
        };
        let serial = SERIAL.lock().await;
        let device = device(root).await;
        let dir = root.join(nanoid::nanoid!(8));
        std::fs::create_dir_all(dir.join("pass")).unwrap();
        let (bus, address) = BusDaemon::start(&dir);

        let gate = AuthGate::new(&test_config(timeout_secs), device.local_key.clone());
        let pass: &'static PasswordStore = Box::leak(Box::new(
            PasswordStore::from_env(
                Some(dir.join("pass")),
                key_store::key_to_passphrase(&device.local_key),
            )
            .unwrap(),
        ));
        let connection = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let service = Service::init(connection.clone(), pass, gate.clone(), false, false)
            .await
            .unwrap();
        connection
            .object_server()
            .at(BASE_PATH, service)
            .await
            .unwrap();
        connection.request_name(SERVICE).await.unwrap();

        let approver = Approver::spawn(gate.clone(), device.device_key.clone(), approve_after);
        Some(Self {
            address,
            gate,
            approver,
            _service_connection: connection,
            _bus: bus,
            dir,
            _serial: serial,
        })
    }

    async fn client(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    async fn secret_tool(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        limit: Duration,
    ) -> (Option<i32>, String, Duration) {
        let mut child = tokio::process::Command::new("secret-tool")
            .args(args)
            .env("DBUS_SESSION_BUS_ADDRESS", &self.address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        if let Some(text) = stdin {
            input.write_all(text.as_bytes()).await.unwrap();
        }
        drop(input);
        let started = Instant::now();
        let output = tokio::time::timeout(limit, child.wait_with_output())
            .await
            .unwrap_or_else(|_| panic!("secret-tool {args:?} hung for {limit:?}"))
            .unwrap();
        if !output.stderr.is_empty() {
            eprintln!(
                "secret-tool {args:?} stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            started.elapsed(),
        )
    }

    /// Store `password` under `service=<name>` and return the item path.
    async fn store(&self, name: &str, password: &str) -> OwnedObjectPath {
        let (status, _, _) = self
            .secret_tool(
                &["store", "--label", name, "service", name],
                Some(password),
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(status, Some(0), "secret-tool store failed");
        let client = self.client().await;
        let (unlocked, locked) = search(&client, name).await;
        assert!(unlocked.is_empty(), "items start out locked");
        assert_eq!(locked.len(), 1);
        locked.into_iter().next().unwrap()
    }

    /// Wait until no approval request or prompt object is left behind.
    async fn assert_idle(&self, client: &Connection) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pending = self.gate.pending_request_count().await;
            let local = self.gate.pending_local_challenges().await.len();
            let prompts = prompt_objects(client).await;
            if pending == 0 && local == 0 && prompts == 0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "left behind: {pending} pending, {local} local challenges, {prompts} prompts"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_pending_request(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.gate.pending_local_challenges().await.is_empty() {
            assert!(Instant::now() < deadline, "no approval request appeared");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn call<B, R>(
    conn: &Connection,
    path: &str,
    interface: &str,
    method: &str,
    body: &B,
) -> zbus::Result<R>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
    R: for<'d> serde::Deserialize<'d> + zbus::zvariant::Type,
{
    conn.call_method(Some(SERVICE), path, Some(interface), method, body)
        .await?
        .body()
        .deserialize()
}

async fn search(conn: &Connection, name: &str) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
    let attributes = HashMap::from([("service", name)]);
    call(
        conn,
        BASE_PATH,
        SERVICE_IFACE,
        "SearchItems",
        &(attributes,),
    )
    .await
    .unwrap()
}

async fn unlock(conn: &Connection, paths: &[&str]) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
    let paths: Vec<OwnedObjectPath> = paths
        .iter()
        .map(|p| OwnedObjectPath::try_from(*p).unwrap())
        .collect();
    call(conn, BASE_PATH, SERVICE_IFACE, "Unlock", &(paths,))
        .await
        .unwrap()
}

async fn locked(conn: &Connection, path: &str) -> bool {
    let (value,): (OwnedValue,) = call(
        conn,
        path,
        "org.freedesktop.DBus.Properties",
        "Get",
        &("org.freedesktop.Secret.Item", "Locked"),
    )
    .await
    .unwrap();
    bool::try_from(value).unwrap()
}

async fn get_secret(conn: &Connection, item: &str) -> zbus::Result<String> {
    let (_, session): (OwnedValue, OwnedObjectPath) = call(
        conn,
        BASE_PATH,
        SERVICE_IFACE,
        "OpenSession",
        &("plain", Value::from("")),
    )
    .await?;
    let items = vec![OwnedObjectPath::try_from(item).unwrap()];
    type RawSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let (secrets,): (HashMap<OwnedObjectPath, RawSecret>,) = call(
        conn,
        BASE_PATH,
        SERVICE_IFACE,
        "GetSecrets",
        &(items, session),
    )
    .await?;
    let (_, _, value, _) = secrets.into_values().next().expect("one secret");
    Ok(String::from_utf8(value).unwrap())
}

async fn prompt_objects(conn: &Connection) -> usize {
    let Ok(proxy) = IntrospectableProxy::builder(conn)
        .destination(SERVICE)
        .unwrap()
        .path("/org/freedesktop/secrets/prompt")
        .unwrap()
        .build()
        .await
    else {
        return 0;
    };
    match proxy.introspect().await {
        Ok(xml) => xml.matches("<node name=").count(),
        Err(_) => 0,
    }
}

async fn completed_stream(conn: &Connection, prompt: &str) -> MessageStream {
    let rule = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .interface(PROMPT_IFACE)
        .unwrap()
        .member("Completed")
        .unwrap()
        .path(prompt.to_string())
        .unwrap()
        .build();
    MessageStream::for_match_rule(rule, conn, None)
        .await
        .unwrap()
}

/// Wait for `Completed`; returns (dismissed, result paths). Checks the
/// result variant is always `ao`, as libsecret requires.
async fn next_completed(
    stream: &mut MessageStream,
    limit: Duration,
) -> (bool, Vec<OwnedObjectPath>) {
    let message = tokio::time::timeout(limit, stream.next())
        .await
        .expect("Completed signal not received")
        .unwrap()
        .unwrap();
    let (dismissed, result): (bool, OwnedValue) = message.body().deserialize().unwrap();
    assert_eq!(result.value_signature().as_str(), "ao");
    (dismissed, Vec::<OwnedObjectPath>::try_from(result).unwrap())
}

/// Call `Prompt` and assert it replies immediately.
async fn start_prompt(conn: &Connection, prompt: &str) {
    let started = Instant::now();
    let () = call(conn, prompt, PROMPT_IFACE, "Prompt", &("",))
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "Prompt must reply before approval ({:?})",
        started.elapsed()
    );
}

fn paths(paths: &[&OwnedObjectPath]) -> Vec<OwnedObjectPath> {
    paths.iter().map(|p| (*p).clone()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_tool_lookup_waits_for_approval_via_prompt() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-a", "password-a").await;
    h.approver.set_delay(Some(Duration::from_secs(2)));

    let before = h.approver.challenges();
    let (status, stdout, elapsed) = h
        .secret_tool(
            &["lookup", "service", "prompt-a"],
            None,
            Duration::from_secs(60),
        )
        .await;
    assert_eq!(status, Some(0));
    assert_eq!(stdout, "password-a");
    assert!(elapsed >= Duration::from_secs(2));
    assert_eq!(
        h.approver.challenges() - before,
        1,
        "one approval per lookup"
    );

    // the same flow by hand: Prompt replies at once, Completed carries `ao`
    let client = h.client().await;
    let (unlocked, prompt) = unlock(&client, &[item.as_str()]).await;
    assert!(unlocked.is_empty());
    assert_ne!(prompt.as_str(), "/");
    let mut completed = completed_stream(&client, &prompt).await;
    start_prompt(&client, &prompt).await;
    let (dismissed, result) = next_completed(&mut completed, Duration::from_secs(60)).await;
    assert!(!dismissed);
    assert_eq!(result, paths(&[&item]));
    assert!(!locked(&client, &item).await);
    assert_eq!(get_secret(&client, &item).await.unwrap(), "password-a");
    // the grant was consumed by GetSecrets
    assert!(locked(&client, &item).await);
    h.assert_idle(&client).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_without_approval_times_out_cleanly() {
    let Some(h) = Harness::start(3, Some(Duration::from_millis(200))).await else {
        return;
    };
    h.store("prompt-b", "password-b").await;
    h.approver.set_delay(None);

    let (status, stdout, elapsed) = h
        .secret_tool(
            &["lookup", "service", "prompt-b"],
            None,
            Duration::from_secs(30),
        )
        .await;
    assert_ne!(status, Some(0));
    assert!(stdout.is_empty());
    assert!(elapsed >= Duration::from_secs(3), "{elapsed:?}");
    h.assert_idle(&h.client().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dismiss_cancels_the_pending_request() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-c", "password-c").await;
    h.approver.set_delay(None);

    let client = h.client().await;
    let other = h.client().await;
    let (_, prompt) = unlock(&client, &[item.as_str()]).await;
    let mut completed = completed_stream(&client, &prompt).await;

    // only the caller that asked for the unlock may drive the prompt
    let err = call::<_, ()>(&other, &prompt, PROMPT_IFACE, "Prompt", &("",))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("AccessDenied"), "{err}");

    start_prompt(&client, &prompt).await;
    assert!(
        call::<_, ()>(&client, &prompt, PROMPT_IFACE, "Prompt", &("",))
            .await
            .is_err()
    );
    h.wait_for_pending_request().await;
    assert_eq!(h.gate.pending_request_count().await, 1);

    let () = call(&client, &prompt, PROMPT_IFACE, "Dismiss", &())
        .await
        .unwrap();
    let (dismissed, result) = next_completed(&mut completed, Duration::from_secs(5)).await;
    assert!(dismissed);
    assert!(result.is_empty());
    h.assert_idle(&client).await;
    assert!(locked(&client, &item).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnecting_client_loses_prompt_and_grant() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-d", "password-d").await;
    let observer = h.client().await;

    // an approved but unclaimed grant disappears with its client
    let client = h.client().await;
    let (_, prompt) = unlock(&client, &[DEFAULT_ALIAS]).await;
    let mut completed = completed_stream(&client, &prompt).await;
    start_prompt(&client, &prompt).await;
    let (dismissed, _) = next_completed(&mut completed, Duration::from_secs(60)).await;
    assert!(!dismissed);
    assert!(!locked(&observer, &item).await);
    drop(completed);
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !locked(&observer, &item).await {
        assert!(Instant::now() < deadline, "grant survived its client");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // a prompt still waiting for approval is dismissed with its client
    h.approver.set_delay(None);
    let client = h.client().await;
    let (_, prompt) = unlock(&client, &[item.as_str()]).await;
    start_prompt(&client, &prompt).await;
    h.wait_for_pending_request().await;
    drop(client);
    h.assert_idle(&observer).await;
    assert!(locked(&observer, &item).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn chrome_like_sequence_needs_one_approval() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-e", "password-e").await;
    h.approver.set_delay(Some(Duration::from_secs(2)));
    let before = h.approver.challenges();

    let client = h.client().await;
    let (unlocked, prompt) = unlock(&client, &[DEFAULT_ALIAS]).await;
    assert!(unlocked.is_empty());
    let mut completed = completed_stream(&client, &prompt).await;
    start_prompt(&client, &prompt).await;
    let (dismissed, result) = next_completed(&mut completed, Duration::from_secs(60)).await;
    assert!(!dismissed);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].as_str(), DEFAULT_ALIAS);

    // the item is covered by the collection approval: no second prompt
    let (unlocked, prompt) = unlock(&client, &[item.as_str()]).await;
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(unlocked, paths(&[&item]));
    let (unlocked, _) = search(&client, "prompt-e").await;
    assert_eq!(unlocked, paths(&[&item]));

    assert_eq!(get_secret(&client, &item).await.unwrap(), "password-e");
    assert_eq!(h.approver.challenges() - before, 1);
    h.assert_idle(&client).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_are_single_use_and_per_connection() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-f", "password-f").await;
    let client = h.client().await;
    let other = h.client().await;
    let before = h.approver.challenges();

    let (_, prompt) = unlock(&client, &[item.as_str()]).await;
    let mut completed = completed_stream(&client, &prompt).await;
    start_prompt(&client, &prompt).await;
    assert!(
        !next_completed(&mut completed, Duration::from_secs(60))
            .await
            .0
    );
    assert_eq!(h.approver.challenges() - before, 1);

    // another connection does not benefit from that approval (quick checks
    // only, so the grant cannot expire before it is claimed below)
    let (unlocked, locked_items) = search(&other, "prompt-f").await;
    assert!(unlocked.is_empty());
    assert_eq!(locked_items, paths(&[&item]));
    let (_, other_prompt) = unlock(&other, &[item.as_str()]).await;
    assert_ne!(other_prompt.as_str(), "/");
    let () = call(&other, &other_prompt, PROMPT_IFACE, "Dismiss", &())
        .await
        .unwrap();

    // the approval is consumed by the first read; the next one asks again
    assert_eq!(get_secret(&client, &item).await.unwrap(), "password-f");
    assert_eq!(h.approver.challenges() - before, 1);
    assert_eq!(get_secret(&client, &item).await.unwrap(), "password-f");
    assert_eq!(h.approver.challenges() - before, 2);

    // and the other connection needs its own approval too
    assert_eq!(get_secret(&other, &item).await.unwrap(), "password-f");
    assert_eq!(h.approver.challenges() - before, 3, "other needs its own");
    h.assert_idle(&client).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blocking_read_is_cancelled_when_its_client_disconnects() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-h", "password-h").await;
    h.approver.set_delay(None);

    // GetSecrets without Unlock blocks on the approval (legacy fallback)
    let client = h.client().await;
    let read = {
        let (client, item) = (client.clone(), item.clone());
        tokio::spawn(async move { get_secret(&client, &item).await })
    };
    h.wait_for_pending_request().await;
    read.abort();
    let _ = read.await;
    drop(client);
    h.assert_idle(&h.client().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn outstanding_prompts_are_capped_per_client() {
    let Some(h) = Harness::start(60, Some(Duration::from_millis(200))).await else {
        return;
    };
    let item = h.store("prompt-i", "password-i").await;
    let client = h.client().await;
    let items = vec![item.clone()];
    for _ in 0..8 {
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            call(&client, BASE_PATH, SERVICE_IFACE, "Unlock", &(&items,))
                .await
                .unwrap();
        assert_ne!(prompt.as_str(), "/");
    }
    let refused: zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> =
        call(&client, BASE_PATH, SERVICE_IFACE, "Unlock", &(&items,)).await;
    assert!(refused.is_err());

    // other clients are unaffected, and leaving cleans up the idle prompts
    let other = h.client().await;
    let (_, prompt) = unlock(&other, &[item.as_str()]).await;
    assert_ne!(prompt.as_str(), "/");
    drop(client);
    drop(other);
    h.assert_idle(&h.client().await).await;
}

/// Approval far beyond libsecret's 25s method-call timeout. Slow, so run
/// with `cargo test --test secret_service_prompt -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn secret_tool_lookup_survives_slow_approval() {
    let Some(h) = Harness::start(120, Some(Duration::from_millis(200))).await else {
        return;
    };
    h.store("prompt-g", "password-g").await;
    h.approver.set_delay(Some(Duration::from_secs(30)));
    let (status, stdout, elapsed) = h
        .secret_tool(
            &["lookup", "service", "prompt-g"],
            None,
            Duration::from_secs(90),
        )
        .await;
    assert_eq!(status, Some(0));
    assert_eq!(stdout, "password-g");
    assert!(elapsed >= Duration::from_secs(30));
}
