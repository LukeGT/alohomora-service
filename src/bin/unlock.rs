use std::{process::ExitCode, time::Duration};

use pass_secret_service::{
    auth_gate::LocalChallenge, config::AppConfig, http_server::AuthenticateRequest, key_store,
    local_device,
};
use zeroize::Zeroizing;

#[derive(argh::FromArgs)]
/// Approve a pending Alohomora request with the local (password-protected) device
struct Args {
    /// local device uuid (required only if several local devices exist)
    #[argh(option, long = "device-uuid")]
    device_uuid: Option<String>,

    /// base URL of the service (default: http://127.0.0.1:<internal port>)
    #[argh(option, long = "server")]
    server: Option<String>,

    /// seconds to wait for a pending request to appear (default 30)
    #[argh(option, long = "wait", default = "30")]
    wait_secs: u64,
}

async fn fetch_challenges(
    client: &reqwest::Client,
    server: &str,
    device_uuid: &str,
    wait: Duration,
) -> Result<Vec<LocalChallenge>, String> {
    let url = format!("{server}/alohomora/local/challenges");
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("cannot reach service at {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "service refused challenge request: {}",
                resp.status()
            ));
        }
        let all: Vec<LocalChallenge> = resp.json().await.map_err(|e| e.to_string())?;
        let mine: Vec<_> = all
            .into_iter()
            .filter(|c| c.device_uuid == device_uuid)
            .collect();
        if !mine.is_empty() || tokio::time::Instant::now() >= deadline {
            return Ok(mine);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn run(args: Args) -> Result<(), String> {
    let config = AppConfig::from_env().map_err(|e| e.to_string())?;
    let key_dir = key_store::get_key_dir();

    let mut key_files = local_device::find_key_files(&key_dir).map_err(|e| e.to_string())?;
    if let Some(wanted) = &args.device_uuid {
        key_files.retain(|(uuid, _)| uuid == wanted);
    }
    let (device_uuid, key_path) = match key_files.len() {
        0 => {
            return Err(
                "no local device key file found; run `alohomora-local-device register`".into(),
            )
        }
        1 => key_files.remove(0),
        _ => return Err("several local devices found; pass --device-uuid".into()),
    };
    let key_file = local_device::read_key_file(&key_path).map_err(|e| e.to_string())?;

    let password =
        Zeroizing::new(rpassword::prompt_password("Unlock password: ").map_err(|e| e.to_string())?);
    let device_key = local_device::decrypt_private_key(&key_file, password.as_bytes())
        .map_err(|e| e.to_string())?;
    drop(password);

    let server = args
        .server
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", config.internal_port));
    let server = server.trim_end_matches('/');
    let client = reqwest::Client::new();

    let challenges = fetch_challenges(
        &client,
        server,
        &device_uuid,
        Duration::from_secs(args.wait_secs),
    )
    .await?;
    if challenges.is_empty() {
        return Err("no pending unlock requests for this device".into());
    }

    let mut failures = 0;
    for challenge in challenges {
        println!(
            "Request {}: uid={} user={} pid={} process={}",
            challenge.request_uuid,
            challenge.uid,
            challenge.username,
            challenge.pid,
            challenge.process_name
        );
        let response: AuthenticateRequest =
            match local_device::answer_challenge(&device_key, &challenge) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  refused: {e}");
                    failures += 1;
                    continue;
                }
            };
        let resp = client
            .post(format!("{server}/alohomora/authenticate"))
            .json(&response)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            println!("  approved");
        } else {
            eprintln!("  service rejected response: {}", resp.status());
            failures += 1;
        }
    }
    if failures > 0 {
        return Err(format!("{failures} request(s) failed"));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(argh::from_env()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
