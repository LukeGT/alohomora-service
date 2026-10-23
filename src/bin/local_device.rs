use std::{
    io::{self, BufRead},
    os::unix::fs::PermissionsExt,
    process::ExitCode,
};

use pass_secret_service::{
    config::AppConfig,
    http_server::KeychainInfo,
    key_store::{self, DeviceKind},
    local_device::{self, KdfParams},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MIN_PASSWORD_LEN: usize = 12;

#[derive(argh::FromArgs)]
/// Manage the password-protected local (virtual) Alohomora device
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(argh::FromArgs)]
#[argh(subcommand)]
enum Command {
    Register(Register),
}

/// register this host as a local device (requires a running `alohomora-setup`)
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "register")]
struct Register {
    /// setup URL or pairing token printed by `alohomora-setup`; read from stdin if omitted
    #[argh(option, long = "setup")]
    setup: Option<String>,

    /// base URL of the setup server (default: http://127.0.0.1:<internal port>)
    #[argh(option, long = "server")]
    server: Option<String>,
}

fn prompt_new_password() -> Result<Zeroizing<String>, String> {
    let first = Zeroizing::new(
        rpassword::prompt_password("New unlock password: ").map_err(|e| e.to_string())?,
    );
    if first.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    let second =
        Zeroizing::new(rpassword::prompt_password("Repeat password: ").map_err(|e| e.to_string())?);
    if *first != *second {
        return Err("passwords do not match".into());
    }
    Ok(first)
}

async fn register(args: Register) -> Result<(), String> {
    let config = AppConfig::from_env().map_err(|e| e.to_string())?;
    let key_dir = key_store::get_key_dir();

    let setup_input = match args.setup {
        Some(s) => s,
        None => {
            eprintln!(
                "Paste the setup URL or pairing token from alohomora-setup, then press Enter:"
            );
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            line
        }
    };
    let setup = local_device::parse_setup_input(&setup_input).map_err(|e| e.to_string())?;

    let identity = key_store::read_service_identity(&key_dir)
        .await
        .map_err(|e| e.to_string())?;
    let keychain = KeychainInfo {
        domain: setup
            .domain
            .clone()
            .unwrap_or_else(|| config.domain.clone()),
        port: setup.port.unwrap_or(config.external_port),
        service_uuid: setup
            .service_uuid
            .clone()
            .or_else(|| identity.as_ref().map(|i| i.service_uuid.clone()))
            .ok_or("service uuid unknown; pass the full setup URL")?,
        service_name: setup
            .service_name
            .clone()
            .or_else(|| identity.as_ref().map(|i| i.service_name.clone()))
            .unwrap_or_default(),
    };

    let password = prompt_new_password()?;

    eprintln!("Generating RSA-2048 key and deriving password key (Argon2id)...");
    let device_key = local_device::generate_device_key().map_err(|e| e.to_string())?;
    let key_file =
        local_device::encrypt_private_key(&device_key, password.as_bytes(), KdfParams::default())
            .map_err(|e| e.to_string())?;
    drop(password);

    let device_uuid = Uuid::new_v4();
    let device_dir = key_store::device_dir(&key_dir, DeviceKind::Local, &device_uuid.to_string());
    std::fs::create_dir_all(&device_dir)
        .map_err(|e| format!("cannot create {device_dir:?}: {e}"))?;
    std::fs::set_permissions(&device_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let key_path = local_device::key_file_path(&key_dir, &device_uuid.to_string());
    local_device::write_key_file(&key_path, &key_file).map_err(|e| e.to_string())?;

    let request = local_device::build_register_request(
        &device_uuid,
        keychain,
        &setup.token,
        local_device::public_key_info(&device_key).map_err(|e| e.to_string())?,
    );
    let server = args
        .server
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", config.internal_port));
    let url = format!("{}/alohomora/register", server.trim_end_matches('/'));

    let outcome = async {
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("registration request failed: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(format!("registration rejected ({status}): {body}"))
        }
    }
    .await;

    if let Err(e) = outcome {
        // Do not leave an orphaned key behind for a registration that never happened.
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_dir(&device_dir);
        return Err(e);
    }

    println!(
        "Registered local device {device_uuid} ({}).",
        local_device::LOCAL_DEVICE_NAME
    );
    println!("Encrypted private key: {}", key_path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Args = argh::from_env();
    let result = match args.command {
        Command::Register(r) => register(r).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
