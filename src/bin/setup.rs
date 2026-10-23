use pass_secret_service::{auth_gate::AuthGate, config, http_server, key_store};
use std::io::{self, Write};
use std::process::ExitCode;

#[derive(argh::FromArgs)]
/// Setup tool for alohomora-service
struct SetupArgs {
    /// clear existing setup state and secret store files
    #[argh(switch, long = "clear")]
    clear: bool,

    /// friendly name for this Alohomora service
    #[argh(option, long = "name")]
    pub name: Option<String>,
}

fn confirm_clear() -> bool {
    let expected = "I want to clear my secret store";
    println!("WARNING: This will permanently delete your local setup keys, device pairing state, and stored secrets!");
    print!(
        "Please type the following sentence to confirm:\n  \"{}\"\n> ",
        expected
    );
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() && input.trim() == expected {
        return true;
    }
    false
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: SetupArgs = argh::from_env();

    if args.clear {
        if !confirm_clear() {
            eprintln!("Confirmation failed. Action aborted.");
            return ExitCode::FAILURE;
        }

        match key_store::clear_secret_store().await {
            Ok(_) => {
                println!("Secret store cleared successfully.");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error clearing secret store: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    let config = match config::AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let (key_dir, local_key, service_identity) =
        match key_store::prepare_setup_keys(args.name).await {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("Setup preparation error: {}", e);
                return ExitCode::FAILURE;
            }
        };

    let has_devices = match key_store::has_registered_devices().await {
        Ok(has) => has,
        Err(e) => {
            eprintln!("Error checking existing devices: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let secret_key = if !has_devices {
        match key_store::generate_random_secret_key() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error generating secret key: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("Existing paired device(s) found. Please approve the authentication request on an existing device to unlock the secret key for pairing...");
        let auth_gate = AuthGate::new(&config, local_key.clone());
        let temp_http_server = if !config.use_relay {
            match http_server::spawn(config.clone(), auth_gate.clone()).await {
                Ok(handle) => Some(handle),
                Err(e) => {
                    eprintln!("Error starting authentication server: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        } else {
            None
        };

        let secret_key_res = auth_gate.request_secret_key(None).await;
        if let Some(handle) = temp_http_server {
            handle.abort();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        match secret_key_res {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Failed to authenticate with existing device. Aborting setup so existing secret key is not lost.");
                return ExitCode::FAILURE;
            }
        }
    };

    if let Err(e) = key_store::clear_temp_pairing_keys(&key_dir).await {
        eprintln!("Error clearing temp pairing keys: {}", e);
        return ExitCode::FAILURE;
    }

    let pairing_token = match key_store::create_temp_pairing_key(
        &key_dir,
        &local_key,
        &secret_key,
        &config,
        &service_identity,
    )
    .await
    {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Setup error creating pairing token: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Printed to the terminal only (never logged): the URL embeds the pairing token.
    let setup_url = key_store::build_setup_url(&pairing_token.value, &config, &service_identity);
    println!(
        "To register a local (password) emergency device instead of / in addition to a phone, run:"
    );
    println!(
        "  {}",
        pass_secret_service::local_device::register_command(&setup_url, config.internal_port)
    );
    if config.use_relay {
        println!("(Relay mode: the alohomora service must not be holding port {}; stop it while registering.)", config.internal_port);
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    let done_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));
    let _server_handle = match pass_secret_service::http_server::spawn_setup_server(
        config.clone(),
        local_key.clone(),
        done_tx.clone(),
    )
    .await
    {
        Ok(handle) => Some(handle),
        Err(e) => {
            if config.use_relay {
                eprintln!("Direct HTTP server not bound ({e}); proceeding with public relay");
                None
            } else {
                eprintln!("Error starting registration server: {}", e);
                return ExitCode::FAILURE;
            }
        }
    };

    if config.use_relay {
        let done_tx = done_tx.clone();
        let local_key = local_key.clone();
        let web_service_url = config.web_service_url.clone();
        let session_id = pairing_token.id.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let res = pass_secret_service::http_server::poll_relay_once(
                &client,
                &web_service_url,
                "register",
                &session_id,
                std::time::Duration::from_secs(300),
                |req: pass_secret_service::http_server::RegisterRequest| async move {
                    pass_secret_service::http_server::process_register_request(&local_key, req)
                        .await
                },
            )
            .await;

            if let Ok(()) = res {
                if let Some(tx) = done_tx.lock().await.take() {
                    let _ = tx.send(());
                }
            }
        });
    }

    println!("Waiting for Android device registration...");
    let _ = rx.await;
    println!("Registration successful! Setup completed successfully.");
    ExitCode::SUCCESS
}
