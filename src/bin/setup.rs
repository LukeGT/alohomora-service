use pass_secret_service::{config, key_store};
use std::io::{self, Write};
use std::process::ExitCode;

#[derive(argh::FromArgs)]
/// Setup tool for alohomora-service
struct SetupArgs {
    /// clear existing setup state and secret store files
    #[argh(switch, long = "clear")]
    clear: bool,
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

    match key_store::run_setup(&config).await {
        Ok(Some(pairing_token)) => {
            let key_dir = key_store::get_key_dir();
            let local_key_path = key_dir.join(key_store::LOCAL_KEY_FILE);
            let local_key = match key_store::read_local_key(&local_key_path).await {
                Ok(Some(key)) => key,
                _ => {
                    eprintln!("Error: local key not found after setup.");
                    return ExitCode::FAILURE;
                }
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            let done_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));
            match pass_secret_service::http_server::spawn_setup_server(
                config.clone(),
                local_key.clone(),
                done_tx.clone(),
            )
            .await
            {
                Ok(_server_handle) => {
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
                                    pass_secret_service::http_server::process_register_request(
                                        &local_key, req,
                                    )
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
                Err(e) => {
                    eprintln!("Error starting registration server: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Setup error: {}", e);
            ExitCode::FAILURE
        }
    }
}
