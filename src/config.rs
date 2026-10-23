use std::{env, time::Duration};

use crate::error::{Error, Result};

const DEFAULT_DOMAIN: &str = "alohomora.app";
const DEFAULT_PORT: u16 = 19969;
const DEFAULT_AUTH_TIMEOUT_SECS: u64 = 60;
const MAX_AUTH_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub domain: String,
    pub external_port: u16,
    pub internal_port: u16,
    pub web_service_url: String,
    pub use_relay: bool,
    /// How long to wait for the mobile device to approve an authorization request.
    pub authorization_timeout: Duration,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let domain = env::var("ALOHOMORA_DOMAIN").unwrap_or_else(|_| DEFAULT_DOMAIN.into());
        let external_port = read_port_env("ALOHOMORA_EXTERNAL_PORT", 443)?;
        let internal_port = read_port_env("ALOHOMORA_INTERNAL_PORT", DEFAULT_PORT)?;

        let web_service_url = env::var("ALOHOMORA_WEB_SERVICE_URL")
            .unwrap_or_else(|_| "https://alohomora.app".to_string());

        let use_relay = match env::var("ALOHOMORA_RELAY") {
            Ok(val) => {
                let lower = val.trim().to_lowercase();
                lower == "true" || lower == "1"
            }
            Err(_) => domain == "alohomora.app",
        };

        let authorization_timeout = read_timeout_secs_env(
            "ALOHOMORA_AUTH_TIMEOUT_SECS",
            DEFAULT_AUTH_TIMEOUT_SECS,
            MAX_AUTH_TIMEOUT_SECS,
        )?;

        Ok(Self {
            domain,
            external_port,
            internal_port,
            web_service_url,
            use_relay,
            authorization_timeout,
        })
    }

    pub fn notification_url(&self) -> String {
        std::env::var("ALOHOMORA_NOTIFICATION_URL").unwrap_or_else(|_| {
            format!(
                "{}/send-notification",
                self.web_service_url.trim_end_matches('/')
            )
        })
    }
}

fn read_port_env(name: &str, default: u16) -> Result<u16> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| Error::ConfigError(format!("{name} must be a valid u16, got `{value}`"))),
        Err(_) => Ok(default),
    }
}

fn read_timeout_secs_env(name: &str, default: u64, max: u64) -> Result<Duration> {
    match env::var(name) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(secs) if (1..=max).contains(&secs) => Ok(Duration::from_secs(secs)),
            _ => Err(Error::ConfigError(format!(
                "{name} must be an integer between 1 and {max}, got `{value}`"
            ))),
        },
        Err(_) => Ok(Duration::from_secs(default)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static CONFIG_ENV_MUTEX: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new(names: &[&'static str]) -> Self {
            let vars = names
                .iter()
                .map(|&name| (name, env::var(name).ok()))
                .collect();
            for &name in names {
                env::remove_var(name);
            }
            Self { vars }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, val) in &self.vars {
                if let Some(v) = val {
                    env::set_var(name, v);
                } else {
                    env::remove_var(name);
                }
            }
        }
    }

    #[test]
    fn test_app_config_defaults() {
        let _lock = CONFIG_ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ALOHOMORA_DOMAIN",
            "ALOHOMORA_EXTERNAL_PORT",
            "ALOHOMORA_INTERNAL_PORT",
            "ALOHOMORA_WEB_SERVICE_URL",
            "ALOHOMORA_NOTIFICATION_URL",
            "ALOHOMORA_RELAY",
            "ALOHOMORA_AUTH_TIMEOUT_SECS",
        ]);

        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.authorization_timeout, Duration::from_secs(60));
        assert_eq!(config.domain, "alohomora.app");
        assert_eq!(config.external_port, 443);
        assert_eq!(config.internal_port, 19969);
        assert_eq!(config.web_service_url, "https://alohomora.app");
        assert!(config.use_relay);
        assert_eq!(
            config.notification_url(),
            "https://alohomora.app/send-notification"
        );
    }

    #[test]
    fn test_app_config_custom_domain_and_relay() {
        let _lock = CONFIG_ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ALOHOMORA_DOMAIN",
            "ALOHOMORA_RELAY",
            "ALOHOMORA_WEB_SERVICE_URL",
            "ALOHOMORA_NOTIFICATION_URL",
        ]);

        // Custom domain defaults use_relay to false
        env::set_var("ALOHOMORA_DOMAIN", "example.com");
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.domain, "example.com");
        assert!(!config.use_relay);

        // Force use_relay=true with ALOHOMORA_RELAY="true"
        env::set_var("ALOHOMORA_RELAY", "true");
        let config = AppConfig::from_env().unwrap();
        assert!(config.use_relay);

        // Force use_relay=true with ALOHOMORA_RELAY="1"
        env::set_var("ALOHOMORA_RELAY", "1");
        let config = AppConfig::from_env().unwrap();
        assert!(config.use_relay);

        // Force use_relay=false with ALOHOMORA_RELAY="false" on alohomora.app
        env::set_var("ALOHOMORA_DOMAIN", "alohomora.app");
        env::set_var("ALOHOMORA_RELAY", "false");
        let config = AppConfig::from_env().unwrap();
        assert!(!config.use_relay);

        // Force use_relay=false with ALOHOMORA_RELAY="0"
        env::set_var("ALOHOMORA_RELAY", "0");
        let config = AppConfig::from_env().unwrap();
        assert!(!config.use_relay);
    }

    #[test]
    fn test_app_config_web_service_and_notification_urls() {
        let _lock = CONFIG_ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(&["ALOHOMORA_WEB_SERVICE_URL", "ALOHOMORA_NOTIFICATION_URL"]);

        // Explicit web service url
        env::set_var("ALOHOMORA_WEB_SERVICE_URL", "http://custom-web.org:8080");
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.web_service_url, "http://custom-web.org:8080");
        assert_eq!(
            config.notification_url(),
            "http://custom-web.org:8080/send-notification"
        );

        // When ALOHOMORA_WEB_SERVICE_URL is unset, web_service_url defaults to
        // https://alohomora.app without fallback stripping from ALOHOMORA_NOTIFICATION_URL
        env::remove_var("ALOHOMORA_WEB_SERVICE_URL");
        env::set_var(
            "ALOHOMORA_NOTIFICATION_URL",
            "https://relay.custom.org/send-notification",
        );
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.web_service_url, "https://alohomora.app");
        assert_eq!(
            config.notification_url(),
            "https://relay.custom.org/send-notification"
        );
    }

    #[test]
    fn test_app_config_authorization_timeout() {
        let _lock = CONFIG_ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(&["ALOHOMORA_AUTH_TIMEOUT_SECS"]);

        env::set_var("ALOHOMORA_AUTH_TIMEOUT_SECS", "3600");
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.authorization_timeout, Duration::from_secs(3600));

        env::set_var("ALOHOMORA_AUTH_TIMEOUT_SECS", "1");
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.authorization_timeout, Duration::from_secs(1));

        for bad in ["0", "3601", "-5", "abc", ""] {
            env::set_var("ALOHOMORA_AUTH_TIMEOUT_SECS", bad);
            assert!(
                matches!(AppConfig::from_env(), Err(Error::ConfigError(_))),
                "expected ConfigError for `{bad}`"
            );
        }
    }
}
