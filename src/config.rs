use std::env;

use crate::error::{Error, Result};

const DEFAULT_DOMAIN: &str = "alohomora.app";
const DEFAULT_PORT: u16 = 19969;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub domain: String,
    pub external_port: u16,
    pub internal_port: u16,
    pub web_service_url: String,
    pub use_relay: bool,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let domain = env::var("ALOHOMORA_DOMAIN").unwrap_or_else(|_| DEFAULT_DOMAIN.into());
        let external_port = read_port_env("ALOHOMORA_EXTERNAL_PORT", 443)?;
        let internal_port = read_port_env("ALOHOMORA_INTERNAL_PORT", DEFAULT_PORT)?;

        let web_service_url = env::var("ALOHOMORA_WEB_SERVICE_URL").unwrap_or_else(|_| {
            if let Ok(notif_url) = env::var("ALOHOMORA_NOTIFICATION_URL") {
                if let Some(stripped) = notif_url.strip_suffix("/send-notification") {
                    stripped.to_string()
                } else {
                    notif_url
                }
            } else {
                "https://alohomora.app".to_string()
            }
        });

        let use_relay = match env::var("ALOHOMORA_RELAY") {
            Ok(val) => {
                let lower = val.trim().to_lowercase();
                lower == "true" || lower == "1"
            }
            Err(_) => domain == "alohomora.app",
        };

        Ok(Self {
            domain,
            external_port,
            internal_port,
            web_service_url,
            use_relay,
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
        ]);

        let config = AppConfig::from_env().unwrap();
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

        // Fallback from notification url by stripping /send-notification
        env::remove_var("ALOHOMORA_WEB_SERVICE_URL");
        env::set_var(
            "ALOHOMORA_NOTIFICATION_URL",
            "https://relay.custom.org/send-notification",
        );
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.web_service_url, "https://relay.custom.org");
        assert_eq!(
            config.notification_url(),
            "https://relay.custom.org/send-notification"
        );
    }
}
