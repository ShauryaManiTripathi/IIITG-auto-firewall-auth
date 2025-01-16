use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};
use anyhow::{Context, Result, anyhow};
use dialoguer::{Input, Password};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Duration};
use tokio::{self, time::sleep};
use reqwest;
use notify_rust::Notification;
use directories::BaseDirs;
use log::{info, error, warn};

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: String,
    encrypted_password: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Debug)]
enum NetworkState {
    Connected(String),
    Disconnected,
}

struct AuthClient {
    creds_path: PathBuf,
    key: Key<Aes256Gcm>,
    last_state: NetworkState,
}

impl AuthClient {
    fn new() -> Result<Self> {
        let base_dirs = BaseDirs::new().context("Failed to get base directories")?;
        let config_dir = base_dirs.config_dir().join("iiitg-auth");
        fs::create_dir_all(&config_dir)?;
        
        let mut key_bytes = [0u8; 32];
        let key_str = b"IIITG-AUTH-CLIENT-STATIC-KEY-32BYTE!";
        key_bytes[..32].copy_from_slice(&key_str[..32]);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        Ok(Self {
            creds_path: config_dir.join("credentials.json"),
            key: *key,
            last_state: NetworkState::Disconnected,
        })
    }

    async fn get_current_wifi() -> Result<NetworkState> {
        let output = tokio::process::Command::new("nmcli")
            .args(["-t", "-f", "active,ssid", "dev", "wifi"])
            .output()
            .await?;
            
        if output.status.success() {
            let connections = String::from_utf8_lossy(&output.stdout);
            for line in connections.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 && parts[0] == "yes" {
                    return Ok(NetworkState::Connected(parts[1].to_string()));
                }
            }
        }
        Ok(NetworkState::Disconnected)
    }

    fn encrypt_password(&self, password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce_vec: Vec<u8> = rand::thread_rng().gen::<[u8; 12]>().to_vec();
        let nonce = Nonce::from_slice(&nonce_vec);
        let encrypted = cipher.encrypt(nonce, password.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        Ok((encrypted, nonce_vec))
    }

    fn decrypt_password(&self, encrypted: &[u8], nonce: &[u8]) -> Result<String> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Nonce::from_slice(nonce);
        let decrypted = cipher.decrypt(nonce, encrypted)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        String::from_utf8(decrypted).context("Invalid UTF-8")
    }

    async fn authenticate(&self) -> Result<()> {
        info!("Checking credentials...");
        
        let creds = if self.creds_path.exists() {
            info!("Found existing credentials");
            let data = fs::read_to_string(&self.creds_path)?;
            serde_json::from_str(&data)?
        } else {
            info!("No credentials found, prompting for new ones");
            self.prompt_credentials()?
        };

        let password = self.decrypt_password(&creds.encrypted_password, &creds.nonce)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        let a = format!("{}", timestamp);

        info!("Attempting authentication for user: {}", creds.username);
        
        let client = reqwest::Client::new();
        let response = client
            .post("https://secure.iiitg.ac.in:8090/login.xml")
            .header("Accept", "*/*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Connection", "keep-alive")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Origin", "https://secure.iiitg.ac.in:8090")
            .header("Referer", "https://secure.iiitg.ac.in:8090/")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "same-origin")
            .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .header("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Linux\"")
            .form(&[
                ("mode", "191"),
                ("username", &creds.username),
                ("password", &password),
                ("a", &a),
                ("producttype", "0"),
            ])
            .send()
            .await?;

        if response.status().is_success() {
            let response_text = response.text().await?;
            info!("Authentication response: {}", response_text);
            
            if response_text.contains("LOGIN") || response_text.contains("success") {
                info!("Authentication successful for user: {}", creds.username);
                Notification::new()
                    .summary("IIITG Network")
                    .body(&format!("Successfully authenticated as {}!", creds.username))
                    .show()?;
            } else {
                warn!("Authentication failed for user: {}", creds.username);
                if self.creds_path.exists() {
                    fs::remove_file(&self.creds_path)?;
                    info!("Deleted invalid credentials file");
                }
                Notification::new()
                    .summary("IIITG Network")
                    .body("Authentication failed. Please check credentials.")
                    .show()?;
            }
        } else {
            warn!("HTTP request failed with status: {}", response.status());
            Notification::new()
                .summary("IIITG Network")
                .body("Connection failed. Please check your network.")
                .show()?;
        }

        Ok(())
    }

    fn prompt_credentials(&self) -> Result<Credentials> {
        println!("Please enter your IIITG credentials:");
        
        let username: String = Input::new()
            .with_prompt("IIITG Username")
            .interact()
            .context("Failed to get username input")?;
            
        let password: String = Password::new()
            .with_prompt("IIITG Password")
            .interact()
            .context("Failed to get password input")?;
        println!("Now, the client might throw some error , but ignore it and press Ctrl+C");
        let (encrypted_password, nonce) = self.encrypt_password(&password)?;
        
        let creds = Credentials {
            username,
            encrypted_password,
            nonce,
        };
        
        let json = serde_json::to_string_pretty(&creds)?;
        fs::write(&self.creds_path, json)?;
        
        Ok(creds)
    }

    async fn run(&mut self) -> Result<()> {
        info!("Starting IIITG Auth Client...");
        
        if self.creds_path.exists() {
            if let Err(e) = self.authenticate().await {
            error!("Initial authentication error: {}", e);
            }
        } else {
            info!("No credentials found, waiting for network connection...");
        }
        
        loop {
            match Self::get_current_wifi().await {
                Ok(current_state) => {
                    match (&self.last_state, &current_state) {
                        (NetworkState::Disconnected, NetworkState::Connected(ssid)) => {
                            info!("Connected to WiFi: {}", ssid);
                            if ssid.contains("IIITG") {
                                sleep(Duration::from_secs(2)).await;
                                if let Err(e) = self.authenticate().await {
                                    error!("Authentication error: {}", e);
                                }
                            }
                        },
                        (NetworkState::Connected(old_ssid), NetworkState::Connected(new_ssid)) => {
                            if old_ssid != new_ssid && new_ssid.contains("IIITG") {
                                info!("Network changed: {} -> {}", old_ssid, new_ssid);
                                sleep(Duration::from_secs(2)).await;
                                if let Err(e) = self.authenticate().await {
                                    error!("Authentication error: {}", e);
                                }
                            }
                        },
                        (NetworkState::Connected(ssid), NetworkState::Disconnected) => {
                            info!("Disconnected from WiFi: {}", ssid);
                        },
                        _ => {}
                    }
                    self.last_state = current_state;
                },
                Err(e) => {
                    error!("Error checking WiFi state: {}", e);
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger with timestamp
    env_logger::builder()
        .format_timestamp_secs()
        .init();
    
    info!("IIITG Auth Client starting...");
    let mut client = AuthClient::new()?;
    client.run().await
}