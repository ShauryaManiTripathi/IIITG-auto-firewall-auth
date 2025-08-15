#!/bin/bash

# A robust, multi-distro installer for the IIITG Auth Client.
# It detects the Linux distribution family, checks dependencies, compiles the Rust code,
# installs the binary, and sets up a systemd service.

# --- Script Configuration ---
set -euo pipefail

# --- Color Definitions ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'

# --- Helper Functions ---
info() {
    echo -e "${C_BLUE}INFO:${C_RESET} $1"
}

success() {
    echo -e "${C_GREEN}SUCCESS:${C_RESET} $1"
}

warn() {
    echo -e "${C_YELLOW}WARNING:${C_RESET} $1"
}

error() {
    echo -e "${C_RED}ERROR:${C_RESET} $1"
    exit 1
}

# --- Main Logic ---
main() {
    if [[ "$EUID" -eq 0 ]]; then
        error "This script should not be run as root. It will use 'sudo' when necessary."
    fi

    info "Starting the installation of IIITG Auth Client."
    echo

    check_dependencies
    check_rust
    compile_and_install
    setup_systemd_service

    echo
    success "IIITG Auth Client installation is complete!"
    echo
    info "--------------------------- IMPORTANT NEXT STEPS ---------------------------"
    info "1. You MUST configure your account credentials now."
    info "   Run the following command:"
    echo -e "   ${C_YELLOW}iiitg-auth --manage${C_RESET}"
    echo
    info "2. The background service has been started. To check its status, run:"
    echo -e "   ${C_YELLOW}systemctl --user status iiitg-auth.service${C_RESET}"
    echo
    info "3. To view live logs from the service, run:"
    echo -e "   ${C_YELLOW}journalctl --user -u iiitg-auth.service -f${C_RESET}"
    info "--------------------------------------------------------------------------"
}

check_dependencies() {
    info "Checking for required system dependencies..."

    if ! [ -f /etc/os-release ]; then
        error "Cannot detect Linux distribution: /etc/os-release not found."
    fi
    . /etc/os-release

    local distro_family=""
    if [[ -n "${ID_LIKE-}" ]]; then
        if [[ "$ID_LIKE" =~ "debian" ]]; then distro_family="debian";
        elif [[ "$ID_LIKE" =~ "fedora" ]]; then distro_family="fedora";
        elif [[ "$ID_LIKE" =~ "arch" ]]; then distro_family="arch"; fi
    fi

    if [[ -z "$distro_family" ]]; then
        if [[ "$ID" =~ "debian"|"ubuntu"|"pop"|"mint" ]]; then distro_family="debian";
        elif [[ "$ID" =~ "fedora"|"centos"|"rhel" ]]; then distro_family="fedora";
        elif [[ "$ID" =~ "arch"|"manjaro"|"endeavouros" ]]; then distro_family="arch"; fi
    fi

    local pkg_manager_check_cmd=""
    local install_cmd=""
    local update_cmd=""
    local required_pkgs=()

    case "$distro_family" in
        debian)
            info "Debian-based distribution detected ($NAME)."
            pkg_manager_check_cmd="dpkg -s"
            update_cmd="sudo apt-get update"
            install_cmd="sudo apt-get install -y"
            required_pkgs=("build-essential" "pkg-config" "libssl-dev" "curl")
            ;;
        fedora)
            info "Fedora/RHEL-based distribution detected ($NAME)."
            pkg_manager_check_cmd="rpm -q"
            install_cmd="sudo dnf install -y"
            required_pkgs=("gcc" "gcc-c++" "make" "pkgconf-pkg-config" "openssl-devel" "curl")
            ;;
        arch)
            info "Arch-based distribution detected ($NAME)."
            pkg_manager_check_cmd="pacman -Q"
            install_cmd="sudo pacman -S --noconfirm --needed"
            required_pkgs=("base-devel" "openssl" "curl")
            ;;
        *)
            error "Unsupported distribution: '$NAME'. Please install dependencies manually and re-run.
Required: C/C++ compiler, make, pkg-config, OpenSSL headers (libssl-dev/openssl-devel), curl."
            ;;
    esac

    local missing_pkgs=()
    for pkg in "${required_pkgs[@]}"; do
        if ! $pkg_manager_check_cmd "$pkg" &> /dev/null; then missing_pkgs+=("$pkg"); fi
    done

    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        warn "The following packages are required but not found: ${missing_pkgs[*]}"
        read -p "Do you want to install them now? (y/N): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            info "Installing missing packages. This may require your password."
            [[ -n "$update_cmd" ]] && $update_cmd
            $install_cmd "${missing_pkgs[@]}" || error "Failed to install required packages."
            success "Dependencies installed."
        else
            error "Dependencies not installed. Aborting installation."
        fi
    else
        success "All system dependencies are already installed."
    fi
    echo
}

check_rust() {
    info "Checking for Rust compiler (cargo)..."
    if command -v cargo &> /dev/null; then
        success "Rust is already installed."
    else
        warn "Rust is not installed. It is required to compile the client."
        read -p "Do you want to install Rust via rustup now? (y/N): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            info "Downloading and running rustup-init.sh..."
            # CORRECTED: Using the secure curl command with non-interactive flags
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
            success "Rust has been installed."
        else
            error "Rust not installed. Aborting installation."
        fi
    fi
    echo
}

compile_and_install() {
    local TEMP_DIR
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    info "Setting up build environment in $TEMP_DIR"
    cd "$TEMP_DIR"
    mkdir -p iiitg-auth/src
    cd iiitg-auth

    info "Creating Cargo.toml..."
    cat > Cargo.toml << EOL
[package]
name = "iiitg-auth"
version = "0.2.1"
edition = "2021"

[dependencies]
tokio = { version = "1.0", features = ["macros", "rt-multi-thread", "time", "process"] }
reqwest = { version = "0.12", features = ["json"] }
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
aes-gcm = "0.10"
rand = "0.8"
dialoguer = "0.11"
notify-rust = "4"
directories = "6.0"
log = "0.4"
env_logger = "0.11"
futures = "0.3"
EOL

    info "Creating src/main.rs..."
    cat > src/main.rs << 'EOL'
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};
use anyhow::{Context, Result, anyhow};
use dialoguer::{Input, Password, Select};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Duration};
use tokio::{self, time::sleep};
use futures::future;
use reqwest;
use notify_rust::Notification;
use directories::BaseDirs;
use log::{info, error, warn, debug};

#[derive(Serialize, Deserialize, Clone)]
struct Credential {
    username: String,
    encrypted_password: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AccountList {
    accounts: Vec<Credential>,
    primary_index: usize,
}

#[derive(Debug)]
enum NetworkState {
    Connected(String),
    Disconnected,
}

#[derive(Debug)]
enum AuthResult {
    Success(String),    // Username that succeeded
    Failure(String),    // Error message
    NetworkError(String), // Network-related error
}

struct AuthClient {
    creds_path: PathBuf,
    key: Key<Aes256Gcm>,
    last_state: NetworkState,
    account_list: Option<AccountList>,
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
            account_list: None,
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

    async fn authenticate_with_creds(&self, creds: &Credential) -> Result<AuthResult> {
        let password = self.decrypt_password(&creds.encrypted_password, &creds.nonce)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        let a = format!("{}", timestamp);

        info!("Attempting authentication for user: {}", creds.username);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        let response = match client
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
            .await {
                Ok(resp) => resp,
                Err(e) => return Ok(AuthResult::NetworkError(format!("Network error: {}", e))),
            };

        if response.status().is_success() {
            let response_text = response.text().await?;
            debug!("Authentication response: {}", response_text);

            if response_text.contains("signed in") {
                info!("Authentication successful for user: {}", creds.username);
                return Ok(AuthResult::Success(creds.username.clone()));
            } else {
                warn!("Authentication failed for user: {}", creds.username);
                return Ok(AuthResult::Failure(format!("Authentication failed for {}", creds.username)));
            }
        } else {
            warn!("HTTP request failed with status: {}", response.status());
            return Ok(AuthResult::NetworkError(format!("HTTP error: {}", response.status())));
        }
    }

    async fn authenticate(&mut self) -> Result<()> {
        info!("Starting authentication process...");

        // Try loading accounts if not already loaded
        if self.account_list.is_none() {
            info!("Loading accounts from disk");
            if let Err(e) = self.load_accounts() {
                error!("Failed to load accounts: {}", e);
                // Don't try to set up new accounts here - let the interactive interface handle that
                return Err(anyhow!("No accounts found"));
            }
        }

        // Now that we've ensured accounts are loaded, attempt authentication
        let account_list = match &self.account_list {
            Some(list) => list,
            None => {
                return Err(anyhow!("No accounts loaded"));
            }
        };

        if account_list.accounts.is_empty() {
            return Err(anyhow!("No accounts found"));
        }

        return self.authenticate_with_loaded_accounts().await;
    }

    // Helper method to avoid recursion
    async fn authenticate_with_loaded_accounts(&self) -> Result<()> {
        let account_list = self.account_list.as_ref().unwrap();

        info!("Found {} accounts, starting with primary account (index {})",
              account_list.accounts.len(), account_list.primary_index);

        // Start with primary account
        let mut account_indices: Vec<usize> = vec![account_list.primary_index];

        // Add other accounts
        for i in 0..account_list.accounts.len() {
            if i != account_list.primary_index {
                account_indices.push(i);
            }
        }

        for idx in account_indices {
            if idx >= account_list.accounts.len() {
                continue;
            }

            let creds = &account_list.accounts[idx];
            match self.authenticate_with_creds(creds).await? {
                AuthResult::Success(username) => {
                    Notification::new()
                        .summary("IIITG Network")
                        .body(&format!("Successfully authenticated as {}!", username))
                        .show()?;
                    return Ok(());
                },
                AuthResult::Failure(msg) => {
                    info!("{}", msg);
                    // Continue to next account
                },
                AuthResult::NetworkError(msg) => {
                    warn!("{}", msg);
                    Notification::new()
                        .summary("IIITG Network")
                        .body("Connection failed. Please check your network.")
                        .show()?;
                    // Network error - stop trying other accounts
                    return Ok(());
                }
            }
        }

        // If all accounts failed
        warn!("All accounts failed authentication");
        Notification::new()
            .summary("IIITG Network")
            .body("Authentication failed with all accounts. Check credentials.")
            .show()?;

        Ok(())
    }

    async fn prompt_and_add_account(&self) -> Result<()> {
        println!("Please enter your IIITG credentials:");

        let username: String = Input::new()
            .with_prompt("IIITG Username")
            .interact()
            .context("Failed to get username input")?;

        let password: String = Password::new()
            .with_prompt("IIITG Password")
            .interact()
            .context("Failed to get password input")?;

        let (encrypted_password, nonce) = self.encrypt_password(&password)?;

        let new_cred = Credential {
            username,
            encrypted_password,
            nonce,
        };

        // Create or update account list
        let mut account_list = self.account_list.clone().unwrap_or(AccountList {
            accounts: vec![],
            primary_index: 0,
        });

        account_list.accounts.push(new_cred);
        account_list.primary_index = account_list.accounts.len() - 1;

        // Save to disk
        let json = serde_json::to_string_pretty(&account_list)?;
        fs::write(&self.creds_path, json)?;

        println!("Account added successfully.");

        Ok(())
    }

    fn load_accounts(&mut self) -> Result<()> {
        if self.creds_path.exists() {
            let data = fs::read_to_string(&self.creds_path)?;

            // Try loading as AccountList first (new format)
            match serde_json::from_str::<AccountList>(&data) {
                Ok(account_list) => {
                    info!("Loaded {} accounts from file", account_list.accounts.len());
                    self.account_list = Some(account_list.clone());
                    return Ok(());
                },
                Err(_) => {
                    // Maybe it's old format (single credential)
                    match serde_json::from_str::<Credential>(&data) {
                        Ok(cred) => {
                            info!("Found legacy credentials format, converting to multi-account format");
                            let account_list = AccountList {
                                accounts: vec![cred],
                                primary_index: 0,
                            };
                            self.account_list = Some(account_list.clone());

                            // Save in new format
                            let json = serde_json::to_string_pretty(&account_list)?;
                            fs::write(&self.creds_path, json)?;

                            return Ok(());
                        },
                        Err(e) => {
                            error!("Failed to parse credentials file: {}", e);
                            return Err(anyhow!("Invalid credentials file format"));
                        }
                    }
                }
            }
        } else {
            return Err(anyhow!("No credentials file found"));
        }
    }

    async fn manage_accounts(&mut self) -> Result<()> {
        if let Err(e) = self.load_accounts() {
            println!("No accounts found. Please add an account first.");
            self.prompt_and_add_account().await?;
            self.load_accounts()?;
            println!("Account added successfully!");
            return Ok(());
        }

        loop {
            let account_list = self.account_list.as_ref().unwrap();
            let usernames: Vec<String> = account_list.accounts.iter()
                .map(|cred| cred.username.clone())
                .collect();

            let options = vec![
                "➕ Add new account",
                "🔄 Set primary account",
                "🗑️ Remove account",
                "🔙 Exit"
            ];

            let selection = Select::new()
                .with_prompt("Account management")
                .items(&options)
                .default(0)
                .interact()?;

            match selection {
                0 => {
                    // Add new account
                    self.prompt_and_add_account().await?;
                    self.load_accounts()?;
                    println!("Account added successfully!");
                },
                1 => {
                    // Set primary account
                    if usernames.is_empty() {
                        println!("No accounts to set as primary.");
                        continue;
                    }

                    let account_idx = Select::new()
                        .with_prompt("Select primary account")
                        .items(&usernames)
                        .default(0)
                        .interact()?;

                    let mut account_list = self.account_list.clone().unwrap();
                    account_list.primary_index = account_idx;

                    let json = serde_json::to_string_pretty(&account_list)?;
                    fs::write(&self.creds_path, json)?;

                    self.load_accounts()?;
                    println!("Primary account set to: {}", usernames[account_idx]);
                },
                2 => {
                    // Remove account
                    if usernames.is_empty() {
                        println!("No accounts to remove.");
                        continue;
                    }

                    let account_idx = Select::new()
                        .with_prompt("Select account to remove")
                        .items(&usernames)
                        .default(0)
                        .interact()?;

                    let mut account_list = self.account_list.clone().unwrap();
                    let removed_username = account_list.accounts[account_idx].username.clone();
                    account_list.accounts.remove(account_idx);

                    // Update primary index if needed
                    if account_list.accounts.is_empty() {
                        account_list.primary_index = 0;
                    } else if account_idx == account_list.primary_index {
                        account_list.primary_index = 0;
                    } else if account_idx < account_list.primary_index {
                        account_list.primary_index -= 1;
                    }

                    let json = serde_json::to_string_pretty(&account_list)?;
                    fs::write(&self.creds_path, json)?;

                    self.load_accounts()?;
                    println!("Removed account: {}", removed_username);
                },
                3 | _ => {
                    println!("Exiting account management.");
                    return Ok(());
                }
            }
        }
    }

    async fn run(&mut self) -> Result<()> {
        info!("Starting IIITG Auth Client daemon mode...");

        // Check if there are no accounts and remind the user to set them up
        if let Err(e) = self.load_accounts() {
            println!("No accounts found. Please run 'iiitg-auth --manage' to add your accounts.");
            info!("No accounts found: {}", e);
            return Ok(());
        }

        info!("Found {} accounts", self.account_list.as_ref().unwrap().accounts.len());
        if let Err(e) = self.authenticate().await {
            error!("Initial authentication error: {}", e);
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

    async fn interactive_mode(&mut self) -> Result<()> {
        println!("IIITG Auth Client Interactive Mode");
        println!("==================================");

        // Always show account management screen when in interactive mode
        self.manage_accounts().await
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

    // Check if running in interactive mode (explicit flag)
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 && args[1] == "--manage" {
        // User explicitly asked for management mode
        client.interactive_mode().await?;
    } else {
        // Check if we're running interactively or as a service
        let is_interactive = std::env::var("TERM").map(|term| !term.is_empty()).unwrap_or(false);
        
        if is_interactive {
            // If running in a terminal but without --manage, start in daemon mode
            // but print informative message
            println!("IIITG Auth Client starting in daemon mode.");
            println!("To manage accounts, use 'iiitg-auth --manage'");
            println!("Press Ctrl+C to exit.\n");
            
            // Run the client
            client.run().await?;
        } else {
            // Running as a service, just start daemon mode
            client.run().await?;
        }
    }

    Ok(())
}
EOL

    info "Compiling the Rust project (this may take a few minutes)..."
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    cargo build --release || error "Compilation failed. Please check the error messages above."
    success "Project compiled successfully."
    echo

    info "Installing the binary to /usr/local/bin..."
    sudo cp target/release/iiitg-auth /usr/local/bin/iiitg-auth
    sudo chmod +x /usr/local/bin/iiitg-auth
    success "Binary installed."
}

setup_systemd_service() {
    info "Setting up systemd service to run the client in the background..."
    local current_user
    current_user=$(whoami)
    local service_file_path="$HOME/.config/systemd/user/iiitg-auth.service"

    mkdir -p "$HOME/.config/systemd/user"

    info "Creating systemd service file at $service_file_path"
    cat > "$service_file_path" << EOL
[Unit]
Description=IIITG Auth Client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/iiitg-auth
Restart=on-failure
RestartSec=10
Environment="RUST_LOG=info"

[Install]
WantedBy=default.target
EOL
    success "Service file created."

    info "Enabling and starting the service for user $current_user..."
    sudo loginctl enable-linger "$current_user"

    systemctl --user daemon-reload
    systemctl --user enable iiitg-auth.service
    systemctl --user restart iiitg-auth.service

    success "Systemd service 'iiitg-auth.service' is now enabled and running."
}

main
