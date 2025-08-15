# IIITG Auto Firewall Auth [![Rust](https://img.shields.io/badge/language-Rust-orange.svg?logo=rust)](https://www.rust-lang.org/)
This script automates firewall authentication for IIITG networks.

### Requirement
Linux System with [Systemd] and [pacman|apt|dnf]

### Installation and Usage
To fetch and execute the script, simply run the following command in your terminal:
## With Curl
```bash
curl -fsSL https://github.com/ShauryaManiTripathi/IIITG-auto-firewall-auth/releases/download/release/manager.sh -o manager.sh && chmod +x manager.sh && sudo ./manager.sh
```

## With Wget
```bash
wget https://github.com/ShauryaManiTripathi/IIITG-auto-firewall-auth/releases/download/release/manager.sh -O manager.sh && chmod +x manager.sh && sudo ./manager.sh
```
after installing ,run 
```bash
iiitg-auth --manage
```
to add username and password


