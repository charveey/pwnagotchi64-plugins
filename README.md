# pwnagotchi64-plugins
A collection of plugins to automatically upload, crack, display, and manage WiFi handshakes captured by your Pwnagotchi.

Edit your `/etc/pwnagotchi/config.toml` to look like this

```TOML
main.custom_plugin_repos = [
    "https://github.com/charveey/pwnagotchi64-plugins/archive/master.zip",
    ]
```
Then run this command: `sudo pwnagotchi plugins update`


## better-pwncrack

Converts captured `.pcap` handshakes to `.hc22000` format and uploads them to [pwncrack.org](https://pwncrack.org) for cracking. Automatically downloads results back to your device.

Run the following command to install Better-pwncrack

`sudo pwnagotchi plugins install better-pwncrack`

Add the following lines to your `/etc/pwnagotchi.config.toml`

```TOML
main.plugins.better-pwncrack.enabled = true
main.plugins.better-pwncrack.key = "your_pwncrack_key"
```

**Files created by this plugin:**

| File | Description |
|------|-------------|
| `/root/handshakes/cracked.pwncrack.potfile` | Cracked passwords downloaded from pwncrack.org |
| `/root/handshakes/.pwncrack_uploaded.json` | Tracks which pcaps have already been uploaded |

---

# OnlineHashCrack v2

Run the following command to install OnlineHashCrack

`sudo pwnagotchi plugins install ohcapi`

Add the following lines to your `/etc/pwnagotchi.config.toml`

```TOML
main.plugins.ohcapi.enabled = true
main.plugins.ohcapi.api_key = "your_ohc_key"
main.plugins.ohcapi.receive_email = "yes"
main.plugins.ohcapi.sleep = 3600
```

**Files created by this plugin:**

| File | Description |
|------|-------------|
| `/root/handshakes/onlinehashcrack.cracked` | Cracked passwords downloaded from OnlineHashCrack |


---

## cracked-pw

Aggregates cracked passwords from all sources (wpa-sec, pwncrack, onlinehashcrack), displays the most recently cracked password on screen, generates WiFi QR codes, and builds a wordlist compatible with the `quickdic` plugin.

Run the following command to install OnlineHashCrack

`sudo pwnagotchi plugins install cracked-pw`

Install the required dependency:
```bash
sudo apt update && sudo apt install python3-qr
```

Add the following lines to your `/etc/pwnagotchi/config.toml`

```toml
main.plugins.cracked-pw.enabled = true
main.plugins.cracked-pw.orientation = "horizontal"  # or "vertical"
```

**Potfiles read by this plugin:**

| Source | Path |
|--------|------|
| wpa-sec | `/root/handshakes/wpa-sec.cracked.potfile` |
| pwncrack | `/root/handshakes/cracked.pwncrack.potfile` |
| onlinehashcrack | `/root/handshakes/onlinehashcrack.cracked` |

**Files created by this plugin:**

| File | Description |
|------|-------------|
| `/home/pwn/wordlists/mycracked.txt` | Deduplicated wordlist of all cracked passwords |
| `/home/pwn/qrcodes/<SSID>-<password>.txt` | ASCII QR codes for each cracked network |

---

## Recommended stack

These plugins are designed to work together alongside the official `wpa-sec` plugin:

```toml
# Upload to wpa-sec
main.plugins.wpa-sec.enabled = true
main.plugins.wpa-sec.api_key = "your_wpasec_key"
main.plugins.wpa-sec.download_results = true
main.plugins.wpa-sec.download_interval = 3600

# Upload to pwncrack
main.plugins.better-pwncrack.enabled = true
main.plugins.better-pwncrack.key = "your_pwncrack_key"

# Upload to OnlineHashCrack
main.plugins.ohcapi.enabled = true
main.plugins.ohcapi.api_key = "your_ohc_key"
main.plugins.ohcapi.receive_email = "yes"

# Display & aggregate results
main.plugins.cracked-pw.enabled = true
main.plugins.cracked-pw.orientation = "horizontal"
```

