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

# Better OnlineHashCrack

Run the following command to install Better OnlineHashCrack

`sudo pwnagotchi plugins install better-ohcapi`

Add the following lines to your `/etc/pwnagotchi.config.toml`

```TOML
main.plugins.better-ohcapi.enabled = true
main.plugins.better-ohcapi.api_key = "your_ohc_key"
main.plugins.better-ohcapi.receive_email = "yes"
main.plugins.better-ohcapi.sleep = 3600
```

**Files created by this plugin:**

| File | Description |
|------|-------------|
| `/root/handshakes/onlinehashcrack.cracked` | Cracked passwords downloaded from OnlineHashCrack |

---
 
## pwngpu
 
Converts captured `.pcap` handshakes to `.hc22000` format and sends them over USB to a companion app running on your own PC, where they're cracked locally with your GPU via hashcat. No cloud upload and no third-party API key — everything stays on hardware you control.
 
Requires the [PwnGPU Crack Server](https://github.com/charveey/pwngpu-server) companion app running on Windows, with the Pwnagotchi tethered to it over USB (the plugin talks to the app over the `usb0` gadget interface, reaching it at `10.0.0.1` by default). <!-- add a link to the companion app repo here once it's published -->
 
Run the following command to install pwngpu
 
`sudo pwnagotchi plugins install pwngpu`
 
Add the following lines to your `/etc/pwnagotchi/config.toml`
 
```toml
main.plugins.pwngpu.enabled = true
main.plugins.pwngpu.api_key = "your_pwngpu_key"   # must match the key shown in the companion app
main.plugins.pwngpu.port = 6881
main.plugins.pwngpu.sleep = 1800
```
You can use `main.plugins.pwngpu.server_url = "http://url-to-your-remote--server"` to connect remotely to a server

**Files created by this plugin:**
 
| File | Description |
|------|-------------|
| `/root/handshakes/cracked.pwngpu.potfile` | Cracked passwords downloaded from the companion app |
| `/root/handshakes/.pwngpu_crack_status.json` | Tracks which pcaps have already been sent |
 
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
main.plugins.better-ohcapi.enabled = true
main.plugins.better-ohcapi.api_key = "your_ohc_key"
main.plugins.better-ohcapi.receive_email = "yes"
 
# OR crack locally on your own GPU instead of/alongside the cloud options
# above - no API key needed, just the companion app running on a tethered PC
main.plugins.pwngpu.enabled = true
main.plugins.pwngpu.api_key = "your_pwngpu_key"
 
# Display & aggregate results
main.plugins.cracked-pw.enabled = true
```

