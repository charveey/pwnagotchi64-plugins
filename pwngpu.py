import os
import subprocess
import requests
import logging
import json
import time
from threading import Lock
from pwnagotchi.plugins import Plugin
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts


class GpuCrack(Plugin):
    __author__ = 'charveey'
    __version__ = '2.0.2'
    __license__ = 'GPL3'
    __description__ = (
        'Sends uncracked handshakes to a GPU cracking server on your PC via USB gadget. '
        'Shows hashcat status on the display.'
    )

    POTFILE_PATH = '/root/handshakes/cracked.pwngpu.potfile'
    STATUS_PATH  = '/root/handshakes/.pwngpu_crack_status.json'

    # USB gadget interface — usb0 when tethered to a PC
    USB_IFACE    = 'usb0'
    # Default gateway over usb0 that points to the PC
    USB_GATEWAY  = '10.0.0.1'

    def __init__(self):
        self.lock        = Lock()
        self.last_run    = 0
        self.sent        = set()
        self.ui_status   = 'GPU: waiting'
        self._load_status()

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def on_loaded(self):
        missing = [f for f in ('api_key',) if not self.options.get(f)]
        if missing:
            logging.error(f"[pwngpu] Missing config fields: {missing}")
            return
        logging.info("[pwngpu] Plugin loaded.")

    def on_unload(self, ui):
        with ui._lock:
            try:
                ui.remove_element('pwngpu_crack_status')
            except KeyError:
                pass
        logging.info("[pwngpu] Plugin unloaded.")

    # ------------------------------------------------------------------ #
    #  UI                                                                  #
    # ------------------------------------------------------------------ #

    def on_ui_setup(self, ui):
        if ui.is_waveshare_v2() or ui.is_waveshare_v3() or ui.is_waveshare_v4():
            pos = (0, 128)
        elif ui.is_waveshare_v1():
            pos = (0, 128)
        elif ui.is_waveshare144lcd():
            pos = (0, 104)
        elif ui.is_inky():
            pos = (0, 96)
        elif ui.is_waveshare27inch():
            pos = (0, 165)
        else:
            pos = (0, 128)

        ui.add_element('pwngpu_crack_status', LabeledValue(
            color=BLACK,
            label='',
            value='GPU: waiting',
            position=pos,
            label_font=fonts.Bold,
            text_font=fonts.Small
        ))

    def on_ui_update(self, ui):
        ui.set('pwngpu_crack_status', self.ui_status)

    # ------------------------------------------------------------------ #
    #  Hooks                                                               #
    # ------------------------------------------------------------------ #

    def on_handshake(self, agent, filename, access_point, client_station):
        if not self._usb_connected():
            logging.debug("[pwngpu] USB not connected, skipping on_handshake.")
            return
        if self.lock.locked():
            return
        logging.info(f"[pwngpu] New handshake: {filename}")
        self._run(agent)
        self.last_run = time.time()

    def on_internet_available(self, agent):
        if not self._usb_connected():
            logging.debug("[pwngpu] USB not connected, skipping on_internet_available.")
            return
        if self.lock.locked():
            return
        sleep = self.options.get('sleep', 1800)
        if time.time() - self.last_run < sleep:
            return
        self._run(agent)
        self.last_run = time.time()

    def on_epoch(self, agent, epoch, epoch_data):
        if not self._usb_connected():
            return
        if self.lock.locked():
            return
        sleep = self.options.get('sleep', 1800)
        if time.time() - self.last_run < sleep:
            return
        self._run(agent)
        self.last_run = time.time()

    # ------------------------------------------------------------------ #
    #  USB gadget detection                                                #
    # ------------------------------------------------------------------ #

    def _usb_connected(self):
        """
        Returns True if the usb0 gadget interface is up and has an IP.
        This is only true when the Pwnagotchi is tethered to a PC.
        """
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', self.USB_IFACE],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0:
                self.ui_status = 'GPU: no USB'
                return False
            if 'inet ' in result.stdout:
                return True
            self.ui_status = 'GPU: no USB'
            return False
        except Exception as e:
            logging.debug(f"[pwngpu] USB check error: {e}")
            self.ui_status = 'GPU: no USB'
            return False

    def _get_server_url(self):
        """
        Build server URL: use config server_url if set,
        otherwise default to the USB gateway IP.
        """
        url = self.options.get('server_url', '').rstrip('/')
        if not url:
            port = self.options.get('port', 6881)
            url  = f"http://{self.USB_GATEWAY}:{port}"
        return url

    # ------------------------------------------------------------------ #
    #  Status persistence                                                  #
    # ------------------------------------------------------------------ #

    def _load_status(self):
        if os.path.exists(self.STATUS_PATH):
            try:
                with open(self.STATUS_PATH, 'r') as f:
                    data = json.load(f)
                    self.sent = set(data.get('sent', []))
                logging.debug(f"[pwngpu] Loaded {len(self.sent)} previously sent entries.")
            except Exception as e:
                logging.warning(f"[pwngpu] Could not load status: {e}")
                self.sent = set()

    def _save_status(self):
        try:
            with open(self.STATUS_PATH, 'w') as f:
                json.dump({'sent': list(self.sent)}, f)
        except Exception as e:
            logging.warning(f"[pwngpu] Could not save status: {e}")

    # ------------------------------------------------------------------ #
    #  Core logic                                                          #
    # ------------------------------------------------------------------ #

    def _run(self, agent):
        with self.lock:
            server_url    = self._get_server_url()
            api_key       = self.options['api_key']
            config        = agent.config()
            handshake_dir = config['bettercap']['handshakes']
            whitelist     = self.options.get('whitelist', [])

            self.ui_status = 'GPU: connecting...'

            if not self._ping_server(server_url, api_key):
                logging.warning(f"[pwngpu] Server unreachable at {server_url}")
                self.ui_status = 'GPU: offline'
                return

            self.ui_status = 'GPU: online'

            pcaps = [
                f for f in os.listdir(handshake_dir)
                if f.endswith('.pcap')
                and f not in self.sent
                and not any(w in f for w in whitelist)
            ]

            if not pcaps:
                logging.debug("[pwngpu] No new pcaps to send.")
                self._fetch_and_save_results(server_url, api_key)
                self.ui_status = 'GPU: idle'
                return

            logging.info(f"[pwngpu] Sending {len(pcaps)} pcap(s) to GPU server.")
            self.ui_status = f"GPU: sending {len(pcaps)} file(s)"

            for pcap_file in pcaps:
                pcap_path = os.path.join(handshake_dir, pcap_file)
                hc_path   = pcap_path.replace('.pcap', '.tmp.hc22000')

                hashes = self._convert(pcap_path, hc_path)
                if not hashes:
                    logging.debug(f"[pwngpu] No hashes from {pcap_file}.")
                    self.sent.add(pcap_file)
                    continue

                self.ui_status = f"GPU: cracking {pcap_file[:16]}"
                success, cracked_count = self._send(server_url, api_key, hc_path, pcap_file)

                if success:
                    self.sent.add(pcap_file)
                    if cracked_count > 0:
                        self.ui_status = f"GPU: {cracked_count} cracked!"
                        logging.info(f"[pwngpu] {cracked_count} password(s) cracked from {pcap_file}")
                    else:
                        self.ui_status = 'GPU: no match'

                if os.path.exists(hc_path):
                    os.remove(hc_path)

            self._save_status()
            self._fetch_and_save_results(server_url, api_key)

    def _convert(self, pcap_path, hc_path):
        try:
            subprocess.run(
                ['hcxpcapngtool', '-o', hc_path, pcap_path],
                capture_output=True, text=True, timeout=60
            )
            if os.path.exists(hc_path) and os.path.getsize(hc_path) > 0:
                with open(hc_path, 'r') as f:
                    return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            logging.error("[pwngpu] hcxpcapngtool not found.")
        except Exception as e:
            logging.error(f"[pwngpu] Conversion error: {e}")
        return []

    def _ping_server(self, server_url, api_key):
        try:
            r = requests.get(
                f"{server_url}/health",
                headers={'X-API-Key': api_key},
                timeout=5
            )
            return r.status_code == 200
        except Exception:
            return False

    def _send(self, server_url, api_key, hc_path, original_name):
        """POST the .hc22000 to /crack. Returns (success, cracked_count)."""
        try:
            with open(hc_path, 'rb') as f:
                response = requests.post(
                    f"{server_url}/crack",
                    headers={'X-API-Key': api_key},
                    files={'file': (original_name.replace('.pcap', '.hc22000'), f, 'application/octet-stream')},
                    timeout=60
                )
            response.raise_for_status()
            data = response.json()
            if data.get('cracked'):
                self._save_results(data['cracked'])
            return True, data.get('total', 0)
        except requests.exceptions.ConnectionError:
            logging.warning("[pwngpu] Connection error during send.")
        except requests.exceptions.Timeout:
            logging.warning("[pwngpu] Server timed out during send.")
        except Exception as e:
            logging.error(f"[pwngpu] Send error: {e}")
        return False, 0

    def _fetch_and_save_results(self, server_url, api_key):
        try:
            r = requests.get(
                f"{server_url}/results",
                headers={'X-API-Key': api_key},
                timeout=10
            )
            r.raise_for_status()
            cracked = r.json().get('cracked', [])
            if cracked:
                self._save_results(cracked)
                self.ui_status = f"GPU: {len(cracked)} total"
                logging.info(f"[pwngpu] {len(cracked)} total result(s) in server potfile.")
        except Exception as e:
            logging.warning(f"[pwngpu] Could not fetch results: {e}")

    def _save_results(self, cracked):
        if not cracked:
            return
        existing = set()
        if os.path.exists(self.POTFILE_PATH):
            with open(self.POTFILE_PATH, 'r', encoding='utf-8') as f:
                existing = set(line.strip() for line in f if line.strip())
        new_lines = []
        for entry in cracked:
            ssid     = entry.get('ssid', 'unknown')
            bssid    = entry.get('bssid', '00:00:00:00:00:00')
            password = entry.get('password', '')
            if not password:
                continue
            line = f"{bssid}:{bssid}:{ssid}:{password}"
            if line not in existing:
                new_lines.append(line)
                existing.add(line)
        if new_lines:
            with open(self.POTFILE_PATH, 'a', encoding='utf-8') as f:
                for line in new_lines:
                    f.write(line + '\n')
            logging.info(f"[pwngpu] Saved {len(new_lines)} new password(s).")