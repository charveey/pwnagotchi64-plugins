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

log = logging.getLogger(__name__)


class GpuCrack(Plugin):
    __author__ = 'charveey'
    __version__ = '2.6.0'
    __license__ = 'GPL3'
    __description__ = (
        'Sends uncracked handshakes to a GPU cracking server on your PC via USB gadget. '
        'Shows hashcat status on the display.'
    )

    POTFILE_PATH  = '/root/handshakes/cracked.pwngpu.potfile'
    STATUS_PATH   = '/root/handshakes/.pwngpu_crack_status.json'
    DEFAULT_HS_DIR = '/root/handshakes'
    USB_IFACE     = 'usb0'
    USB_OWN_IP    = '10.0.0.2'
    USB_GATEWAY   = '10.0.0.1'
    POLL_INTERVAL = 60
    CAPTURE_EXTENSIONS = ('.pcap', '.pcapng')

    def __init__(self):
        self._run_lock     = Lock()   # prevents concurrent _run() calls
        self._status_lock  = Lock()   # protects ui_status for cross-thread safety
        self.last_run      = 0
        self.sent          = set()
        self._ui_status    = 'GPU: waiting'
        self._status       = 'waiting'
        self._handshake_dir = self.DEFAULT_HS_DIR
        self._stop_event   = Event()
        self._poll_thread  = None
        self._load_status()

    # ------------------------------------------------------------------ #
    #  Status helper                                                       #
    # ------------------------------------------------------------------ #

    @property
    def ui_status(self):
        with self._status_lock:
            return self._ui_status

    @ui_status.setter
    def ui_status(self, value):
        with self._status_lock:
            self._ui_status = value

    def _set_status(self, state: str, detail: str = '', log_it: bool = True):
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
        text = label_map.get(state, f'GPU: {state}')
        self.ui_status = text
        if log_it:
            log.info(f"[pwngpu] {text}")

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def on_loaded(self):
        if not self.options.get('api_key'):
            log.error("[pwngpu] Missing required config field: api_key")
            return
        self._set_status('waiting')
        self._stop_event.clear()
        self._poll_thread = Thread(
            target=self._poller, daemon=True, name='pwngpu-poll'
        )
        self._poll_thread.start()
        log.info(
            f"[pwngpu] v{self.__version__} loaded — "
            f"hs_dir={self._handshake_dir} "
            f"server={self._get_server_url()} "
            f"poll={self.POLL_INTERVAL}s "
            f"sleep={self.options.get('sleep', 1800)}s"
        )

    def on_unload(self, ui):
        self._stop_event.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
        with ui._lock:
            try:
                ui.remove_element('pwngpu_crack_status')
            except KeyError:
                pass
        log.info("[pwngpu] Plugin unloaded.")

    # ------------------------------------------------------------------ #
    #  Background poller                                                   #
    # ------------------------------------------------------------------ #

    def _poller(self):
        while not self._stop_event.is_set():
            try:
                self._poll_tick()
            except Exception as e:
                log.error(f"[pwngpu] poller error: {e}")
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_tick(self):
        if not self._usb_connected():
            return

        sleep   = self.options.get('sleep', 1800)
        elapsed = time.time() - self.last_run
        if elapsed < sleep:
            log.debug(f"[pwngpu] Cooldown: {int(sleep - elapsed)}s left.")
            return

        # Try to acquire without blocking — if _run() is already going
        # (e.g. triggered by on_handshake), just skip this tick.
        if self._run_lock.locked():
            log.debug("[pwngpu] Poller: sync already running, skipping tick.")
            return

        log.info("[pwngpu] Poller triggering sync.")
        self._run_in_thread()

    def _run_in_thread(self):
        """Spawn _run() in a background thread so callers never block."""
        t = Thread(target=self._run, daemon=True, name='pwngpu-sync')
        t.start()

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
    #  Hooks — never block, always dispatch to background thread          #
    # ------------------------------------------------------------------ #

    def _update_hs_dir(self, agent):
        try:
            d = agent.config()['bettercap']['handshakes']
            if d and d != self._handshake_dir:
                log.info(f"[pwngpu] Handshake dir updated: {d}")
                self._handshake_dir = d
        except Exception:
            pass

    def on_handshake(self, agent, filename, access_point, client_station):
        """Fires on main thread — dispatch immediately, never block."""
        self._update_hs_dir(agent)
        if not self._usb_connected():
            return
        if self._run_lock.locked():
            log.debug("[pwngpu] on_handshake: sync running, skipping.")
            return
        log.info(f"[pwngpu] New handshake: {filename} — queuing immediate sync.")
        self.last_run = 0   # force cooldown bypass
        self._run_in_thread()

    def on_internet_available(self, agent):
        self._update_hs_dir(agent)
        self._maybe_run('on_internet_available')

    def on_epoch(self, agent, epoch, epoch_data):
        self._update_hs_dir(agent)
        self._maybe_run(f'on_epoch({epoch})')

    def _maybe_run(self, source='hook'):
        if not self._usb_connected():
            return
        if self._run_lock.locked():
            return
        sleep   = self.options.get('sleep', 1800)
        elapsed = time.time() - self.last_run
        if elapsed < sleep:
            log.debug(f"[pwngpu] {source}: cooldown {int(sleep - elapsed)}s left.")
            return
        log.info(f"[pwngpu] {source}: queuing sync.")
        self._run_in_thread()

    # ------------------------------------------------------------------ #
    #  USB detection                                                       #
    # ------------------------------------------------------------------ #

    def _usb_connected(self):
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', self.USB_IFACE],
                capture_output=True, text=True, timeout=3
            )
            up = (
                result.returncode == 0
                and f'inet {self.USB_OWN_IP}' in result.stdout
            )
            if not up:
                if self._status != 'no_usb':
                    log.info("[pwngpu] USB down.")
                self._set_status('no_usb', log_it=False)
                return False
            if self._status in ('no_usb', 'waiting'):
                log.info(f"[pwngpu] USB up: {self.USB_OWN_IP} -> {self.USB_GATEWAY}")
            return True
        except Exception as e:
            log.debug(f"[pwngpu] USB check error: {e}")
            self._set_status('no_usb', log_it=False)
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
            log.info(f"[pwngpu] Loaded {len(self.sent)} previously sent entries.")
        except Exception as e:
            log.warning(f"[pwngpu] Could not load status: {e}")
            self.sent = set()

    def _save_status(self):
        try:
            with open(self.STATUS_PATH, 'w') as f:
                json.dump({'sent': list(self.sent)}, f)
        except Exception as e:
            log.warning(f"[pwngpu] Could not save status: {e}")

    # ------------------------------------------------------------------ #
    #  Core sync — always runs in its own thread via _run_in_thread()     #
    # ------------------------------------------------------------------ #

    def _run(self):
        if not self._run_lock.acquire(blocking=False):
            log.debug("[pwngpu] _run: already locked, bailing.")
            return
        try:
            self._do_sync()
        finally:
            self.last_run = time.time()
            self._run_lock.release()

    def _do_sync(self):
        server_url    = self._get_server_url()
        api_key       = self.options.get('api_key', '')
        handshake_dir = self._handshake_dir
        whitelist     = self.options.get('whitelist', [])

        log.info(f"[pwngpu] Sync start — dir={handshake_dir} server={server_url}")

        # 1. Ping server — distinguish auth failure from unreachable
        self._set_status('connecting')
        ok, reason = self._ping_server(server_url, api_key)
        if not ok:
            log.warning(f"[pwngpu] Server not available: {reason}")
            if reason == 'auth':
                self._set_status('error', 'bad key')
            else:
                self._set_status('offline')
            return
        log.info("[pwngpu] Server OK.")

        # 2. Scan for unsent pcaps
        self._set_status('scanning')
        try:
            all_files = os.listdir(handshake_dir)
        except Exception as e:
            log.error(f"[pwngpu] Cannot read {handshake_dir}: {e}")
            self._set_status('error', 'dir')
            return

        pcaps = [
            f for f in all_files
            if f.endswith(self.CAPTURE_EXTENSIONS)
            and f not in self.sent
            and not any(w in f for w in whitelist)
        ]
        log.info(
            f"[pwngpu] {len(pcaps)} unsent pcap(s) "
            f"({len(all_files)} files in dir, {len(self.sent)} already sent)."
        )

        if not pcaps:
            self._fetch_and_save_results(server_url, api_key)
            return

        # 3. Convert and upload — log per-file but don't spam status changes
        total_new = 0
        for i, pcap_file in enumerate(pcaps, 1):
            pcap_path = os.path.join(handshake_dir, pcap_file)
            hc_path   = os.path.splitext(pcap_path)[0] + '.tmp.hc22000'
            short     = pcap_file[:12]

            log.info(f"[pwngpu] [{i}/{len(pcaps)}] Converting: {pcap_file}")
            self._set_status('uploading', f"{i}/{len(pcaps)}", log_it=False)
            hashes = self._convert(pcap_path, hc_path)

            if hashes is None:
                log.info(f"[pwngpu] Conversion failed for {pcap_file}, will retry next sync.")
                continue   # NOT marked sent — will be retried

            if not hashes:
                log.info(f"[pwngpu] No hashes in {pcap_file}, marking sent.")
                self.sent.add(pcap_file)
                continue

            log.info(f"[pwngpu] [{i}/{len(pcaps)}] Uploading {pcap_file} ({len(hashes)} hashes)")
            self._set_status('cracking', short, log_it=False)
            success, cracked_count = self._send(server_url, api_key, hc_path, pcap_file)

            if success:
                self.sent.add(pcap_file)
                total_new += cracked_count
                log.info(f"[pwngpu] {pcap_file} queued. Server immediate cracked: {cracked_count}")

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
        log.info("[pwngpu] Sync complete.")

    # ------------------------------------------------------------------ #
    #  Network helpers                                                     #
    # ------------------------------------------------------------------ #

    def _ping_server(self, server_url, api_key):
        """Returns (ok: bool, reason: str). reason is 'auth', 'error', or ''."""
        try:
            r = requests.get(
                f"{server_url}/health",
                headers={'X-API-Key': api_key},
                timeout=5
            )
            if r.status_code == 200:
                return True, ''
            if r.status_code == 401:
                return False, 'auth'
            return False, f'http_{r.status_code}'
        except requests.exceptions.ConnectionError:
            return False, 'unreachable'
        except requests.exceptions.Timeout:
            return False, 'timeout'
        except Exception as e:
            log.debug(f"[pwngpu] Health check exception: {e}")
            return False, 'error'

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
            if response.status_code == 401:
                log.error("[pwngpu] Send rejected: bad API key.")
                self._set_status('error', 'bad key')
                return False, 0
            response.raise_for_status()
            data = response.json()
            if data.get('cracked'):
                self._save_results(data['cracked'])
            return True, data.get('total', 0)
        except requests.exceptions.ConnectionError:
            log.warning("[pwngpu] Connection error during send.")
            self._set_status('offline')
        except requests.exceptions.Timeout:
            log.warning("[pwngpu] Timeout during send.")
            self._set_status('error', 'timeout')
        except Exception as e:
            log.error(f"[pwngpu] Send error: {e}")
            self._set_status('error', 'send')
        return False, 0

    def _convert(self, pcap_path, hc_path):
        try:
            result = subprocess.run(
                ['hcxpcapngtool', '-o', hc_path, pcap_path],
                capture_output=True, text=True, timeout=60
            )
            log.debug(f"[pwngpu] hcxpcapngtool rc={result.returncode} {result.stdout.strip()}")
            if os.path.exists(hc_path) and os.path.getsize(hc_path) > 0:
                with open(hc_path, 'r') as f:
                    return [l.strip() for l in f if l.strip()]
            return []  # ran fine, genuinely no extractable hash
        except FileNotFoundError:
            log.error("[pwngpu] hcxpcapngtool not found — install it first.")
            self._set_status('error', 'no hcxtool')
        except subprocess.TimeoutExpired:
            log.error(f"[pwngpu] hcxpcapngtool timed out on {pcap_path}")
            self._set_status('error', 'convert timeout')
        except Exception as e:
            log.error(f"[pwngpu] Conversion error: {e}")
            self._set_status('error', 'convert')
        return None  # signals "error, retry later" vs [] = "tried, nothing there"

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
            log.info(f"[pwngpu] {count} total cracked result(s) on server.")
        except Exception as e:
            log.warning(f"[pwngpu] Could not fetch results: {e}")

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
            log.info(f"[pwngpu] Saved {len(new_lines)} new password(s).")