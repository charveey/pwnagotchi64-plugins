import os
import logging
import requests
import time
import subprocess
from threading import Lock
from pwnagotchi.utils import StatusFile
import pwnagotchi.plugins as plugins
from json.decoder import JSONDecodeError


class ohcapi(plugins.Plugin):
    __author__ = 'charveey'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Uploads WPA/WPA2 handshakes to OnlineHashCrack.com using the new API (V2), no dashboard.'

    def __init__(self):
        self.ready = False
        self.lock = Lock()
        self.last_run = 0

        try:
            self.report = StatusFile('/root/handshakes/.ohc_uploads', data_format='json')
        except JSONDecodeError:
            os.remove('/root/handshakes/.ohc_uploads')
            self.report = StatusFile('/root/handshakes/.ohc_uploads', data_format='json')

    # called when the plugin is loaded
    def on_loaded(self):
        required_fields = ['api_key']
        missing = [f for f in required_fields if f not in self.options or not self.options[f]]
        if missing:
            logging.error(f"[OHC] Missing required config fields: {missing}")
            return

        if 'receive_email' not in self.options:
            self.options['receive_email'] = 'yes'

        if 'sleep' not in self.options:
            self.options['sleep'] = 60 * 60  # 1 hour default

        self.ready = True
        logging.info("[OHC] Plugin loaded and ready.")

    # called when http://<host>:<port>/plugins/ohcapi/ is called
    def on_webhook(self, path, request):
        from flask import make_response, redirect
        return make_response(redirect("https://www.onlinehashcrack.com", code=302))

    # called when there's internet connectivity
    def on_internet_available(self, agent):
        if not self.ready or self.lock.locked():
            return

        current_time = time.time()
        if current_time - self.last_run < self.options['sleep']:
            remaining = self.options['sleep'] - (current_time - self.last_run)
            logging.debug(f"[OHC] Waiting {remaining:.0f}s before next run.")
            return

        logging.info("[OHC] Internet available, starting upload tasks.")
        self._run_tasks(agent)
        self.last_run = time.time()

    # called when a new handshake is captured — upload immediately if possible
    def on_handshake(self, agent, filename, access_point, client_station):
        if not self.ready or self.lock.locked():
            return
        logging.info(f"[OHC] New handshake captured: {filename}, queuing upload.")
        self._run_tasks(agent)
        self.last_run = time.time()

    # called when an epoch is over — used to retry uploads periodically
    def on_epoch(self, agent, epoch, epoch_data):
        if not self.ready or self.lock.locked():
            return

        current_time = time.time()
        if current_time - self.last_run < self.options['sleep']:
            return

        logging.debug("[OHC] Epoch trigger: checking for pending uploads.")
        self._run_tasks(agent)
        self.last_run = time.time()

    # called before the plugin is unloaded
    def on_unload(self, ui):
        logging.info("[OHC] Plugin unloaded.")

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _run_tasks(self, agent):
        with self.lock:
            try:
                display = agent.view()
                config  = agent.config()
            except Exception as e:
                logging.error(f"[OHC] Failed to get agent state: {e}")
                return
            reported           = self.report.data_field_or('reported', default=[])
            processed_stations = self.report.data_field_or('processed_stations', default=[])
            handshake_dir      = config['bettercap']['handshakes']

            # Find .pcap files without an existing .22000 counterpart
            try:
                all_pcaps = [
                    os.path.join(handshake_dir, f)
                    for f in os.listdir(handshake_dir)
                    if f.endswith('.pcap')
                ]
            except FileNotFoundError:
                logging.error(f"[OHC] Handshake directory not found: {handshake_dir}")
                return

            handshake_new = set(all_pcaps) - set(reported)

            if not handshake_new:
                logging.debug("[OHC] No new PCAP files to process.")
                return

            logging.info(f"[OHC] Processing {len(handshake_new)} new PCAP handshake(s).")

            all_hashes         = []
            successfully_extracted = []
            essid_bssid_map    = {}

            for pcap_path in handshake_new:
                hashes = self._extract_hashes_from_handshake(pcap_path)
                if not hashes:
                    logging.debug(f"[OHC] No hashes extracted from {pcap_path}, skipping.")
                    reported.append(pcap_path)
                    continue

                essid, bssid = self._extract_essid_bssid_from_hash(hashes[0])
                station_key = f"{essid}|{bssid}"
                if station_key in processed_stations:
                    logging.debug(f"[OHC] Station {station_key} already processed, skipping.")
                    reported.append(pcap_path)
                    continue

                all_hashes.extend(hashes)
                successfully_extracted.append(pcap_path)
                essid_bssid_map[pcap_path] = (essid, bssid)

            if not all_hashes:
                logging.debug("[OHC] No hashes extracted from new PCAPs.")
                self.report.update(
                    data={
                        'reported': reported,
                        'processed_stations': processed_stations
                    }
                )
                display.on_normal()
                return

            # Upload in batches of 50
            batches = [all_hashes[i:i+50] for i in range(0, len(all_hashes), 50)]
            upload_success = True
            for batch_idx, batch in enumerate(batches):
                display.on_uploading(f"onlinehashcrack.com ({min((batch_idx+1)*50, len(all_hashes))}/{len(all_hashes)})")
                if not self._add_tasks(batch):
                    upload_success = False
                    break

            if upload_success:
                for pcap_path in successfully_extracted:
                    reported.append(pcap_path)
                    essid, bssid = essid_bssid_map[pcap_path]
                    station_key = f"{essid}|{bssid}"
                    processed_stations.append(station_key)
                self.report.update(data={'reported': reported, 'processed_stations': processed_stations})
                logging.info("[OHC] Successfully uploaded all new handshakes.")
            else:
                logging.warning(
                    "[OHC] Upload failed. Handshakes will be retried later."
                )

            display.on_normal()

    def _add_tasks(self, hashes, timeout=30):
        clean_hashes = [h.strip() for h in hashes if h.strip()]
        if not clean_hashes:
            return True

        payload = {
            'api_key':       self.options['api_key'],
            'agree_terms':   'yes',
            'action':        'add_tasks',
            'algo_mode':     22000,
            'hashes':        clean_hashes,
            'receive_email': self.options['receive_email'],
        }

        for attempt in range(3):
            try:
                result = requests.post(
                    'https://api.onlinehashcrack.com/v2',
                    json=payload,
                    timeout=timeout
                )
        
                result.raise_for_status()
                data = result.json()

                logging.info(f"[OHC] Upload response: {data}")
                
                if data.get("success") is False:
                    logging.error(
                        f"[OHC] API rejected upload: {data}"
                    )
                    return False
                return True
            except (ValueError, JSONDecodeError) as e:
                logging.error(f"[OHC] Invalid JSON response: {e}")
                return False
            except requests.exceptions.RequestException as e:
                logging.warning(
                    f"[OHC] Upload attempt "
                    f"{attempt + 1}/3 failed: {e}"
                )
        
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
        
        logging.error("[OHC] Upload failed after 3 attempts.")
        return False

    def _extract_hashes_from_handshake(self, pcap_path):
        hccapx_path = pcap_path.replace('.pcap', '.22000')
        try:                                               
            subprocess.run(
                ['/usr/bin/hcxpcapngtool', '-o', hccapx_path, pcap_path],
                capture_output=True,
                timeout=60
            )
        except FileNotFoundError:
            logging.error("[OHC] hcxpcapngtool not found. Is it installed?")
            return []
        except subprocess.TimeoutExpired:
            logging.warning(f"[OHC] hcxpcapngtool timed out on {pcap_path}")
            return []
        except Exception as e:
            logging.error(f"[OHC] Unexpected error running hcxpcapngtool: {e}")
            return []
    
        if os.path.exists(hccapx_path) and os.path.getsize(hccapx_path) > 0:
            logging.debug(f"[OHC] Extracted hashes from {pcap_path}")
            with open(hccapx_path, 'r') as f:
                return f.readlines()
        else:
            logging.debug(f"[OHC] No hashes from {pcap_path}")
            if os.path.exists(hccapx_path):
                os.remove(hccapx_path)
            return []

    def _extract_essid_bssid_from_hash(self, hash_line):
        parts = hash_line.strip().split('*')
        essid = 'unknown_ESSID'
        bssid = '00:00:00:00:00:00'

        if len(parts) > 5:
            try:
                essid = bytes.fromhex(parts[5]).decode('utf-8', errors='replace')
            except Exception:
                essid = 'unknown_ESSID'

        if len(parts) > 3:
            apmac = parts[3]
            if len(apmac) == 12:
                bssid = ':'.join(apmac[i:i+2] for i in range(0, 12, 2))

        if essid == 'unknown_ESSID' or bssid == '00:00:00:00:00:00':
            logging.debug(f"[OHC] Failed to extract ESSID/BSSID from hash -> {hash_line}")

        return essid, bssid
