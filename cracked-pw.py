import pwnagotchi.plugins as plugins
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts
import logging
import csv
import os
import io

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False
    logging.warning("[mycracked-pw] qrcode library not installed. QR codes will be skipped. Run: sudo apt install python3-qrcode or pip3 install qrcode[pil] to enable QR code generation.")


class MyCrackedPasswords(plugins.Plugin):
    __author__ = '@silentree12th and charveey'
    __version__ = '7.0.0'
    __license__ = 'GPL3'
    __description__ = (
        'Aggregates cracked passwords from wpa-sec, pwncrack, and onlinehashcrack. '
        'Generates WiFi QR codes, a wordlist, and displays the latest crack on screen.'
    )

    WORDLIST_DIR  = '/home/pwn/wordlists/'
    WORDLIST_PATH = '/home/pwn/wordlists/mycracked.txt'
    QRCODE_DIR    = '/home/pwn/qrcodes/'

    POTFILES = {
        'wpa-sec':         '/root/handshakes/wpa-sec.cracked.potfile',
        'pwncrack':        '/root/handshakes/cracked.pwncrack.potfile',
        'onlinehashcrack': '/root/handshakes/onlinehashcrack.cracked',
    }

    def on_loaded(self):
        logging.info("[mycracked-pw] Plugin loaded.")
        os.makedirs(self.WORDLIST_DIR, exist_ok=True)
        os.makedirs(self.QRCODE_DIR, exist_ok=True)
        self._update_all()

    # ------------------------------------------------------------------ #
    #  UI                                                                  #
    # ------------------------------------------------------------------ #

    def on_ui_setup(self, ui):
        if ui.is_waveshare_v2() or ui.is_waveshare_v3() or ui.is_waveshare_v4():
            h_pos = (0, 95)
            v_pos = (180, 61)
        elif ui.is_waveshare_v1():
            h_pos = (0, 95)
            v_pos = (170, 61)
        elif ui.is_waveshare144lcd():
            h_pos = (0, 92)
            v_pos = (78, 67)
        elif ui.is_inky():
            h_pos = (0, 83)
            v_pos = (165, 54)
        elif ui.is_waveshare27inch():
            h_pos = (0, 153)
            v_pos = (216, 122)
        else:
            h_pos = (0, 91)
            v_pos = (180, 61)

        pos = v_pos if self.options.get('orientation') == 'vertical' else h_pos

        ui.add_element('mycracked-pw', LabeledValue(
            color=BLACK,
            label='',
            value='',
            position=pos,
            label_font=fonts.Bold,
            text_font=fonts.Small
        ))

    def on_unload(self, ui):
        with ui._lock:
            ui.remove_element('mycracked-pw')

    def on_ui_update(self, ui):
        """
        Pick the most recently cracked password across all potfiles and show it.
        """
        best_entry = None
        best_mtime = 0

        for source, path in self.POTFILES.items():
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                continue
            try:
                mtime = os.path.getmtime(path)
                if mtime <= best_mtime:
                    continue

                last_line = os.popen(f"tail -n 1 {path}").read().strip()
                if not last_line:
                    continue

                if source in ('wpa-sec', 'pwncrack'):
                    parts = last_line.split(':')
                    if len(parts) >= 4:
                        ssid     = parts[2] or 'Unknown'
                        password = parts[3] or '?'
                        best_entry = f"{ssid} - {password}"
                        best_mtime = mtime

                elif source == 'onlinehashcrack':
                    parts = last_line.split(',')
                    if len(parts) >= 3:
                        password = parts[2].strip()
                        task     = parts[0].strip()
                        ssid     = task[:-18].rstrip('_').strip() if len(task) > 17 else task
                        best_entry = f"OHC: {ssid} - {password}"
                        best_mtime = mtime

            except Exception as e:
                logging.warning(f"[mycracked-pw] Could not read {path} for display: {e}")

        ui.set('mycracked-pw', best_entry if best_entry else 'No cracked passwords yet')

    # ------------------------------------------------------------------ #
    #  Handshake hook                                                      #
    # ------------------------------------------------------------------ #

    def on_handshake(self, agent, filename, access_point, client_station):
        self._update_all()

    # ------------------------------------------------------------------ #
    #  Potfile readers                                                     #
    # ------------------------------------------------------------------ #

    def _read_wpasec_potfile(self, path):
        """
        wpa-sec / pwncrack format: BSSID:BSSID2:ESSID:password
        """
        results = []
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return results
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 4 and parts[3]:
                        results.append((parts[0], parts[2], parts[3]))
        except Exception as e:
            logging.error(f"[mycracked-pw] Error reading {path}: {e}")
        return results

    def _read_ohc_potfile(self, path):
        """
        OnlineHashCrack CSV format: task,hash,password
        task = ESSID + '_' + BSSID (last 17 chars are the MAC)
        """
        results = []
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return results
        try:
            with open(path, 'r', encoding='utf-8') as h:
                for row in csv.DictReader(h):
                    try:
                        password = row.get('password', '').strip()
                        task     = row.get('task', '').strip()
                        if not password or not task:
                            continue
                        if len(task) > 17:
                            bssid = task[-17:]
                            ssid  = task[:-18].rstrip('_').rstrip('-').strip()
                        else:
                            bssid = task
                            ssid  = 'unknown'
                        results.append((bssid, ssid, password))
                    except Exception as e:
                        logging.error(f"[mycracked-pw] Error parsing OHC row: {e}")
        except Exception as e:
            logging.error(f"[mycracked-pw] Error reading {path}: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Main update logic                                                   #
    # ------------------------------------------------------------------ #

    def _update_all(self):
        entries = []
        entries += self._read_wpasec_potfile(self.POTFILES['wpa-sec'])
        entries += self._read_wpasec_potfile(self.POTFILES['pwncrack'])
        entries += self._read_ohc_potfile(self.POTFILES['onlinehashcrack'])

        if not entries:
            logging.info("[mycracked-pw] No cracked passwords found yet.")
            return

        logging.info(f"[mycracked-pw] Total entries collected: {len(entries)}")

        # Deduplicate by (ssid, password)
        seen = set()
        unique_entries = []
        for bssid, ssid, password in entries:
            key = (ssid.lower(), password)
            if key not in seen:
                seen.add(key)
                unique_entries.append((bssid, ssid, password))

        self._generate_qrcodes(unique_entries)
        self._update_wordlist([pw for _, _, pw in unique_entries])

    def _generate_qrcodes(self, entries):
        if not HAS_QRCODE:
            return
        for bssid, ssid, password in entries:
            safe_name = (ssid + '-' + password).replace('/', '_').replace('\\', '_')
            filepath  = os.path.join(self.QRCODE_DIR, safe_name + '.txt')
            if os.path.exists(filepath):
                continue
            try:
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(f'WIFI:S:{ssid};T:WPA;P:{password};;')
                qr.make(fit=True)
                with open(filepath, 'w+', encoding='utf-8') as f:
                    qr.print_ascii(out=f)
                logging.info(f"[mycracked-pw] QR code saved: {filepath}")
            except Exception as e:
                logging.error(f"[mycracked-pw] Failed to generate QR code for {ssid}: {e}")

    def _update_wordlist(self, passwords):
        try:
            new_lines = sorted(set(p for p in passwords if p))
            with open(self.WORDLIST_PATH, 'w', encoding='utf-8') as g:
                for pw in new_lines:
                    g.write(pw + '\n')
            logging.info(f"[mycracked-pw] Wordlist updated with {len(new_lines)} unique passwords.")
        except Exception as e:
            logging.error(f"[mycracked-pw] Failed to update wordlist: {e}")