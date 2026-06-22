import logging, os, pwnagotchi, requests, socket, traceback, shutil, toml, time
from pwnagotchi import plugins
from PIL import ImageOps, Image

class InetIcon(pwnagotchi.ui.components.Widget):
    def __init__(self, value, xy=(225, 101), color=0, invert=False):
        super().__init__(xy, color)
        self.image_path = value
        self.invert = invert
        img = Image.open(self.image_path).convert('L')
        self.image = ImageOps.invert(img) if self.invert else img

    def draw(self, canvas, drawer):
        if self.image:
            try:
                canvas.paste(self.image, self.xy)
            except Exception as e:
                logging.error(f"Error drawing image: {e}")
                logging.error(traceback.format_exc())

class InternetConectionPlugin(plugins.Plugin):
    __author__ = 'neonlightning & charveey'
    __version__ = '1.4.0'
    __license__ = 'GPL3'
    __description__ = 'A plugin that displays the Internet connection status on the pwnagotchi display.'
    __help__ = """
    A plugin that displays the Internet connection status on the pwnagotchi display.
    """
    __defaults__ = {
        'x': 0,
        'y': 218,
    }

    def __init__(self):
        super().__init__()
        self.current_state = False
        self._last_check = 0
        self._check_interval = 30
        self.icon_on_path  = os.path.join(os.path.dirname(os.path.realpath(__file__)), "internet-conection-on.png")
        self.icon_off_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "internet-conection-off.png")
        self.icon_path     = os.path.join(os.path.dirname(os.path.realpath(__file__)), "internet-conection.png")

    def on_ready(self, agent):
        if not os.path.exists(self.icon_on_path):
            logging.info("[Internet Conection] on icon path not found")
            self.download_icon("https://raw.githubusercontent.com/charveey/pwnagotchi64-plugins/main/internet-conection-on.png", self.icon_on_path)
        if not os.path.exists(self.icon_off_path):
            logging.info("[Internet Conection] off icon path not found")
            self.download_icon("https://raw.githubusercontent.com/charveey/pwnagotchi64-plugins/main/internet-conection-off.png", self.icon_off_path)
        try:
            shutil.copy(self.icon_off_path, self.icon_path)
            logging.info("[Internet Conection] setup icon.")
        except Exception as e:
            logging.error(f"[Internet Conection] Error copying file: {e}")

    def download_icon(self, url, save_path):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(save_path, 'wb') as file:
                file.write(response.content)
        except Exception as e:
            logging.error(f"[Internet Conection] Failed to download icon: {e}")

    def _is_internet_available(self):
        try:
            socket.create_connection(("www.google.com", 80), timeout=1)
            return True
        except OSError:
            return False

    def invert(self):
        try:
            config = toml.load("/etc/pwnagotchi/config.toml")
            return config.get('ui', {}).get('invert', False)
        except Exception as e:
            logging.warning(f"[Internet Conection] Could not read config: {e}")
            return False

    def on_loaded(self):
        x = self.options.get('x', self.__defaults__['x'])
        y = self.options.get('y', self.__defaults__['y'])
        logging.info(f"[Internet Conection] Plugin loaded. Icon position: ({x}, {y})")

        is_connected = self._is_internet_available()
        if is_connected != self.current_state:
            self.current_state = is_connected
            self._swap_icon(is_connected)

    def on_ui_setup(self, ui):
        self.invert_status = self.invert()
        x = int(self.options.get('x', self.__defaults__['x']))
        y = int(self.options.get('y', self.__defaults__['y']))
        try:
            ui.add_element('connection_status', InetIcon(
                xy=(x, y),
                value=self.icon_path,
                invert=self.invert_status
            ))
            logging.info(f"[Internet Conection] Icon placed at ({x}, {y})")
        except Exception as e:
            logging.info(f"[Internet Conection] Error loading {e}")

    def on_ui_update(self, ui):
        now = time.time()
        if now - self._last_check < self._check_interval:
            return
        self._last_check = now
        is_connected = self._is_internet_available()
        if is_connected != self.current_state:
            self.current_state = is_connected
            self._swap_icon(is_connected)

    def _swap_icon(self, is_connected):
        """Overwrite the active icon file with the on or off source."""
        source_path = self.icon_on_path if is_connected else self.icon_off_path
        try:
            shutil.copy(source_path, self.icon_path)
        except Exception as e:
            logging.error(f"[Internet Conection] Error updating icon: {e}")

    def on_unload(self, ui):
        with ui._lock:
            try:
                ui.remove_element('connection_status')
            except KeyError:
                pass
        logging.info("[Internet Conection] Plugin unloaded.")
