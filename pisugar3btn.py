import logging
import time
import subprocess
import smbus
import pwnagotchi.plugins as plugins


class PiSugar3Button(plugins.Plugin):
    __author__ = 'charveey'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = (
        'Handles PiSugar 3 physical button with single, double, and long press support. '
        'Each press type can trigger a configurable shell script.'
    )

    I2C_ADDRESS = 0x57
    BTN_REGISTER = 0x08
    BTN_BIT      = 0x40

    def __init__(self):
        self._bus = None

        # Scripts
        self._script_single = None
        self._script_double = None
        self._script_long   = None

        # Thresholds
        self._long_press_threshold = 1.5
        self._double_press_window  = 0.4

        # State
        self._last_state          = False
        self._pressed_at          = None
        self._pending_single      = False
        self._pending_single_time = None

    def on_loaded(self):
        try:
            self._bus = smbus.SMBus(1)
        except Exception as e:
            logging.error(f"[pisugar3btn] Could not open I2C bus: {e}")
            return

        self._script_single        = self.options.get('on_single', None)
        self._script_double        = self.options.get('on_double', None)
        self._script_long          = self.options.get('on_long',   None)
        self._long_press_threshold = self.options.get('long_press_threshold', 1.5)
        self._double_press_window  = self.options.get('double_press_window',  0.4)

        logging.info("[pisugar3btn] Plugin loaded.")
        logging.info(f"[pisugar3btn] single='{self._script_single}' "
                     f"double='{self._script_double}' "
                     f"long='{self._script_long}'")
        logging.info(f"[pisugar3btn] long_press_threshold={self._long_press_threshold}s "
                     f"double_press_window={self._double_press_window}s")

    def on_ui_update(self, ui):
        if self._bus is None:
            return
        self._poll_button()

    def _poll_button(self):
        try:
            btn_reg = self._bus.read_byte_data(self.I2C_ADDRESS, self.BTN_REGISTER)
            pressed = (btn_reg & self.BTN_BIT) != 0
            now = time.time()

            # Rising edge — button down
            if pressed and not self._last_state:
                self._pressed_at = now

            # Falling edge — button released
            if not pressed and self._last_state:
                hold = now - (self._pressed_at or now)

                if hold >= self._long_press_threshold:
                    logging.info("[pisugar3btn] Long press detected.")
                    self._run_script(self._script_long, "long")
                    self._clear_pending()

                elif self._pending_single:
                    logging.info("[pisugar3btn] Double press detected.")
                    self._run_script(self._script_double, "double")
                    self._clear_pending()

                else:
                    # Tentative single — wait for double press window to expire
                    self._pending_single      = True
                    self._pending_single_time = now

                # Acknowledge button press in hardware
                self._bus.write_byte_data(
                    self.I2C_ADDRESS,
                    self.BTN_REGISTER,
                    btn_reg & ~self.BTN_BIT
                )

            # Single press window expired — confirm it as single
            if self._pending_single and self._pending_single_time:
                if now - self._pending_single_time > self._double_press_window:
                    logging.info("[pisugar3btn] Single press detected.")
                    self._run_script(self._script_single, "single")
                    self._clear_pending()

            self._last_state = pressed

        except Exception as e:
            logging.debug(f"[pisugar3btn] Button poll error: {e}")

    def _clear_pending(self):
        self._pending_single      = False
        self._pending_single_time = None
        self._pressed_at          = None

    def _run_script(self, script, label):
        if not script:
            logging.debug(f"[pisugar3btn] No script configured for '{label}' press, skipping.")
            return
        try:
            subprocess.Popen(
                script,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info(f"[pisugar3btn] Ran '{label}' script: {script}")
        except Exception as e:
            logging.error(f"[pisugar3btn] Failed to run '{label}' script: {e}")

    def on_unload(self, ui):
        logging.info("[pisugar3btn] Plugin unloaded.")