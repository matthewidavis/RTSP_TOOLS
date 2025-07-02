import sys
import socket
import threading
import time
import av
import cv2
import numpy as np

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QHBoxLayout, QLabel, QLineEdit, QCheckBox
)
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtCore import Qt

# Constants
IFRAME_COMMAND = bytes.fromhex('81 0b 01 04 0d 00 ff')
IFRAME_PORT = 1259
IFRAME_INTERVAL = 0.033  # 33ms
MAX_IFRAME_DURATION = 2

class RTSPSwitcher(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RTSP Seamless Switcher")
        self.setGeometry(100, 100, 1280, 720)

        self.rtsp_uris = [
            "rtsp://192.168.12.8:554/1",
            "rtsp://192.168.12.9:554/1"
        ]
        self.current_index = 0
        self.seamless_mode = True
        self.player_thread = None
        self.stop_event = threading.Event()

        self.build_ui()

    def build_ui(self):
        layout = QVBoxLayout()

        self.uri_fields = []
        for uri in self.rtsp_uris:
            uri_input = QLineEdit(uri)
            self.uri_fields.append(uri_input)
            layout.addWidget(uri_input)

        control_layout = QHBoxLayout()
        self.seamless_checkbox = QCheckBox("Enable Seamless Switching")
        self.seamless_checkbox.setChecked(True)
        self.seamless_checkbox.stateChanged.connect(
            lambda: setattr(self, 'seamless_mode', self.seamless_checkbox.isChecked())
        )
        control_layout.addWidget(self.seamless_checkbox)

        switch_button = QPushButton("Switch Camera")
        switch_button.clicked.connect(self.switch_camera)
        control_layout.addWidget(switch_button)
        layout.addLayout(control_layout)

        self.video_label = QLabel("Live Preview")
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setStyleSheet("background-color: black;")
        layout.addWidget(self.video_label, stretch=1)

        self.setLayout(layout)

    def log(self, msg):
        print(msg)

    def switch_camera(self):
        if self.player_thread and self.player_thread.is_alive():
            self.stop_event.set()
            self.player_thread.join()

        self.stop_event.clear()
        self.current_index = (self.current_index + 1) % len(self.uri_fields)
        uri = self.uri_fields[self.current_index].text()
        seamless = self.seamless_mode
        self.player_thread = threading.Thread(
            target=self.start_stream, args=(uri, seamless), daemon=True
        )
        self.player_thread.start()

    def update_preview(self, img):
        rgb_image = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb_image.shape
        bytes_per_line = ch * w
        qt_img = QImage(rgb_image.data, w, h, bytes_per_line, QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(qt_img)
        self.video_label.setPixmap(pixmap.scaled(
            self.video_label.width(),
            self.video_label.height(),
            Qt.KeepAspectRatio
        ))

    def start_stream(self, uri, seamless):
        start_time = time.time()
        self.log(f"\n🔁 SWITCHING to {uri} (Seamless={seamless})")
        self.log(f"🕒 Started at {start_time:.3f}")

        ip = uri.split("//")[1].split("/")[0].split(":")[0]
        iframe_triggered = threading.Event()

        def send_iframe_triggers():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            count = 0
            while not iframe_triggered.is_set():
                sock.sendto(IFRAME_COMMAND, (ip, IFRAME_PORT))
                count += 1
                self.log(f"📡 Sent I-frame trigger #{count} to {ip}:{IFRAME_PORT}")
                time.sleep(IFRAME_INTERVAL)

        if seamless:
            trigger_thread = threading.Thread(target=send_iframe_triggers, daemon=True)
            trigger_thread.start()

        container = None
        try:
            container = av.open(uri, options={'rtsp_transport': 'tcp'})
            stream = container.streams.video[0]
            stream.thread_type = 'AUTO'

            self.log(f"📥 Beginning decode init at {time.time():.3f}")

            for frame in container.decode(stream):
                if self.stop_event.is_set():
                    break
                img = frame.to_ndarray(format='bgr24')
                self.update_preview(img)

                if frame.key_frame:
                    iframe_triggered.set()
                    self.log("⏱️ I-frame detected. Starting display.")
                    break

            if seamless:
                iframe_triggered.set()
                self.log("✅ Stopped I-frame trigger thread.")
                self.log(f"✅ I-frame detected after {time.time() - start_time:.3f} seconds")

            for frame in container.decode(stream):
                if self.stop_event.is_set():
                    break
                img = frame.to_ndarray(format='bgr24')
                self.update_preview(img)

        except Exception as e:
            self.log(f"❌ Error: {e}")
        finally:
            if container:
                container.close()
            self.stop_event.set()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RTSPSwitcher()
    window.show()
    sys.exit(app.exec_())
