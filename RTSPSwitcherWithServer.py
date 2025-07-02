import sys
import socket
import threading
import time
import av
import av.error
import cv2
import numpy as np
import asyncio
import random
import re
from queue import Queue as ThreadSafeQueue, Full

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QHBoxLayout, QLabel, QLineEdit, QCheckBox
)
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtCore import Qt, pyqtSignal, QObject

# ==== CONFIG & CONSTANTS ====
IFRAME_COMMAND = bytes.fromhex('81 0b 01 04 0d 00 ff')
IFRAME_PORT = 1259
IFRAME_INTERVAL = 0.033
RTSP_SERVER_PORT = 8554

# RTP/RTSP constants
VIDEO_PT = 96
VIDEO_CLOCK = 90_000
MAX_PAYLOAD = 1400
QUEUE_SIZE = 120

# A global queue to pass video frames from the decoder thread to the server thread.
video_frame_queue = ThreadSafeQueue(maxsize=QUEUE_SIZE)

def log(*args):
    """A simple print logger with a prefix."""
    print("[Switcher]", *args)

# =================================================================================
#  RTSP SERVER CODE
# =================================================================================

class RTPPacketizer:
    def __init__(self, pt):
        self.pt, self.seq, self.ts, self.ssrc = pt, random.randint(0, 0xFFFF), 0, random.randint(0, 0xFFFFFFFF)

    def packetize(self, payload: bytes, marker: bool = True):
        hdr = bytearray(12)
        hdr[0], hdr[1] = 0x80, (0x80 if marker else 0) | (self.pt & 0x7F)
        hdr[2:4], hdr[4:8], hdr[8:12] = self.seq.to_bytes(2, 'big'), self.ts.to_bytes(4, 'big'), self.ssrc.to_bytes(4, 'big')
        self.seq = (self.seq + 1) & 0xFFFF
        return bytes(hdr) + payload

    def fragment_h264(self, nalu: bytes):
        if not nalu:
            return

        if len(nalu) <= MAX_PAYLOAD:
            yield self.packetize(nalu)
            return
        
        hdr_byte, payload = nalu[0], nalu[1:]
        fu_indicator = (hdr_byte & 0xE0) | 28
        fu_header_start = (1 << 7) | (hdr_byte & 0x1F)
        fu_header_end = (1 << 6) | (hdr_byte & 0x1F)
        fu_header_middle = hdr_byte & 0x1F

        payload_data = payload
        offset = 0
        is_first = True

        while offset < len(payload_data):
            chunk = payload_data[offset:offset + MAX_PAYLOAD - 2]
            is_last = (offset + len(chunk) >= len(payload_data))

            if is_first:
                fu_header = fu_header_start
                is_first = False
            elif is_last:
                fu_header = fu_header_end
            else:
                fu_header = fu_header_middle

            yield self.packetize(bytes([fu_indicator, fu_header]) + chunk, is_last)
            offset += len(chunk)

class RTSPProtocol(asyncio.Protocol):
    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport = transport
        self.buf = b''
        self.client_ip = transport.get_extra_info('peername')[0]
        self.state = 'INIT'
        self.session_id = None
        self.streaming_task = None
        self.track_setups = {}
        log(f"[RTSP] Connected: {self.client_ip}")

    def connection_lost(self, exc):
        log(f"[RTSP] Disconnected: {self.client_ip}")
        self._cleanup()

    def _cleanup(self):
        if self.streaming_task and not self.streaming_task.done():
            self.streaming_task.cancel()
        for track in self.track_setups.values():
            if rtp_sock := track.get('rtp_sock'):
                rtp_sock.close()
        if self.transport and not self.transport.is_closing():
            self.transport.close()

    def data_received(self, data: bytes):
        self.buf += data
        while b'\r\n\r\n' in self.buf:
            req_data, self.buf = self.buf.split(b'\r\n\r\n', 1)
            lines = req_data.decode('utf-8', 'ignore').split('\r\n')
            if not lines or len(lines[0].split()) < 2: continue
            method, _ = lines[0].split()[:2]
            log(f"[RTSP] <- {method}")
            if handler := getattr(self, f'on_{method.lower()}', self.on_unsupported):
                handler(lines)
            else:
                return

    def _get_header(self, lines, key):
        key = key.lower()
        for line in lines:
            if line.lower().startswith(key): return line.split(':', 1)[1].strip()
        return None

    def on_unsupported(self, lines): self._send_response(501, self._get_header(lines, 'CSeq'))
    def on_options(self, lines): self._send_response(200, self._get_header(lines, 'CSeq'), {'Public': 'OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN'})

    def on_describe(self, lines):
        cseq = self._get_header(lines, 'CSeq')
        sdp_parts = [f"m=video 0 RTP/AVP {VIDEO_PT}",
                     f"a=rtpmap:{VIDEO_PT} H264/{VIDEO_CLOCK}",
                     f"a=fmtp:{VIDEO_PT} packetization-mode=1",
                     "a=control:track1"]
        
        ip = self.transport.get_extra_info('sockname')[0]
        sdp_base = (f"v=0\r\no=- {int(time.time())} 1 IN IP4 {ip}\r\n"
                    f"s=RTSP Switcher Output\r\nt=0 0\r\na=control:*\r\n")
        sdp_body = (sdp_base + "\r\n".join(sdp_parts) + "\r\n").encode()
        self._send_response(200, cseq, {'Content-Type': 'application/sdp'}, sdp_body)

    def on_setup(self, lines):
        cseq, transport_hdr = self._get_header(lines, 'CSeq'), self._get_header(lines, 'Transport')
        self.session_id = self.session_id or str(random.randint(100000, 999999))
        
        if m := re.search(r'client_port=(\d+)-(\d+)', transport_hdr):
            client_ports = tuple(map(int, m.groups()))
            rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp_sock.bind(('', 0))
            self.track_setups['1'] = {'rtp_sock': rtp_sock, 'client_ports': client_ports, 'packetizer': RTPPacketizer(VIDEO_PT)}
            
            server_rtp_port = rtp_sock.getsockname()[1]
            spec = f"RTP/AVP;unicast;client_port={client_ports[0]}-{client_ports[1]};server_port={server_rtp_port}"
            
            self.state = 'READY'
            self._send_response(200, cseq, {'Transport': spec, 'Session': self.session_id})
        else: self._send_response(461, cseq)

    def on_play(self, lines):
        cseq = self._get_header(lines, 'CSeq')
        if self.state != 'READY': return self._send_response(455, cseq)
        self.state = 'PLAYING'
        self.streaming_task = asyncio.create_task(self._stream_media())
        self._send_response(200, cseq, {'Session': self.session_id, 'RTP-Info': 'url=rtsp://.../track1;seq=0;rtptime=0'})

    def on_teardown(self, lines):
        cseq = self._get_header(lines, 'CSeq')
        self._send_response(200, cseq)
        self._cleanup()

    async def _stream_media(self):
        log("[RTSP] Stream is now PLAYING.")
        loop = asyncio.get_running_loop()
        packetizer = self.track_setups['1']['packetizer']
        start_time = time.time()
        
        while self.state == 'PLAYING':
            try:
                packet = await loop.run_in_executor(None, video_frame_queue.get)
                if packet is None:
                    await asyncio.sleep(0.01)
                    continue

                packetizer.ts = int((time.time() - start_time) * VIDEO_CLOCK)

                for nalu in packet.split(b'\x00\x00\x00\x01'):
                    if nalu:
                        for rtp_pkt in packetizer.fragment_h264(nalu):
                            self._send_rtp(rtp_pkt, '1')
                await asyncio.sleep(0)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log(f"[RTSP] Streaming error: {e}")
                break
        log("[RTSP] Stream ended."); self._cleanup()

    def _send_rtp(self, packet: bytes, track_id: str):
        if (setup := self.track_setups.get(track_id)) and (sock := setup.get('rtp_sock')):
            try: sock.sendto(packet, (self.client_ip, setup['client_ports'][0]))
            except Exception: pass

    def _send_response(self, code, cseq, headers=None, body=b''):
        status = {200: 'OK', 455: 'Method Not Valid', 461: 'Unsupported Transport', 500: 'Internal Server Error', 501: 'Not Implemented'}.get(code, 'Unknown')
        response = f"RTSP/1.0 {code} {status}\r\nCSeq: {cseq}\r\n"
        if self.session_id: response += f"Session: {self.session_id}\r\n"
        if headers: response += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        if body: response += f"Content-Length: {len(body)}\r\n"
        self.transport.write(f"{response}\r\n".encode() + body)

# =================================================================================
#  RTSP SWITCHER UI & LOGIC
# =================================================================================

class SignalHandler(QObject):
    update_image = pyqtSignal(np.ndarray)
    log_message = pyqtSignal(str)

class RTSPSwitcher(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RTSP Seamless Switcher with RTSP Output")
        self.setGeometry(100, 100, 1280, 720)

        self.rtsp_uris = ["rtsp://192.168.12.8:554/1", "rtsp://192.168.12.9:554/1"]
        self.current_index = -1 # Start at -1 so first switch goes to index 0
        self.seamless_mode = True
        self.rtsp_output_enabled = True
        self.player_thread = None
        self.stop_event = threading.Event()

        self.signals = SignalHandler()
        self.signals.update_image.connect(self.update_preview)
        self.signals.log_message.connect(lambda msg: log(msg))

        self.build_ui()
        self.start_rtsp_server()

    def build_ui(self):
        layout = QVBoxLayout()
        self.uri_fields = [QLineEdit(uri) for uri in self.rtsp_uris]
        for field in self.uri_fields: layout.addWidget(field)

        control_layout = QHBoxLayout()
        self.seamless_checkbox = QCheckBox("Enable Seamless Switching")
        self.seamless_checkbox.setChecked(True)
        self.seamless_checkbox.stateChanged.connect(lambda: setattr(self, 'seamless_mode', self.seamless_checkbox.isChecked()))
        control_layout.addWidget(self.seamless_checkbox)

        self.rtsp_output_checkbox = QCheckBox("Enable RTSP Output")
        self.rtsp_output_checkbox.setChecked(True)
        self.rtsp_output_checkbox.stateChanged.connect(self.toggle_rtsp_output)
        control_layout.addWidget(self.rtsp_output_checkbox)

        switch_button = QPushButton("Switch Camera")
        switch_button.clicked.connect(self.switch_camera)
        control_layout.addWidget(switch_button)
        layout.addLayout(control_layout)
        
        rtsp_output_label = QLabel(f"<b>RTSP Output URL:</b> rtsp://0.0.0.0:{RTSP_SERVER_PORT}/")
        rtsp_output_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(rtsp_output_label)

        self.video_label = QLabel("Press 'Switch Camera' to start")
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setStyleSheet("background-color: black; color: white; font-size: 18px;")
        layout.addWidget(self.video_label, stretch=1)
        self.setLayout(layout)

    def toggle_rtsp_output(self):
        self.rtsp_output_enabled = self.rtsp_output_checkbox.isChecked()
        log(f"RTSP Output Enabled: {self.rtsp_output_enabled}")
        if not self.rtsp_output_enabled:
            with video_frame_queue.mutex:
                video_frame_queue.queue.clear()
    
    def start_rtsp_server(self):
        log("Starting RTSP Server thread...")
        threading.Thread(target=self._run_server, daemon=True).start()

    def _run_server(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        server_task = loop.create_server(RTSPProtocol, '0.0.0.0', RTSP_SERVER_PORT)
        server = loop.run_until_complete(server_task)
        log(f"RTSP Server listening on rtsp://0.0.0.0:{RTSP_SERVER_PORT}/")

        try:
            loop.run_forever()
        finally:
            server.close()
            loop.run_until_complete(server.wait_closed())
            loop.close()
            log("RTSP Server has shut down.")

    def switch_camera(self):
        if self.player_thread and self.player_thread.is_alive():
            self.stop_event.set()
            self.player_thread.join()
        
        with video_frame_queue.mutex:
            video_frame_queue.queue.clear()

        self.stop_event.clear()
        self.current_index = (self.current_index + 1) % len(self.uri_fields)
        uri = self.uri_fields[self.current_index].text()
        self.player_thread = threading.Thread(
            target=self.start_stream, args=(uri, self.seamless_mode), daemon=True
        )
        self.player_thread.start()

    def update_preview(self, img):
        h, w, ch = img.shape
        qt_img = QImage(img.data, w, h, ch * w, QImage.Format_RGB888).rgbSwapped()
        pixmap = QPixmap.fromImage(qt_img)
        self.video_label.setPixmap(pixmap.scaled(
            self.video_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))

    def start_stream(self, uri, seamless):
        self.signals.log_message.emit(f"\n🔁 SWITCHING to {uri} (Seamless={seamless})")
        try:
            ip = uri.split("//")[1].split("/")[0].split(":")[0]
        except IndexError:
            self.signals.log_message.emit(f"❌ Invalid RTSP URI format: {uri}")
            return

        iframe_triggered = threading.Event()
        if seamless:
            def send_iframe_triggers():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                while not iframe_triggered.is_set():
                    sock.sendto(IFRAME_COMMAND, (ip, IFRAME_PORT))
                    time.sleep(IFRAME_INTERVAL)
            threading.Thread(target=send_iframe_triggers, daemon=True).start()

        container = None
        try:
            # --- FIXED: Reverted to the original, simpler options ---
            # Using only the transport option that worked in the original script
            options = {'rtsp_transport': 'tcp'}
            container = av.open(uri, options=options)
            
            video_stream = container.streams.video[0]
            # --- FIXED: Added back the thread_type setting from the original script ---
            video_stream.thread_type = 'AUTO' 
            
            self.signals.log_message.emit(f"✅ Successfully connected to {uri}. Starting stream loop...")
            
            for packet in container.demux(video_stream):
                if self.stop_event.is_set():
                    break
                
                try:
                    for frame in packet.decode():
                        self.signals.update_image.emit(frame.to_ndarray(format='bgr24'))
                        if frame.key_frame and seamless: 
                            iframe_triggered.set()
                except Exception:
                    # Skip problematic packets that can't be decoded
                    continue 
                
                if self.rtsp_output_enabled:
                    try:
                        annex_b_packet = b'\x00\x00\x00\x01' + bytes(packet)
                        video_frame_queue.put(annex_b_packet, block=False)
                    except Full:
                        pass # Silently drop if the queue is full

        except Exception as e:
            self.signals.log_message.emit(f"❌ Failed to open or process stream {uri}: {e}")
        finally:
            if container: container.close()
            iframe_triggered.set()
            self.signals.log_message.emit(f"🛑 Stopped stream for {uri}")

    def closeEvent(self, event):
        self.stop_event.set()
        if self.player_thread: self.player_thread.join(timeout=1)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RTSPSwitcher()
    window.show()
    sys.exit(app.exec_())