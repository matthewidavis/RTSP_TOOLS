
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
from queue import Queue as ThreadSafeQueue, Full, Empty

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

AUDIO_PT = 97
AUDIO_CLOCK = None  # Will be probed from first source
AUDIO_CHANNELS = None
AUDIO_CONFIG = None

# Queues for video and audio frames
video_frame_queue = ThreadSafeQueue(maxsize=QUEUE_SIZE)
audio_frame_queue = ThreadSafeQueue(maxsize=QUEUE_SIZE)

def log(*args):
    """A simple print logger with a prefix."""
    print("[Switcher]", *args)

# =================================================================================
#  RTSP SERVER CODE (with audio support)
# =================================================================================

class RTPPacketizer:
    def __init__(self, pt):
        self.pt, self.seq, self.ts, self.ssrc = pt, random.randint(0, 0xFFFF), 0, random.randint(0, 0xFFFFFFFF)

    def packetize(self, payload: bytes, marker: bool = True):
        hdr = bytearray(12)
        hdr[0], hdr[1] = 0x80, (0x80 if marker else 0) | (self.pt & 0x7F)
        hdr[2:4], hdr[4:8], hdr[8:12] = (
            self.seq.to_bytes(2, 'big'),
            self.ts.to_bytes(4, 'big'),
            self.ssrc.to_bytes(4, 'big')
        )
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

        offset = 0
        is_first = True
        while offset < len(payload):
            chunk = payload[offset:offset + MAX_PAYLOAD - 2]
            is_last = (offset + len(chunk) >= len(payload))
            if is_first:
                fu_header = fu_header_start
                is_first = False
            elif is_last:
                fu_header = fu_header_end
            else:
                fu_header = fu_header_middle

            yield self.packetize(bytes([fu_indicator, fu_header]) + chunk, is_last)
            offset += len(chunk)

    def packetize_aac(self, frame: bytes):
        """Packetizes an AAC frame according to RFC 3640."""
        au_header = ((len(frame) & 0x1FFF) << 3).to_bytes(2, 'big')
        yield self.packetize(au_header + frame)

class RTSPProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.buf = b''
        self.client_ip = transport.get_extra_info('peername')[0]
        self.state = 'INIT'
        self.session_id = None
        self.streaming_task = None
        self.track_setups = {}
        print(f"[RTSP] Connected: {self.client_ip}")

    def connection_lost(self, exc):
        print(f"[RTSP] Disconnected: {self.client_ip}")
        self._cleanup()

    def _cleanup(self):
        if self.streaming_task and not self.streaming_task.done():
            self.streaming_task.cancel()
        for track in self.track_setups.values():
            if sock := track.get('rtp_sock'):
                sock.close()
        if self.transport and not self.transport.is_closing():
            self.transport.close()

    def data_received(self, data: bytes):
        self.buf += data
        while b'\r\n\r\n' in self.buf:
            req, self.buf = self.buf.split(b'\r\n\r\n', 1)
            lines = req.decode('utf-8', 'ignore').split('\r\n')
            if not lines or len(lines[0].split()) < 2:
                continue
            method, url = lines[0].split()[:2]
            handler = getattr(self, f'on_{method.lower()}', self.on_unsupported)
            handler(lines, url)

    def _get_header(self, lines, key):
        for line in lines:
            if line.lower().startswith(key.lower()):
                return line.split(':', 1)[1].strip()
        return None

    def on_unsupported(self, lines, url=None):
        self._send_response(501, self._get_header(lines, 'CSeq'))

    def on_options(self, lines, url):
        self._send_response(
            200,
            self._get_header(lines, 'CSeq'),
            {'Public': 'OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN'}
        )

    def on_describe(self, lines, url):
        cseq = self._get_header(lines, 'CSeq')
        ip = self.transport.get_extra_info('sockname')[0]

        sdp_lines = [
            f"v=0",
            f"o=- {random.randint(0,0xFFFFFFFF)} 1 IN IP4 {ip}",
            f"s=RTSP Switcher Output",
            f"t=0 0",
            f"a=control:*",
            "",
            # video track
            f"m=video 0 RTP/AVP {VIDEO_PT}",
            f"a=rtpmap:{VIDEO_PT} H264/{VIDEO_CLOCK}",
            f"a=fmtp:{VIDEO_PT} packetization-mode=1",
            f"a=control:track1",
        ]

        # append audio track if we have it
        if AUDIO_CLOCK and AUDIO_CHANNELS and AUDIO_CONFIG:
            sdp_lines += [
                "",
                f"m=audio 0 RTP/AVP {AUDIO_PT}",
                f"a=rtpmap:{AUDIO_PT} MPEG4-GENERIC/{AUDIO_CLOCK}/{AUDIO_CHANNELS}",
                (f"a=fmtp:{AUDIO_PT} streamtype=5;profile-level-id=1;"
                 f"mode=AAC-hbr;config={AUDIO_CONFIG};"
                 "SizeLength=13;IndexLength=3;IndexDeltaLength=3"),
                f"a=control:track2",
            ]

        body = "\r\n".join(sdp_lines).encode('utf-8') + b"\r\n"
        self._send_response(
            200,
            cseq,
            {'Content-Type': 'application/sdp'},
            body
        )

    def on_setup(self, lines, url):
        cseq = self._get_header(lines, 'CSeq')
        transport_hdr = self._get_header(lines, 'Transport')
        self.session_id = self.session_id or str(random.randint(100000, 999999))

        m = re.search(r'client_port=(\d+)-(\d+)', transport_hdr or '')
        if m:
            client_ports = tuple(map(int, m.groups()))
            rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp_sock.bind(('', 0))

            # Treat any non-track2 URL as video
            if 'track2' in url:
                pt = AUDIO_PT
                track_id = '2'
            else:
                pt = VIDEO_PT
                track_id = '1'

            packetizer = RTPPacketizer(pt)
            self.track_setups[track_id] = {
                'rtp_sock': rtp_sock,
                'client_ports': client_ports,
                'packetizer': packetizer
            }

            server_port = rtp_sock.getsockname()[1]
            spec = (f"RTP/AVP;unicast;client_port={client_ports[0]}-{client_ports[1]};"
                    f"server_port={server_port}")
            # now that we've got at least one track, allow PLAY
            self.state = 'READY'
            self._send_response(200, cseq, {'Transport': spec, 'Session': self.session_id})
        else:
            self._send_response(461, cseq)

    def on_play(self, lines, url):
        cseq = self._get_header(lines, 'CSeq')
        if self.state != 'READY':
            return self._send_response(455, cseq)

        self.state = 'PLAYING'
        self.streaming_task = asyncio.create_task(self._stream_media())
        self._send_response(200, cseq, {'Session': self.session_id})

    def on_teardown(self, lines, url):
        cseq = self._get_header(lines, 'CSeq')
        self._send_response(200, cseq)
        self._cleanup()

    async def _stream_media(self):
        print("[RTSP] Stream is now PLAYING.")
        loop = asyncio.get_running_loop()
        video_pk = self.track_setups['1']['packetizer']
        audio_pk = self.track_setups.get('2', {}).get('packetizer')
        start = time.time()

        while True:
            # get next video packet (blocking)
            packet = await loop.run_in_executor(None, video_frame_queue.get)
            if packet is None:
                break

            # send video
            video_pk.ts = int((time.time() - start) * VIDEO_CLOCK)
            for nalu in packet.split(b'\x00\x00\x00\x01'):
                if nalu:
                    for rtp_pkt in video_pk.fragment_h264(nalu):
                        self._send_rtp(rtp_pkt, '1')

            # send any queued audio
            if audio_pk:
                while True:
                    try:
                        frm = audio_frame_queue.get_nowait()
                    except Empty:
                        break
                    audio_pk.ts = int((time.time() - start) * AUDIO_CLOCK)
                    for rtp_pkt in audio_pk.packetize_aac(frm):
                        self._send_rtp(rtp_pkt, '2')

            await asyncio.sleep(0)

        print("[RTSP] Stream ended.")
        self._cleanup()

    def _send_rtp(self, packet: bytes, track_id: str):
        setup = self.track_setups.get(track_id)
        if not setup:
            return
        try:
            setup['rtp_sock'].sendto(packet, (self.client_ip, setup['client_ports'][0]))
        except Exception:
            pass

    def _send_response(self, code, cseq, headers=None, body=b''):
        status = {
            200: 'OK', 455: 'Method Not Valid',
            461: 'Unsupported Transport', 500: 'Internal Server Error',
            501: 'Not Implemented'
        }.get(code, 'Unknown')
        # Build header lines
        resp_lines = [
            f"RTSP/1.0 {code} {status}",
            f"CSeq: {cseq}"
        ]
        if headers:
            for k, v in headers.items():
                resp_lines.append(f"{k}: {v}")
        if body:
            resp_lines.append(f"Content-Length: {len(body)}")
        # CRLF-join and double-CRLF terminate
        resp_str = "\r\n".join(resp_lines) + "\r\n\r\n"
        resp_bytes = resp_str.encode('utf-8')
        if body:
            resp_bytes += body
        self.transport.write(resp_bytes)


# =================================================================================
#  RTSP SWITCHER UI & LOGIC
# =================================================================================

class SignalHandler(QObject):
    update_image = pyqtSignal(np.ndarray)
    log_message = pyqtSignal(str)

class RTSPSwitcher(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RTSP Seamless Switcher with Audio")
        self.setGeometry(100, 100, 1280, 720)

        self.rtsp_uris = ["rtsp://192.168.12.8:554/1", "rtsp://192.168.12.9:554/1"]
        self.current_index = -1
        self.seamless_mode = True
        self.rtsp_output_enabled = True
        self.player_thread = None
        self.stop_event = threading.Event()

        self.signals = SignalHandler()
        self.signals.update_image.connect(self.update_preview)
        self.signals.log_message.connect(lambda msg: log(msg))

        # Probe first source for audio params
        global AUDIO_CLOCK, AUDIO_CHANNELS, AUDIO_CONFIG
        try:
            probe = av.open(self.rtsp_uris[0], options={'rtsp_transport':'tcp'})
            audio_stream = next((s for s in probe.streams if s.type=='audio'), None)
            if audio_stream:
                ctx = audio_stream.codec_context
                AUDIO_CLOCK = ctx.sample_rate
                AUDIO_CHANNELS = ctx.channels
                AUDIO_CONFIG = ctx.extradata.hex()
            probe.close()
            log(f"Probed audio: clock={AUDIO_CLOCK}, channels={AUDIO_CHANNELS}")
        except Exception as e:
            log(f"Audio probe failed: {e}")

        self.build_ui()
        self.start_rtsp_server()

    def build_ui(self):
        layout = QVBoxLayout()
        self.uri_fields = [QLineEdit(uri) for uri in self.rtsp_uris]
        for field in self.uri_fields:
            layout.addWidget(field)

        control_layout = QHBoxLayout()
        self.seamless_checkbox = QCheckBox("Enable Seamless Switching")
        self.seamless_checkbox.setChecked(True)
        self.seamless_checkbox.stateChanged.connect(
            lambda: setattr(self, 'seamless_mode', self.seamless_checkbox.isChecked())
        )
        control_layout.addWidget(self.seamless_checkbox)

        self.rtsp_output_checkbox = QCheckBox("Enable RTSP Output")
        self.rtsp_output_checkbox.setChecked(True)
        self.rtsp_output_checkbox.stateChanged.connect(self.toggle_rtsp_output)
        control_layout.addWidget(self.rtsp_output_checkbox)

        switch_btn = QPushButton("Switch Camera")
        switch_btn.clicked.connect(self.switch_camera)
        control_layout.addWidget(switch_btn)
        layout.addLayout(control_layout)

        rtsp_label = QLabel(f"<b>RTSP Output URL:</b> rtsp://0.0.0.0:{RTSP_SERVER_PORT}/")
        rtsp_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(rtsp_label)

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
            with audio_frame_queue.mutex:
                audio_frame_queue.queue.clear()

    def start_rtsp_server(self):
        log("Starting RTSP Server thread...")
        threading.Thread(target=self._run_server, daemon=True).start()

    def _run_server(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        coro = loop.create_server(RTSPProtocol, '0.0.0.0', RTSP_SERVER_PORT)
        server = loop.run_until_complete(coro)
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
        with audio_frame_queue.mutex:
            audio_frame_queue.queue.clear()

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
        except Exception:
            self.signals.log_message.emit(f"❌ Invalid RTSP URI: {uri}")
            return

        iframe_event = threading.Event()
        if seamless:
            def trigger_iframe():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                while not iframe_event.is_set():
                    sock.sendto(IFRAME_COMMAND, (ip, IFRAME_PORT))
                    time.sleep(IFRAME_INTERVAL)
            threading.Thread(target=trigger_iframe, daemon=True).start()

        try:
            options = {'rtsp_transport': 'tcp'}
            container = av.open(uri, options=options)
            video_stream = container.streams.video[0]
            video_stream.thread_type = 'AUTO'
            audio_stream = next((s for s in container.streams if s.type=='audio'), None)

            self.signals.log_message.emit(f"✅ Connected. Decoding streams...")

            for packet in container.demux(video_stream, audio_stream):
                if self.stop_event.is_set():
                    break

                if packet.stream.type == 'video':
                    for frame in packet.decode():
                        self.signals.update_image.emit(frame.to_ndarray(format='bgr24'))
                        if frame.key_frame and seamless:
                            iframe_event.set()
                    # enqueue Annex-B formatted packet
                    try:
                        video_frame_queue.put(b'\x00\x00\x00\x01' + bytes(packet), block=False)
                    except Full:
                        pass
                elif packet.stream.type == 'audio':
                    try:
                        audio_frame_queue.put(bytes(packet), block=False)
                    except Full:
                        pass

        except Exception as e:
            self.signals.log_message.emit(f"❌ Stream error for {uri}: {e}")
        finally:
            iframe_event.set()
            if 'container' in locals():
                container.close()
            self.signals.log_message.emit(f"🛑 Stream stopped for {uri}")

    def closeEvent(self, event):
        self.stop_event.set()
        if self.player_thread:
            self.player_thread.join(timeout=1)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RTSPSwitcher()
    window.show()
    sys.exit(app.exec_())
