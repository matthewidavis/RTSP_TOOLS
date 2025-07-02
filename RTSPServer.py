import asyncio
import re
import socket
import random
import struct
import time
import av
import base64
from pathlib import Path
from queue import Queue as ThreadSafeQueue


# ==== CONFIG ====
SAMPLE_FILE = Path(r"C:\Users\Matt\Downloads\tranquil_rainy_day_2.mp4")

# RTP/RTSP constants
VIDEO_PT        = 96
AUDIO_PT        = 97
VIDEO_CLOCK     = 90_000
MAX_PAYLOAD     = 1200
QUEUE_SIZE      = 60

def log(*args):
    """A simple print logger with a prefix."""
    print("[RTSP]", *args)

class RTPPacketizer:
    """A generic RTP packetizer."""
    def __init__(self, pt):
        self.pt, self.seq, self.ts, self.ssrc = pt, random.randint(0, 0xFFFF), 0, random.randint(0, 0xFFFFFFFF)

    def packetize(self, payload: bytes, marker: bool = True):
        hdr = bytearray(12)
        hdr[0], hdr[1] = 0x80, (0x80 if marker else 0) | (self.pt & 0x7F)
        hdr[2:4], hdr[4:8], hdr[8:12] = self.seq.to_bytes(2, 'big'), self.ts.to_bytes(4, 'big'), self.ssrc.to_bytes(4, 'big')
        self.seq = (self.seq + 1) & 0xFFFF
        return bytes(hdr) + payload

    def fragment_h264(self, nalu: bytes):
        if not nalu: return
        if len(nalu) <= MAX_PAYLOAD:
            yield self.packetize(nalu, True)
            return
        
        hdr_byte, payload = nalu[0], nalu[1:]
        fu_ind, start, end, mid = (hdr_byte & 0xE0)|28, (1<<7)|(hdr_byte & 0x1F), (1<<6)|(hdr_byte & 0x1F), hdr_byte & 0x1F
        
        offset, first = 0, True
        while offset < len(payload):
            chunk = payload[offset:offset + MAX_PAYLOAD - 2]
            offset += len(chunk)
            is_last = (offset >= len(payload))
            fu_hdr = start if first else (end if is_last else mid)
            first = False
            yield self.packetize(bytes([fu_ind, fu_hdr]) + chunk, is_last)
    
    def packetize_aac(self, frame: bytes):
        """Packetizes an AAC frame according to RFC 3640."""
        au_header = ((len(frame) & 0x1FFF) << 3).to_bytes(2, 'big')
        yield self.packetize(au_header + frame)

class RTSPProtocol(asyncio.Protocol):
    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport, self.buf, self.client_ip, self.state = transport, b'', transport.get_extra_info('peername')[0], 'INIT'
        self.session_id, self.streaming_task, self.track_setups = None, None, {}
        log(f"Connected: {self.client_ip}")

    def connection_lost(self, exc):
        log(f"Disconnected: {self.client_ip}")
        self._cleanup()

    def _cleanup(self):
        if self.streaming_task and not self.streaming_task.done(): self.streaming_task.cancel()
        for track in self.track_setups.values():
            if rtp_sock := track.get('rtp_sock'): rtp_sock.close()
        if self.transport and not self.transport.is_closing(): self.transport.close()

    def data_received(self, data: bytes):
        self.buf += data
        while True:
            if self.buf.startswith(b'$') and len(self.buf) >= 4:
                if len(self.buf) < 4 + (length := int.from_bytes(self.buf[2:4], 'big')): return
                self.buf = self.buf[4 + length:]
                continue
            if b'\r\n\r\n' in self.buf:
                req_data, self.buf = self.buf.split(b'\r\n\r\n', 1)
                lines = req_data.decode('utf-8', 'ignore').split('\r\n')
                if not lines or len(lines[0].split()) < 2: continue
                method, url = lines[0].split()[:2]
                log(f"← {method} {url}")
                if handler := getattr(self, f'on_{method.lower()}', self.on_unsupported): handler(lines, url)
                continue
            return

    def _get_header(self, lines, key):
        key = key.lower()
        for line in lines:
            if line.lower().startswith(key): return line.split(':', 1)[1].strip()
        return None

    def on_unsupported(self, lines, url): self._send_response(501, self._get_header(lines, 'CSeq'))
    def on_options(self, lines, url): self._send_response(200, self._get_header(lines, 'CSeq'), {'Public': 'OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN'})

    def on_describe(self, lines, url):
            cseq = self._get_header(lines, 'CSeq')
            sdp_parts, self.media_info = [], {}
            try:
                with av.open(str(SAMPLE_FILE), 'r') as container:
                    # Video Track SDP
                    if vs := next((s for s in container.streams if s.type == 'video'), None):
                        self.media_info['video'] = {'time_base': vs.time_base}
                        codec_ctx = vs.codec_context
                        if (ed := codec_ctx.extradata) and ed.startswith(b'\x01'):
                            sps_len = int.from_bytes(ed[6:8], 'big')
                            sps = ed[8 : 8 + sps_len]
                            pps_offset = 8 + sps_len + 1
                            pps_len = int.from_bytes(ed[pps_offset : pps_offset + 2], 'big')
                            pps = ed[pps_offset + 2 : pps_offset + 2 + pps_len]
                            sps_b64, pps_b64 = base64.b64encode(sps).decode(), base64.b64encode(pps).decode()
                            sprop = f"a=fmtp:{VIDEO_PT} packetization-mode=1;sprop-parameter-sets={sps_b64},{pps_b64}\r\n"
                            sdp_parts.append(f"m=video 0 RTP/AVP {VIDEO_PT}\r\na=rtpmap:{VIDEO_PT} H264/{VIDEO_CLOCK}\r\n{sprop}a=control:track1\r\n")

                    # Audio Track SDP
                    if audio := next((s for s in container.streams if s.type == 'audio'), None):
                        ctx = audio.codec_context
                        self.media_info['audio'] = {'time_base': audio.time_base, 'clock_rate': ctx.sample_rate}
                        
                        # --- THE FIX: A simplified, more robust fmtp line for AAC ---
                        fmtp_line = (f"a=fmtp:{AUDIO_PT} streamtype=5;profile-level-id=1;"
                                    f"mode=AAC-hbr;config={ctx.extradata.hex()};"
                                    f"SizeLength=13;IndexLength=3;IndexDeltaLength=3;\r\n")

                        sdp_parts.append(f"m=audio 0 RTP/AVP {AUDIO_PT}\r\na=rtpmap:{AUDIO_PT} MPEG4-GENERIC/{ctx.sample_rate}/{ctx.channels}\r\n{fmtp_line}a=control:track2\r\n")
            
            except Exception as e:
                log(f"Error reading media metadata: {e}"); return self._send_response(500, cseq)

            if not sdp_parts: return self._send_response(500, cseq)
            
            ip = self.transport.get_extra_info('sockname')[0]
            sdp_base = (f"v=0\r\no=- {random.randint(0,0xFFFFFFFF)} 1 IN IP4 {ip}\r\ns=Python RTSP\r\nt=0 0\r\na=control:*\r\n")
            self._send_response(200, cseq, {'Content-Type': 'application/sdp'}, (sdp_base + "".join(sdp_parts)).encode())

    def on_setup(self, lines, url):
        cseq, transport_hdr = self._get_header(lines, 'CSeq'), self._get_header(lines, 'Transport')
        self.session_id = self.session_id or str(random.randint(100000, 999999))
        
        track_id = '1' if 'track1' in url else '2'
        pt = VIDEO_PT if track_id == '1' else AUDIO_PT
        
        if m := re.search(r'client_port=(\d+)-(\d+)', transport_hdr):
            client_ports = tuple(map(int, m.groups()))
            rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp_sock.bind(('', 0))
            self.track_setups[track_id] = {'rtp_sock': rtp_sock, 'client_ports': client_ports, 'packetizer': RTPPacketizer(pt)}
            
            spec = (f"RTP/AVP;unicast;client_port={client_ports[0]}-{client_ports[1]};"
                    f"server_port={rtp_sock.getsockname()[1]}-{rtp_sock.getsockname()[1]+1}")
            self.state = 'READY'
            self._send_response(200, cseq, {'Transport': spec, 'Session': self.session_id})
        else: self._send_response(461, cseq)

    def on_play(self, lines, url):
        cseq = self._get_header(lines, 'CSeq')
        if self.state != 'READY': return self._send_response(455, cseq)
        self.state = 'PLAYING'
        self.streaming_task = asyncio.create_task(self._stream_media())
        self._send_response(200, cseq, {'Session': self.session_id})

    def on_pause(self, lines, url): self._cleanup()
    def on_teardown(self, lines, url): self._cleanup()

    def _producer_thread(self, queue: ThreadSafeQueue):
        try:
            with av.open(str(SAMPLE_FILE), 'r') as container:
                streams_to_demux = [s for s in container.streams if s.type in ['video', 'audio']]
                log("Producer: Starting demuxing...")
                for packet in container.demux(*streams_to_demux):
                    if packet.dts is not None:
                        queue.put(packet)
                queue.put(None)
                log("Producer: Finished demuxing.")
        except Exception as e:
            log(f"Producer thread error: {e}")
            queue.put(None)

    async def _stream_media(self):
        log("Stream is now PLAYING.")
        loop = asyncio.get_running_loop()
        frame_queue = ThreadSafeQueue(maxsize=QUEUE_SIZE)
        
        producer_task = loop.run_in_executor(None, self._producer_thread, frame_queue)
        
        try:
            video_bsfc = None
            if 'video' in self.media_info:
                 with av.open(str(SAMPLE_FILE), 'r') as container:
                    video_bsfc = av.BitStreamFilterContext('h264_mp4toannexb', container.streams.video[0])

            start_pts, start_time, frame_count = None, None, 0
            
            while True:
                packet = await loop.run_in_executor(None, frame_queue.get)
                if packet is None: break

                if start_pts is None: start_pts, start_time = packet.pts, time.time()
                
                target_time = start_time + float((packet.pts - start_pts) * packet.time_base)
                if (delay := target_time - time.time()) > 0: await asyncio.sleep(delay)

                is_video = packet.stream.type == 'video'
                track_id = '1' if is_video else '2'
                setup = self.track_setups.get(track_id)
                if not setup: continue
                
                packetizer = setup['packetizer']
                
                if is_video and video_bsfc:
                    packetizer.ts = int((packet.pts - start_pts) * VIDEO_CLOCK * self.media_info['video']['time_base'])
                    for fp in video_bsfc.filter(packet):
                        for nalu in bytes(fp).split(b'\x00\x00\x00\x01'):
                            if nalu:
                                for i, rtp_pkt in enumerate(packetizer.fragment_h264(nalu)):
                                    self._send_rtp(rtp_pkt, '1')
                                    if i > 0 and i % 16 == 0: await asyncio.sleep(0)
                elif not is_video:
                    audio_info = self.media_info['audio']
                    packetizer.ts = int((packet.pts - start_pts) * audio_info['clock_rate'] * audio_info['time_base'])
                    # --- Add Audio Debug Log ---
                    log(f"  --> Sending AUDIO packet, PTS: {packet.pts}, Size: {len(bytes(packet))}")
                    for rtp_pkt in packetizer.packetize_aac(bytes(packet)):
                        self._send_rtp(rtp_pkt, '2')
                
                if (frame_count := frame_count + 1) % 100 == 0: log(f"... streamed {frame_count} frames")
        except asyncio.CancelledError: log("Stream cancelled by client.")
        except Exception as e: log(f"Streaming error: {e}")
        finally:
            log("Stream ended."); self._cleanup()

    def _send_rtp(self, packet: bytes, track_id: str):
        if (setup := self.track_setups.get(track_id)) and (sock := setup.get('rtp_sock')):
            try: sock.sendto(packet, (self.client_ip, setup['client_ports'][0]))
            except Exception as e: log(f"RTP send error: {e}")

    def _send_response(self, code, cseq, headers=None, body=b''):
        status = {200: 'OK', 455: 'Method Not Valid', 461: 'Unsupported Transport', 500: 'Internal Server Error', 501: 'Not Implemented'}.get(code, 'Unknown')
        response = f"RTSP/1.0 {code} {status}\r\nCSeq: {cseq}\r\n"
        if self.session_id: response += f"Session: {self.session_id}\r\n"
        if headers: response += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        if body: response += f"Content-Length: {len(body)}\r\n"
        self.transport.write(f"{response}\r\n".encode() + body)

async def main():
    if not SAMPLE_FILE.exists(): return log(f"FATAL: Sample file not found at {SAMPLE_FILE}")
    server = await asyncio.get_running_loop().create_server(RTSPProtocol, '0.0.0.0', 8554)
    log(f"Server listening on rtsp://0.0.0.0:8554/")
    async with server: await server.serve_forever()

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: log("Server shutting down.")