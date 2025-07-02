<h2>Overview of Scripts</h2>

<h3>1. RTSPServer.py</h3>
<p>A <strong>standalone RTSP server</strong> that reads a local MP4 file and serves it over the network via RTSP/RTP. Key features include:</p>
<ul>
  <li><strong>Asyncio-based RTSP control channel</strong> handling OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN.</li>
  <li><strong>SDP generation</strong> by probing the sample file with PyAV to extract H.264 SPS/PPS and AAC codec parameters.</li>
  <li><strong>RTP packetization</strong> classes for H.264 fragmentation and AAC payloads.</li>
  <li><strong>Producer thread</strong> demuxing frames into a thread-safe queue, and an <strong>asyncio streaming task</strong> that reads packets, respects timing (PTS → sleep), and sends RTP packets to the client’s UDP port.</li>
  <li><strong>Logging</strong> at each stage (connection, packet send, demux start/end) for easier debugging.</li>
</ul>

<h3>2. RTSPSwitcher.py</h3>
<p>A <strong>PyQt5 GUI client</strong> for seamlessly switching between multiple live RTSP sources and previewing them locally. It does <em>not</em> include any server functionality. Highlights:</p>
<ul>
  <li><strong>GUI with URI inputs</strong>, “Enable Seamless Switching” toggle, and a “Switch Camera” button.</li>
  <li>On switch:
    <ul>
      <li><strong>I-frame trigger thread</strong>: sends periodic VISCA-style I-frame requests over UDP to force an I-frame from the camera.</li>
      <li><strong>PyAV decoding</strong> over TCP, waiting for the key-frame, then updating the preview via OpenCV → QImage → QLabel.</li>
    </ul>
  </li>
  <li><strong>Seamless mode</strong>: overlaps the trigger and decode phases to minimize blackout.</li>
  <li><strong>Error handling</strong>: catches exceptions during container open/decode, prints user-friendly logs.</li>
</ul>

<h3>3. RTSPSwitcherWithServer.py</h3>
<p>Combines the <strong>switcher GUI</strong> with an <strong>embedded RTSP output server</strong>, so that whatever camera you switch to is not only previewed locally but also re-streamed over RTSP. Major additions:</p>
<ul>
  <li><strong>Global frame queue</strong> bridging the decode thread and the server. Frames are pushed (in Annex-B format) as they’re decoded.</li>
  <li><strong>Integrated asyncio RTSP server</strong> (same packetizer logic as <code>RTSPServer.py</code> but video-only) running in its own thread, serving whatever frames are in the queue.</li>
  <li><strong>UI controls</strong> to enable/disable RTSP output at runtime; disabling clears the queue.</li>
  <li><strong>Signal/slot integration</strong> via a custom <code>SignalHandler</code> for thread-safe UI updates of the preview and logs.</li>
  <li><strong>Queue sizing</strong> tuned (120 packets) to balance memory vs. streamer smoothness.</li>
</ul>

<h3>4. RTSPSwitcherWithServerWithAudio.py</h3>
<p>A <strong>PyQt5 GUI client</strong> with an <strong>embedded RTSP server</strong> that streams both <strong>video and audio</strong> from switched sources. Building on <code>RTSPSwitcherWithServer.py</code>, it adds:</p>
<ul>
  <li><strong>Audio frame queue</strong> alongside video queue for inter-thread buffering.</li>
  <li><strong>AAC packetization</strong> classes and RTP packetizer for audio (RFC 3640).</li>
  <li><strong>Dynamic SDP generation</strong> including audio track parameters (clock rate, channels, config).</li>
  <li><strong>Audio probing</strong> of the first RTSP source to extract codec context (sample rate, channels, extradata).</li>
  <li><strong>Integrated audio streaming</strong> in the RTSP server loop, sending both video and audio RTP packets.</li>
</ul>

<h2>Comparison at a Glance</h2>
<table>
  <thead>
    <tr>
      <th>Feature</th>
      <th>RTSPServer.py</th>
      <th>RTSPSwitcher.py</th>
      <th>RTSPSwitcherWithServer.py</th>
      <th>RTSPSwitcherWithServerWithAudio.py</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Role</td>
      <td>File → RTSP server</td>
      <td>RTSP client &amp; preview GUI</td>
      <td>Client + embedded RTSP server</td>
      <td>Client + server w/ audio</td>
    </tr>
    <tr>
      <td>Protocol Handling</td>
      <td>Full RTSP/RTP w/ audio</td>
      <td>RTSP over TCP (video only)</td>
      <td>RTSP/RTP video only</td>
      <td>RTSP/RTP video + audio</td>
    </tr>
    <tr>
      <td>Packetization</td>
      <td>H.264 + AAC</td>
      <td>N/A (uses camera’s stream)</td>
      <td>H.264 only</td>
      <td>H.264 + AAC</td>
    </tr>
    <tr>
      <td>Seamless Switch Logic</td>
      <td>N/A</td>
      <td>Yes (I-frame triggers)</td>
      <td>Yes (I-frame triggers)</td>
      <td>Yes (I-frame triggers)</td>
    </tr>
    <tr>
      <td>GUI</td>
      <td>None</td>
      <td>PyQt5 preview window</td>
      <td>PyQt5 preview + controls</td>
      <td>PyQt5 preview + controls</td>
    </tr>
    <tr>
      <td>Streaming Queue</td>
      <td>Demux → thread → RTP</td>
      <td>N/A</td>
      <td>Decode → queue → RTSP server</td>
      <td>Decode → video &amp; audio queue → RTSP server</td>
    </tr>
    <tr>
      <td>Use Cases</td>
      <td>Serve prerecorded media</td>
      <td>Preview/swapping live cams</td>
      <td>Preview + re-stream live cams</td>
      <td>Preview + re-stream live cams with audio</td>
    </tr>
  </tbody>
</table>

<h2>Summary</h2>
<p>In summary, you have:</p>
<ol>
  <li>A <strong>pure server</strong> for on-disk files (<code>RTSPServer.py</code>).</li>
  <li>A <strong>pure client</strong> that previews and seamlessly switches between live RTSP streams (<code>RTSPSwitcher.py</code>).</li>
  <li>A <strong>hybrid</strong> combining both: switch between sources in a GUI <em>and</em> re-serve the selected feed as RTSP (<code>RTSPSwitcherWithServer.py</code>).</li>
  <li>An <strong>enhanced hybrid</strong> with both video and audio streaming (<code>RTSPSwitcherWithServerWithAudio.py</code>).</li>
</ol>
