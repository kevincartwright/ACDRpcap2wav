# ACDRpcap2wav Audio Extraction

A tool for extracting audio streams from AudioCodes debug recordings in pcap files. This utility uses `tshark` to parse the capture file, isolates RTP payloads associated with AudioCodes Full Session IDs (as seen in syslogs), and converts them to WAV audio files for analysis.

---

## Overview

The ACDRpcap2wav tool automates the process of:
- Filtering pcap files by AudioCodes Full Session ID.
- Extracting RTP payloads based on session parameters.
- Converting μ-law encoded audio to linear PCM.
- Saving the resulting audio as WAV files in an organized directory structure.

Users can target a specific AudioCodes session (using the full session ID found in syslogs) or process all available sessions in the pcap.

---

## Requirements

- **Python 3.7+**
- **Wireshark/tshark**  
  The script checks for `tshark` in common installation paths:
  - Windows:  
    - `C:\Program Files\Wireshark\tshark.exe`
    - `C:\Program Files (x86)\Wireshark\tshark.exe`
  - Linux:  
    - `/usr/bin/tshark`
    - `/usr/local/bin/tshark`
  - macOS:  
    - `/Applications/Wireshark.app/Contents/MacOS/tshark`
- **AudioCodes Debug Recording**
  - Pcap file that includes AudiocCodes Debug Recording traffic.
  - Models supported and tested:
    - AudioCodes MP-114 or MP-118
    - Audiocodes M1K or M1KB
    - AudioCodes M800
- Python modules: `sys`, `subprocess`, `binascii`, `wave`, `time`, `audioop`, and `pathlib`.

> **Note:** The `audioop` module is deprecated in Python 3.11. Consider alternatives if using newer Python versions.

---

## Usage

Run the script from the command line, providing the path to your pcap file:

```bash
python acdrpcap2wav.py /path/to/your/capture.pcapng
```
You will be prompted to enter an AudioCodes Session ID:

Enter a specific session ID (e.g., ccfc41:27) to extract audio for that session.

Leave the input blank to process all sessions found in the pcap.

Extracted audio files are saved in an ACDR-Audio directory created in the same folder as the pcap file. Each session is stored in a subfolder (with colons replaced by periods), and each stream is saved as a WAV file named using its rtp.ssrc and a descriptive trace point.

---

## Example
```bash
$ python acdrpcap2wav.py test.pcapng
╔═════════════════════════════════════════════════╗
║   AudioCodes Debug Recording Audio Extraction   ║
╚═════════════════════════════════════════════════╝
Enter the AudioCodes Session ID or Leave blank to extract All: ccfc41:27
Found tshark at: /usr/local/bin/tshark!
Searching...
   Total unique streams found in pcap: 3
   Total unique session IDs in pcap: 1
User input: ccfc41:27
User input found! Extracting this session ID only.
Running...

Session ID: ccfc41:27
Number of streams: 2
   rtp.ssrc: 0x00001004, acdr.trace_pt: 10
   rtp.ssrc: 0x0000101e, acdr.trace_pt: 10

Process completed in: 15.2 seconds.
```

---

