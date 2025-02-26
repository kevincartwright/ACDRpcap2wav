import sys
import subprocess
import binascii
import wave
import time
import audioop  ## Depreciated in python 3.11 ##
from pathlib import Path

class ACDRpcap2wav:
    def __init__(self, pcap, userinput):
        self.pcap = pcap
        self.pcap_path = Path(pcap)
        self.userinput = userinput.strip()
        self.tshark = None
        self.out_dir = self.pcap_path.parent / "ACDR-Audio"
        self.sid_dict = {}
        self.trace_dict = {
            '10': 'tdm2dsp',
            '1': 'dsp2net',
            '0': 'net2dsp',
            '9': 'dsp2tdm',
            '20': 'beforeVOIPencoder',
            '22': 'beforeNETencoder'
        }

    def tshark_check(self):
        ## List of possible tshark installation places: Windows, Linux, Mac ##
        tshark_paths = [
            Path(r"C:\Program Files\Wireshark\tshark.exe"),
            Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
            Path(r"/usr/bin/tshark"),
            Path(r"/usr/local/bin/tshark"),
            Path(r"/Applications/Wireshark.app/Contents/MacOS/tshark")
        ]
        ## When match is found, use the tshark location ##
        for shark in tshark_paths:
            if shark.exists():
                self.tshark = shark
                print(f"Found tshark at: {shark}!")
                return
            else:
                print(f"tshark not found on system!")
                input("Press any key to exit...")
                sys.exit(1)

    def gather_sessionids(self):
        ## filter for all session ids, ssrc, and tracepoint values ##
        print("Searching...")
        pcap_filter = (
            f'(acdr.session_id || acdr.full_session_id)'
            f' && (acdr.trace_pt != 0 || acdr.trace_pt != "System")'
            f' && rtp'
        )
        all_sids = subprocess.run(
            [
                self.tshark,
                '-r', self.pcap,
                '-T', 'fields',
                '-e', 'acdr.session_id',
                '-e', 'acdr.full_session_id',
                '-e', 'rtp.ssrc',
                '-e', 'acdr.trace_pt',
                '-Y', pcap_filter
            ],
            capture_output=True,
            text=True
        )
        # print(all_sids) ##check for parse error ##
        ## '2922820\tccfc41:27:2922820\t0x0000101e\t10' ##
        ## filter for unique values only ##
        uniques = set(all_sids.stdout.splitlines())
        print(f"   Total unique streams found in pcap: {len(uniques)}")

        for u in uniques:
            values = u.split('\t')
            print(values)
            ## Check if a result was found and use it, else use second value ##
            if values[0] != "":
                sid = values[0]  ## ['277745452', '', '0x00001000', '10'] ##
            else:
                sid = values[1]  ## ['', 'ccfc41:27', '0x00001004', '10'] ##
            ssrc = values[2]
            tp = values[3]
            if sid not in self.sid_dict:
                self.sid_dict[sid] = []
            self.sid_dict[sid].append((ssrc, tp))
        print(f"   Total unique session IDs in pcap: {len(self.sid_dict)}")
        ## Search dictionary keys for match with user input to validate ##
        print(f"User input: {self.userinput}")
        if self.userinput in self.sid_dict:
            ## overwrite dictionary with user inpuit key, using current sid values in dictionary ##
            self.sid_dict = {self.userinput: self.sid_dict[self.userinput]}
            print(f"User input found! Extracting this session ID only.")
        elif self.userinput == "":
            print(f"Extracting for ALL session IDs found")
        else:
            print("No valid user input.")
            sys.exit(1)

    def extract_pcap_audio(self):
        ## Create main output folder ##
        self.out_dir.mkdir(parents=True, exist_ok=True)
        print("Running...")
        for sid, values in self.sid_dict.items():
            ## Create session ID output folder ##
            sid_dir = self.out_dir / sid.replace(':', '.')
            sid_dir.mkdir(parents=True, exist_ok=True)
            print(f"\nSession ID: {sid}")
            print(f"Number of streams: {len(values)}")
            sid_filter = f'(acdr.full_session_id == {sid})'
            sid_pcap = sid_dir / f"{sid.replace(':', '.')}.pcapng"
            ## checks for sid filter type by : ##
            if ":" not in sid:
                sid_filter = f'(acdr.session_id == {sid})'
                sid_pcap = sid_dir / f"{sid}.pcapng"
            ## Filtering input pcap for entire session id ##
            ## Puts file in folder for anaysis or verifying audio conversion ##
            subprocess.run(
                [
                    self.tshark,
                    '-r', self.pcap,
                    '-Y', sid_filter,
                    '-w', sid_pcap
                ]
            )
            for ssrc, tp in values:
                print(f"   rtp.ssrc: {ssrc}, acdr.trace_pt: {tp}")
                ## Filter rtp for conversion ##
                rtp_filter = (
                    sid_filter +
                    f" && rtp.ssrc == {ssrc}"
                    f" && acdr.trace_pt == {tp}"
                    f" && rtp"
                )
                ## load the rtp.payload hex values into stdout ##
                ## ('-e', 'rtp.payload' = \nffe7f) ##
                ## ('-e rtp.payload' = ff:ee:fe:ee) ##
                payload = subprocess.run(
                    [
                        self.tshark,
                        '-r', sid_pcap,
                        '-T', 'fields',
                        '-e', 'rtp.payload',
                        '-Y', rtp_filter
                    ],
                    capture_output=True,
                    text=True
                )
                ## Remove any unnecessary charcters ##
                payload_hex = payload.stdout.strip().replace("\n", "").replace(" ", "")
                payload_raw = binascii.unhexlify(payload_hex)  ## convert from hex to binary ##
                pcm_data = audioop.ulaw2lin(payload_raw, 2)  ## set codec ##
                ## Filter through dictionary to match the acdr.trace_pt value to friendly name ##
                if tp in self.trace_dict.keys():
                    trace_name = self.trace_dict[tp]
                    out_wav = sid_dir / f"{trace_name}-{ssrc}.wav"
                else:
                    out_wav = sid_dir / f"{ssrc}-{tp}.wav"
                ## Write audio data to file ##
                ## Set the audio parameters ##
                nchannels = 1  ## Mono ##
                sampwidth = 2  ## 16-bit (2 bytes per sample) ##
                framerate = 8000  ## Sample rate ##
                comptype = 'NONE'
                compname = 'not compressed'
                with wave.open(str(out_wav), 'wb') as wavfile:
                    wavfile.setparams((nchannels, sampwidth, framerate, 0, comptype, compname))
                    wavfile.writeframes(pcm_data)

if __name__ == '__main__':
    ##  takes the file name and parses the info ##
    pcap_file = sys.argv[1]
    # pcap_file = "m1k.pcapng"
    print("╔═════════════════════════════════════════════════╗")
    print("║   AudioCodes Debug Recording Audio Extraction   ║")
    print("╚═════════════════════════════════════════════════╝")
    user_input = input("Enter the AudioCodes Session ID or Leave blank to extract All: ")
    start = time.time()
    acdr = ACDRpcap2wav(pcap_file, user_input)
    acdr.tshark_check()
    acdr.gather_sessionids()
    acdr.extract_pcap_audio()
    end = time.time()
    total = end - start
    print(f"\nProcess completed in: {total} seconds.")
