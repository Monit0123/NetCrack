#!/usr/bin/env python3
"""Generate the synthetic sample capture shipped in Samples/.

The capture contains a *genuine* PMKID for a known passphrase, so the whole
pipeline can be exercised without touching a radio:

    SSID      NetCrack-Demo
    passphrase password1        (present in the bundled top-10k list)

Because the PMKID is actually computed with PBKDF2/HMAC-SHA1 rather than
randomised, hashcat really does recover "password1" from it. That makes the
sample a real end-to-end test of hcxtools + hashcat, not a mock.

The file also contains a synthetic 4-way handshake (M1/M2) with a placeholder
MIC. hcxtools will list an EAPOL pair as well; that pair will never crack, on
purpose, so you can see the difference between "a hash exists" and "the hash
is right".

    python3 Scripts/make_sample_capture.py
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "Samples"

SSID = "NetCrack-Demo"
PASSPHRASE = "password1"
AP_MAC = bytes.fromhex("021a2b3c4d5e")
STA_MAC = bytes.fromhex("8c8590aabbcc")
CHANNEL = 6
RADIOTAP = bytes.fromhex("0000080000000000")  # version 0, length 8, no flags

RSN_IE = bytes.fromhex(
    "3014"          # element id 48, length 20
    "0100"          # RSN version 1
    "000fac04"      # group cipher: CCMP
    "0100" "000fac04"  # 1 pairwise cipher: CCMP
    "0100" "000fac02"  # 1 AKM: PSK
    "0000"          # RSN capabilities
)


def pmk_and_pmkid() -> tuple[bytes, bytes]:
    pmk = hashlib.pbkdf2_hmac("sha1", PASSPHRASE.encode(), SSID.encode(), 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + AP_MAC + STA_MAC, hashlib.sha1).digest()[:16]
    return pmk, pmkid


def frame_control(flags: int, subtype: int = 0, type_: int = 0) -> bytes:
    fc0 = (subtype << 4) | (type_ << 2)
    return bytes([fc0, flags])


def mac(value: bytes) -> bytes:
    return value


def beacon(seq: int) -> bytes:
    header = frame_control(0x00, subtype=8, type_=0)
    header += b"\x00\x00"                       # duration
    header += b"\xff" * 6                        # DA broadcast
    header += mac(AP_MAC)                        # SA
    header += mac(AP_MAC)                        # BSSID
    header += struct.pack("<H", seq << 4)
    body = struct.pack("<Q", 0) + struct.pack("<H", 100) + struct.pack("<H", 0x0431)
    ssid_ie = bytes([0, len(SSID)]) + SSID.encode()
    rates = bytes([1, 4, 0x82, 0x84, 0x8B, 0x96])
    ds = bytes([3, 1, CHANNEL])
    return header + body + ssid_ie + rates + ds + RSN_IE


def data_frame(from_ds: bool, payload: bytes, seq: int) -> bytes:
    """802.11 data frame carrying an LLC/SNAP EAPOL payload."""
    flags = 0x02 if from_ds else 0x01  # FromDS or ToDS
    header = frame_control(flags, subtype=0, type_=2)
    header += b"\x00\x00"
    if from_ds:  # AP -> STA
        header += mac(STA_MAC)   # addr1 destination
        header += mac(AP_MAC)    # addr2 transmitter / BSSID
        header += mac(AP_MAC)    # addr3 source
    else:        # STA -> AP
        header += mac(AP_MAC)    # addr1 destination / BSSID
        header += mac(STA_MAC)   # addr2 transmitter
        header += mac(AP_MAC)    # addr3 destination
    header += struct.pack("<H", seq << 4)
    snap = bytes.fromhex("aaaa03000000") + b"\x88\x8e"
    return header + snap + payload


def eapol_key(
    key_info: int,
    replay: int,
    nonce: bytes,
    mic: bytes,
    key_data: bytes,
) -> bytes:
    body = bytearray()
    body += b"\x02"                 # descriptor type: RSN
    body += struct.pack(">H", key_info)
    body += struct.pack(">H", 16)   # key length
    body += struct.pack(">Q", replay)
    body += nonce                   # 32 bytes
    body += b"\x00" * 16            # key IV
    body += b"\x00" * 8             # key RSC
    body += b"\x00" * 8             # key ID / reserved
    body += mic                     # 16 bytes
    body += struct.pack(">H", len(key_data))
    body += key_data
    return b"\x02\x03" + struct.pack(">H", len(body)) + bytes(body)


def message_1(anonce: bytes, pmkid: bytes, replay: int = 1) -> bytes:
    key_info = 0x008A  # version 2, pairwise, ACK
    kde = bytes.fromhex("dd14000fac04") + pmkid  # vendor-specific KDE
    return eapol_key(key_info, replay, anonce, b"\x00" * 16, kde)


def message_2(snonce: bytes, replay: int = 1) -> bytes:
    key_info = 0x010A  # version 2, pairwise, MIC
    placeholder_mic = hashlib.sha1(b"netcrack-sample" + snonce).digest()[:16]
    return eapol_key(key_info, replay, snonce, placeholder_mic, b"")


def pcap(frames: list[bytes]) -> bytes:
    out = bytearray()
    out += bytes.fromhex("d4c3b2a1")            # magic, little endian
    out += struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 127)  # linktype 127 = radiotap
    timestamp = 1_700_000_000
    for index, frame in enumerate(frames):
        data = RADIOTAP + frame
        out += struct.pack("<IIII", timestamp + index // 10, (index % 10) * 100_000, len(data), len(data))
        out += data
    return bytes(out)


def main() -> None:
    SAMPLES.mkdir(exist_ok=True)
    _, pmkid = pmk_and_pmkid()
    anonce = hashlib.sha1(b"anonce").digest() + hashlib.sha1(b"anonce2").digest()[:12]
    snonce = hashlib.sha1(b"snonce").digest() + hashlib.sha1(b"snonce2").digest()[:12]

    frames: list[bytes] = []
    # A few beacons so hcxtools can map the BSSID to an SSID.
    for seq in range(4):
        frames.append(beacon(seq))
    # M1 (AP -> STA) carries the PMKID; M2 (STA -> AP) completes a pair.
    frames.append(data_frame(True, message_1(anonce, pmkid), 10))
    frames.append(data_frame(False, message_2(snonce), 11))
    for seq in range(12, 16):
        frames.append(beacon(seq))

    pcap_path = SAMPLES / "netcrack-demo.pcap"
    pcap_path.write_bytes(pcap(frames))

    # The same hash in the 22000 format hcxpcapngtool would produce.
    hash_line = "WPA*01*{pmkid}*{ap}*{sta}*{ssid}***".format(
        pmkid=pmkid.hex(),
        ap=AP_MAC.hex(),
        sta=STA_MAC.hex(),
        ssid=SSID.encode().hex(),
    )
    hash_path = SAMPLES / "netcrack-demo.22000"
    hash_path.write_text(hash_line + "\n", encoding="utf-8")

    wordlist_path = SAMPLES / "netcrack-demo.passphrase.txt"
    wordlist_path.write_text(PASSPHRASE + "\n", encoding="utf-8")

    print(f"wrote {pcap_path.relative_to(ROOT)} ({pcap_path.stat().st_size} bytes, {len(frames)} frames)")
    print(f"wrote {hash_path.relative_to(ROOT)}: {hash_line}")
    print("PMKID verified by construction: HMAC-SHA1(PMK, 'PMK Name'||AP||STA)[0:16]")
    print(f"passphrase: {PASSPHRASE} (line 621 of the bundled top-10k list)")


if __name__ == "__main__":
    main()
