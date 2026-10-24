# Sample capture

Synthetic frames for a fictional network, used to prove the pipeline without
touching a radio.

| File | What it is |
|---|---|
| `netcrack-demo.pcap` | Radiotap 802.11 capture: 8 beacons, an EAPOL-Key M1 carrying a **genuine** PMKID, and a matching M2 |
| `netcrack-demo.22000` | The same PMKID in hashcat's 22000 format (`hcxpcapngtool` produces exactly this line) |
| `netcrack-demo.passphrase.txt` | The passphrase, for test scripts |

```
SSID        NetCrack-Demo
BSSID       02:1a:2b:3c:4d:5e
client      8c:85:90:aa:bb:cc
channel     6
passphrase  password1        (line 621 of NetCrack/Resources/top10k.txt)
```

The PMKID is computed, not randomised:

```
PMK   = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32)
PMKID = HMAC-SHA1(PMK, "PMK Name" || MAC_AP || MAC_STA)[0:16]
```

so `hashcat -m 22000` really cracks it. The M1/M2 pair also carries a
placeholder MIC, so hcxtools may report an EAPOL hash as well — that one is
deliberately uncrackable, which is a useful demonstration of the difference
between "a hash exists" and "the hash is correct".

Rebuild both files with:

```bash
python3 Scripts/make_sample_capture.py
```
