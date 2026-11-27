#!/usr/bin/env python3
"""Generate SYNTHETIC feeds, allow-list, logs and a threat-report excerpt.

Everything is made up. IPs come from documentation ranges (RFC 5737) or private
ranges; domains use the reserved ".example" TLD (they can never resolve); the
"malware hash" is the SHA-256 of a harmless text string.
"""
import csv
import hashlib
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "data")
os.makedirs(OUT, exist_ok=True)
rng = random.Random(11)

BAD_HASH = hashlib.sha256(b"DEMO PLACEHOLDER FILE - NOT MALWARE").hexdigest()
FEED_COLS = ["indicator", "type", "source", "confidence", "first_seen", "last_seen", "tags"]

osint = [
    ["203.0.113.99", "", "OSINT-demo", 70, "2026-03-01", "2026-03-12", "c2"],
    ["qxkzpwd3.example", "", "OSINT-demo", 60, "2026-03-05", "2026-03-13", "dga|malware"],
    ["micr0soft-account-verify.example", "", "OSINT-demo", 85, "2026-03-10", "2026-03-13", "phishing"],
    ["hxxp://203[.]0[.]113[.]150/upload", "", "OSINT-demo", 55, "2026-03-08", "2026-03-11", "exfiltration"],
    ["old-botnet-c2.example", "", "OSINT-demo", 80, "2025-09-01", "2025-10-01", "botnet"],
    ["198.51.100.7", "", "OSINT-demo", 40, "2026-03-09", "2026-03-10", "scanner"],
]
vendor = [
    ["203.0.113.99", "ip", "Vendor-demo", 75, "2026-03-02", "2026-03-13", "c2"],
    [BAD_HASH, "sha256", "Vendor-demo", 90, "2026-03-11", "2026-03-13", "malware"],
    ["micr0soft-account-verify.example", "domain", "Vendor-demo", 90, "2026-03-11", "2026-03-13", "phishing"],
    ["cdn-assets.example", "domain", "Vendor-demo", 30, "2026-03-01", "2026-03-12", "shared-hosting"],   # a noisy entry on purpose
]
for name, rows in (("feed_osint.csv", osint), ("feed_vendor.csv", vendor)):
    with open(os.path.join(OUT, name), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(FEED_COLS)
        w.writerows(rows)

with open(os.path.join(OUT, "allowlist.txt"), "w") as fh:
    fh.write("# Values that must never alert (known-good infrastructure)\ncdn-assets.example   # company CDN, a shared-hosting entry in a feed would otherwise cause noise\n8.8.8.8   # public DNS resolver\n")

LOG_COLS = ["time", "host", "src_ip", "dest_ip", "domain", "url", "file_hash", "action"]
L = []


def row(t, host, src, dest="", domain="", url="", fh="", action="allowed"):
    L.append(["2026-03-14T" + t, host, src, dest, domain, url, fh, action])


# benign background
for i in range(40):
    h, ip = rng.choice([("WS-ACCT-01", "10.0.0.34"), ("WS-HR-01", "10.0.0.40"), ("WS-IT-01", "10.0.1.10"), ("WS-DEV-02", "10.0.6.22")])
    d = rng.choice(["news.example.com", "mail.example.com", "docs.example.com", "update.example.com"])
    row("%02d:%02d:%02d" % (rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59)), h, ip, "93.184.216.34", d, "https://%s/index" % d)
row("09:12:00", "WS-IT-01", "10.0.1.10", "8.8.8.8", "dns.google.example")                          # allow-listed IP

# the story
row("11:42:19", "FIN-LT-07", "10.0.3.41", "203.0.113.99", "", "")                                   # C2 IP (two feeds)
row("11:42:25", "FIN-LT-07", "10.0.3.41", "", "", "", BAD_HASH)                                     # downloaded the bad file
for i in range(20):
    row("13:%02d:%02d" % (25 + i // 4, (i * 13) % 60), "WS-ACCT-03", "10.0.3.18", "", ("sub%d." % i if i % 5 == 0 else "") + "qxkzpwd3.example")
row("13:30:10", "WS-ACCT-03", "10.0.3.18", "203.0.113.99", "")                                      # same C2 IP, second host
row("09:15:02", "HR-PC-02", "10.0.0.44", "", "micr0soft-account-verify.example", "http://micr0soft-account-verify.example/login", "", "blocked")
row("03:40:00", "FILESRV-02", "10.0.2.20", "203.0.113.150", "", "http://203.0.113.150/upload/data", "")  # exfil URL, path-prefix match
row("16:05:00", "LAB-PC-05", "10.0.9.31", "", "old-botnet-c2.example")                             # stale indicator
row("10:10:10", "WS-DEV-01", "10.0.6.10", "", "cdn-assets.example", "https://cdn-assets.example/lib.js")   # allow-listed, must not alert
row("02:10:01", "web-01", "198.51.100.7", "10.0.0.5", "", "", "", "denied")                         # inbound scanner (src_ip match, blocked)

L.sort(key=lambda r: r[0])
with open(os.path.join(OUT, "proxy_dns_logs.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(LOG_COLS)
    w.writerows(L)

with open(os.path.join(OUT, "threat_report_excerpt.txt"), "w") as fh:
    fh.write("""SYNTHETIC THREAT REPORT EXCERPT (made up for practice)

The campaign delivers a document named Invoice_March.docm. After the macro runs, the host contacts the
command-and-control server at 203[.]0[.]113[.]99 over HTTPS and downloads a second stage from
hxxps://payload-host[.]example/stage2.bin (SHA-256 %s).
Victims were sent mail from billing@micr0soft-account-verify[.]example and shown a fake login page at
micr0soft-account-verify[.]example/login. Internal host 10.0.3.41 was the first to beacon.
Data was staged in C:\\Temp\\data.7z and uploaded to http://203.0.113.150/upload. Analysts should also review
traffic to old-botnet-c2[.]example, which was seen in earlier activity.
""" % BAD_HASH)
print("Sample data written to", os.path.abspath(OUT))
