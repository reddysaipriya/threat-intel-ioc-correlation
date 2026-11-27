# Threat Intelligence & IOC Correlation

A small Python tool that answers the question threat intelligence exists for: **"Did any of our hosts touch a known-bad indicator, how reliable is that indicator, and which hosts show more than one?"**

It loads **IOC feeds**, matches them against **proxy / DNS / firewall logs**, scores and ages the indicators, suppresses known-good noise with an **allow-list**, and ranks hosts that hit **several** indicators.

> **Learning project.** All feeds, logs and the "threat report" are **synthetic**. IPs come from documentation ranges (RFC 5737) or private ranges, domains use the reserved `.example` TLD, and the "malware hash" is the SHA-256 of a harmless text string. Python 3.9+, no dependencies, offline.

## What it does

| Feature | Details |
|---|---|
| **Indicator types** | IPv4, domains, URLs, MD5 / SHA-1 / SHA-256, e-mail addresses |
| **Normalisation** | Removes defanging (`hxxp`, `[.]`, `[at]`), lower-cases, strips trailing dots and default ports |
| **Multi-feed merge** | Duplicate indicators from several feeds become one record; more sources raise the score |
| **Smart matching** | Subdomains match their parent domain (but look-alikes do not); URLs match on a path prefix; URL hosts are also checked against domain and IP indicators |
| **Aging** | Indicators not seen for 90+ days are marked **STALE** and downgraded |
| **Allow-list** | Known-good values never alert (and so do their subdomains) |
| **Severity** | From score, lowered one level if every attempt was **blocked** and one level if **stale** |
| **Host correlation** | Lists hosts hitting two or more distinct indicators first |
| **Extractor** | Pulls IOCs out of free text (even defanged) into feed-style CSV |

## Quick start

```bash
git clone https://github.com/reddysaipriya/threat-intel-ioc-correlation.git
cd threat-intel-ioc-correlation

python3 ioc_correlate.py correlate \
  --feed data/feed_osint.csv --feed data/feed_vendor.csv \
  --logs data/proxy_dns_logs.csv \
  --allowlist data/allowlist.txt \
  --as-of 2026-03-14
```

Other commands:

```bash
# extract indicators from a report into a feed-style CSV
python3 ioc_correlate.py extract data/threat_report_excerpt.txt --source MyReport --confidence 60 > new_feed.csv

# see how one indicator is cleaned and classified
python3 ioc_correlate.py normalize 'hxxps://Evil[.]Example.:443/Path/'
```

`--as-of` fixes the date used for aging (so results are repeatable). The exit code is `1` if any **high**-severity match exists.

## File formats

**Feed CSV:** `indicator,type,source,confidence,first_seen,last_seen,tags` (type is optional and detected automatically; dates are `YYYY-MM-DD`; tags are separated by `|`).

**Log CSV:** `time,host,src_ip,dest_ip,domain,url,file_hash,action` (`action` is `allowed`, `blocked` or `denied`).

**Allow-list:** one value per line; `#` starts a comment.

## Example output (from the sample data, excerpt)

```text
IOC CORRELATION REPORT
As of 2026-03-14 | indicators loaded: 8 | log rows: 69 | IOCs matched: 7 | suppressed by allow-list: 1

[1] HIGH  sha256  759b5fb3...f898c3e   score 90
    hosts: FIN-LT-07   matches: 1   actions: allowed

[2] HIGH  ip  203.0.113.99   score 85
    sources: OSINT-demo, Vendor-demo   tags: c2
    hosts: FIN-LT-07, WS-ACCT-03   matches: 2   actions: allowed

[3] MEDIUM  domain  micr0soft-account-verify.example   score 100
    hosts: HR-PC-02   matches: 1   actions: blocked
    note: all attempts were blocked (control worked), still review the host

[4] MEDIUM  domain  old-botnet-c2.example   score 80
    note: indicator is STALE (last seen 164 days ago): verify before acting
...
HOSTS WITH MORE THAN ONE INDICATOR (prioritise these)
  FIN-LT-07: sha256 759b5fb3... [high]; ip 203.0.113.99 [high]
  WS-ACCT-03: ip 203.0.113.99 [high]; domain qxkzpwd3.example [medium]
```

## What the sample data teaches

| Situation | What the tool does |
|---|---|
| The same C2 IP is in two feeds (confidence 70 and 75) | Combines them into **score 85** and shows both hosts that contacted it |
| A phishing domain (score 100) was only reached through a **blocked** request | Downgraded to **medium**, with a note |
| An indicator last seen 164 days ago matches | Downgraded and marked **STALE** |
| A noisy feed entry (`cdn-assets.example`) is also on the allow-list | **Suppressed** and counted |
| A log shows `sub5.qxkzpwd3.example` | Matches the parent domain indicator |
| A defanged URL in the feed (`hxxp://203[.]0[.]113[.]150/upload`) and a log URL `.../upload/data` | Cleaned, then matched on a path prefix |
| Two different indicators hit the same laptop | Listed under **hosts with more than one indicator** |

## Project layout

```text
ioc_correlate.py            correlate / extract / normalize
data/                       synthetic feeds, allow-list, logs and a report excerpt
tools/generate_samples.py   builds the sample data (fixed seed)
docs/ioc-hygiene.md         how to use threat intelligence without noise
tests/test_ioc.py           18 unit tests
```

## Tests

```bash
python3 -m unittest discover -s tests
```

They cover normalisation and classification, feed merging and score capping, staleness, every matching rule (including look-alike domains and path boundaries that must **not** match), blocked-versus-allowed severity, the allow-list, double-count protection, host correlation, the extractor, and the full sample story.

## Limitations (honest list)

- IPv4 only (no IPv6), and domain parsing is simple (no public-suffix list).
- Confidence scores are **taken from the feeds** plus a simple multi-source bonus. They are not independently verified.
- No live lookups (VirusTotal, WHOIS, passive DNS). Enrichment is up to you.
- It reads CSV logs, not raw proxy, DNS or firewall formats.
- A match shows **contact** with a bad indicator, not compromise. Always check what the host did next.

## Ideas for next steps

- Add IPv6 and CIDR-range indicators.
- Read STIX/TAXII or MISP exports.
- Optional enrichment (reputation, domain age) behind a flag.
- Keep match history to show how long a host has been talking to an indicator.

## License

MIT, see [LICENSE](LICENSE).
