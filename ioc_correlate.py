#!/usr/bin/env python3
"""Threat Intelligence & IOC Correlation

Takes indicator-of-compromise (IOC) feeds and your own logs and answers:
"Did any of our hosts touch a known-bad indicator, how reliable is that
indicator, and which hosts show MORE than one?"

  correlate   match feeds against proxy/DNS/firewall logs
  extract     pull IOCs out of free text (handles defanged text like hxxp://1[.]2[.]3[.]4)
  normalize   show how a single indicator is cleaned up and classified

Handles: IPv4, domains (with subdomain matching), URLs (path-prefix matching),
MD5/SHA-1/SHA-256, e-mail addresses. Offline, no dependencies.
Learning project: use synthetic data for practice.
"""
import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

__version__ = "1.0.0"

FILE_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "exe", "dll", "txt", "zip", "rar", "png", "jpg", "jpeg", "gif",
            "js", "html", "htm", "php", "py", "sh", "bat", "ps1", "log", "csv", "json", "xml", "iso", "lnk", "docm", "xlsm", "msi", "tmp",
            "bin", "dat", "db", "cfg", "conf", "ini", "so", "jar", "7z", "gz", "tar", "img", "vbs", "scr", "hta", "wsf", "sys", "bak", "md", "yml", "yaml", "pyc", "dmp"}
LEVELS = ["low", "medium", "high"]

# --------------------------------------------------------------------------
# normalisation and classification
# --------------------------------------------------------------------------

_REFANG = [
    (re.compile(r"hxxp", re.I), "http"), (re.compile(r"\[:\]|\(:\)"), ":"), (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."), (re.compile(r"\[at\]|\(at\)|\[@\]", re.I), "@"),
]


def refang(text: str) -> str:
    """Undo the 'defanging' analysts use to make indicators safe to share."""
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


def valid_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"))


_HEX = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_EMAIL = re.compile(r"^[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}$")


def classify(value: str) -> Optional[str]:
    v = refang(value.strip()).lower()
    if v.startswith(("http://", "https://")):
        return "url"
    if valid_ipv4(v):
        return "ip"
    if re.fullmatch(r"[0-9a-f]+", v) and len(v) in _HEX:
        return _HEX[len(v)]
    if _EMAIL.match(v):
        return "email"
    if _DOMAIN.match(v.rstrip(".")):
        return "domain"
    return None


def normalize(value: str, kind: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Return (clean value, type). Lower-cases, removes defanging, trailing dots, default ports."""
    v = refang(value.strip())
    kind = kind or classify(v)
    if kind in ("ip", "md5", "sha1", "sha256", "email"):
        return v.lower(), kind
    if kind == "domain":
        return v.lower().rstrip("."), kind
    if kind == "url":
        p = urlparse(v)
        host = (p.hostname or "").lower().rstrip(".")
        port = "" if (p.port in (None, 80, 443)) else ":%d" % p.port
        path = p.path or ""
        q = ("?" + p.query) if p.query else ""
        return "%s://%s%s%s%s" % (p.scheme.lower(), host, port, path.rstrip("/") if path != "/" else "", q), kind
    return v, kind


# --------------------------------------------------------------------------
# feeds
# --------------------------------------------------------------------------

def parse_date(s: str) -> Optional[date]:
    try:
        return datetime.strptime((s or "").strip()[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def load_feed(path: str) -> List[Dict]:
    out = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            raw = (r.get("indicator") or "").strip()
            if not raw or raw.startswith("#"):
                continue
            value, kind = normalize(raw, (r.get("type") or "").strip().lower() or None)
            if not kind:
                continue
            try:
                conf = max(0, min(100, int(float(r.get("confidence") or 50))))
            except ValueError:
                conf = 50
            first = parse_date(r.get("first_seen", ""))
            last = parse_date(r.get("last_seen", "")) or first
            out.append({"value": value, "type": kind, "source": (r.get("source") or path).strip(), "confidence": conf,
                        "first_seen": first, "last_seen": last,
                        "tags": [t.strip() for t in (r.get("tags") or "").replace(";", "|").split("|") if t.strip()]})
    return out


def merge(entries: Iterable[Dict], as_of: date, max_age_days: int) -> Dict[Tuple[str, str], Dict]:
    """Combine duplicate indicators from several feeds into one record."""
    merged: Dict[Tuple[str, str], Dict] = {}
    for e in entries:
        m = merged.setdefault((e["type"], e["value"]), {"type": e["type"], "value": e["value"], "sources": set(), "confidence": 0,
                                                         "tags": set(), "first_seen": None, "last_seen": None})
        m["sources"].add(e["source"])
        m["confidence"] = max(m["confidence"], e["confidence"])
        m["tags"].update(e["tags"])
        if e["first_seen"] and (m["first_seen"] is None or e["first_seen"] < m["first_seen"]):
            m["first_seen"] = e["first_seen"]
        if e["last_seen"] and (m["last_seen"] is None or e["last_seen"] > m["last_seen"]):
            m["last_seen"] = e["last_seen"]
    for m in merged.values():
        m["score"] = min(100, m["confidence"] + 10 * (len(m["sources"]) - 1))
        age = (as_of - m["last_seen"]).days if m["last_seen"] else None
        m["age_days"] = age
        m["stale"] = age is not None and age > max_age_days
    return merged


# --------------------------------------------------------------------------
# allow-list
# --------------------------------------------------------------------------

def load_allowlist(path: Optional[str]) -> Set[str]:
    if not path:
        return set()
    with open(path, encoding="utf-8") as fh:
        return {normalize(l.split("#")[0].strip())[0] for l in fh if l.split("#")[0].strip()}


def domain_suffixes(domain: str) -> List[str]:
    parts = domain.lower().strip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]       # a.b.c -> a.b.c, b.c (not the bare TLD)


def allowlisted(value: str, allow: Set[str]) -> bool:
    if value in allow:
        return True
    return any(s in allow for s in domain_suffixes(value)) if not valid_ipv4(value) else False


# --------------------------------------------------------------------------
# correlation
# --------------------------------------------------------------------------

def url_host(u: str) -> str:
    return (urlparse(refang(u)).hostname or "").lower()


def correlate(iocs: Dict[Tuple[str, str], Dict], log_rows: Iterable[Dict[str, str]], allow: Set[str]) -> List[Dict]:
    by_type: Dict[str, Dict[str, Dict]] = defaultdict(dict)
    for (t, v), m in iocs.items():
        by_type[t][v] = m
    hits: List[Dict] = []
    seen: Set[Tuple[Tuple[str, str], int]] = set()      # one match per indicator per log row
    current = [0]

    def hit(m, row, field, value):
        key = ((m["type"], m["value"]), current[0])
        if key in seen:
            return
        seen.add(key)
        hits.append({"ioc": (m["type"], m["value"]), "field": field, "log_value": value, "host": (row.get("host") or "").strip(),
                     "time": (row.get("time") or "").strip(), "action": (row.get("action") or "allowed").strip().lower()})

    for idx, row in enumerate(log_rows):
        current[0] = idx
        # IPs
        for field in ("dest_ip", "src_ip"):
            v = (row.get(field) or "").strip()
            if v and v in by_type["ip"] and not allowlisted(v, allow):
                hit(by_type["ip"][v], row, field, v)
        # domains (exact or any parent domain) from the domain column and from URL hosts
        doms = []
        d = normalize(row.get("domain") or "")[0]
        if d:
            doms.append(("domain", d))
        u = (row.get("url") or "").strip()
        if u:
            h = url_host(u)
            if h:
                doms.append(("url_host", h))
        for field, dom in doms:
            if allowlisted(dom, allow):
                continue
            if valid_ipv4(dom):
                if dom in by_type["ip"]:
                    hit(by_type["ip"][dom], row, field, dom)
                continue
            for s in domain_suffixes(dom):
                if s in by_type["domain"]:
                    hit(by_type["domain"][s], row, field, dom)
                    break
        # URLs: IOC url equals the log url or is a path-prefix of it
        if u:
            nu = normalize(u, "url")[0]
            for iv, m in by_type["url"].items():
                if nu == iv or nu.startswith(iv + "/") or nu.startswith(iv + "?"):
                    hit(m, row, "url", nu)
        # hashes
        fh = (row.get("file_hash") or "").strip().lower()
        if fh:
            kind = classify(fh)
            if kind in ("md5", "sha1", "sha256") and fh in by_type[kind]:
                hit(by_type[kind][fh], row, "file_hash", fh)
    return hits


def severity(m: Dict, actions: Set[str]) -> Tuple[str, List[str]]:
    sc = m["score"]
    level = 2 if sc >= 80 else 1 if sc >= 50 else 0
    notes = []
    if actions and actions <= {"blocked", "denied", "dropped"}:
        level -= 1
        notes.append("all attempts were blocked (control worked), still review the host")
    if m["stale"]:
        level -= 1
        notes.append("indicator is STALE (last seen %d days ago): verify before acting" % m["age_days"])
    return LEVELS[max(level, 0)], notes


def aggregate(iocs: Dict[Tuple[str, str], Dict], hits: List[Dict]) -> List[Dict]:
    grouped: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for h in hits:
        grouped[h["ioc"]].append(h)
    out = []
    for key, hs in grouped.items():
        m = iocs[key]
        actions = {h["action"] for h in hs}
        sev, notes = severity(m, actions)
        times = sorted(h["time"] for h in hs if h["time"])
        out.append({"type": m["type"], "indicator": m["value"], "severity": sev, "score": m["score"], "sources": sorted(m["sources"]),
                    "tags": sorted(m["tags"]), "hosts": sorted({h["host"] for h in hs if h["host"]}), "matches": len(hs),
                    "first": times[0] if times else "", "last": times[-1] if times else "", "actions": sorted(actions),
                    "stale": m["stale"], "notes": notes})
    out.sort(key=lambda r: (-LEVELS.index(r["severity"]), -r["score"], r["indicator"]))
    return out


def host_correlation(results: List[Dict]) -> List[Dict]:
    per_host: Dict[str, List[Dict]] = defaultdict(list)
    for r in results:
        for h in r["hosts"]:
            per_host[h].append(r)
    rows = [{"host": h, "indicators": [(r["type"], r["indicator"], r["severity"]) for r in rs]} for h, rs in per_host.items() if len(rs) >= 2]
    rows.sort(key=lambda x: -len(x["indicators"]))
    return rows


# --------------------------------------------------------------------------
# extraction from text
# --------------------------------------------------------------------------

def extract_iocs(text: str) -> List[Tuple[str, str]]:
    t = refang(text)
    found: Dict[Tuple[str, str], None] = {}

    def add(raw):
        v, k = normalize(raw)
        if not k:
            return
        if k == "ip" and is_private(v):
            return
        if k == "domain" and v.rsplit(".", 1)[-1] in FILE_EXT:
            return
        found[(k, v)] = None

    for u in re.findall(r"https?://[^\s\"'<>)\]]+", t, re.I):
        add(u.rstrip(".,;"))
    for h in re.findall(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])", t):
        add(h)
    for m in re.findall(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}", t):
        add(m)
    for ip in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", t):
        add(ip)
    for d in re.findall(r"(?<![\w@.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])", t):
        if not valid_ipv4(d):
            add(d)
    order = {"url": 0, "ip": 1, "domain": 2, "email": 3, "md5": 4, "sha1": 5, "sha256": 6}
    return sorted(found, key=lambda kv: (order.get(kv[0], 9), kv[1]))


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def render(results: List[Dict], hosts: List[Dict], n_iocs: int, n_rows: int, suppressed: int, as_of: date) -> str:
    L = ["IOC CORRELATION REPORT", "=" * 64,
         "As of %s | indicators loaded: %d | log rows: %d | IOCs matched: %d | suppressed by allow-list: %d" % (as_of, n_iocs, n_rows, len(results), suppressed), ""]
    if not results:
        L.append("No indicator matches.")
    for i, r in enumerate(results, 1):
        L += ["[%d] %s  %s  %s   score %d" % (i, r["severity"].upper(), r["type"], r["indicator"], r["score"]),
              "    sources: %s   tags: %s" % (", ".join(r["sources"]), ", ".join(r["tags"]) or "-"),
              "    hosts: %s   matches: %d   actions: %s" % (", ".join(r["hosts"]) or "-", r["matches"], ", ".join(r["actions"])),
              "    first/last: %s -> %s" % (r["first"] or "-", r["last"] or "-")]
        L += ["    note: " + n for n in r["notes"]]
        L.append("")
    if hosts:
        L += ["HOSTS WITH MORE THAN ONE INDICATOR (prioritise these)", "-" * 64]
        for h in hosts:
            L.append("  %s: %s" % (h["host"], "; ".join("%s %s [%s]" % x for x in h["indicators"])))
        L.append("")
    L += ["Reminder: an IOC match shows contact with a known-bad indicator, not proof of compromise. Check what the host did next.", ""]
    return "\n".join(L)


def read_rows(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Correlate IOC feeds with logs; extract and normalise indicators.")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("correlate", help="match feeds against logs")
    c.add_argument("--feed", action="append", required=True, help="IOC feed CSV (repeatable)")
    c.add_argument("--logs", required=True, help="log CSV: time,host,src_ip,dest_ip,domain,url,file_hash,action")
    c.add_argument("--allowlist", help="text file of values that must never alert")
    c.add_argument("--as-of", default=date.today().isoformat(), help="date used to judge staleness (default today)")
    c.add_argument("--max-age", type=int, default=90, help="days after which an indicator is stale (default 90)")
    c.add_argument("--json", metavar="FILE")
    e = sub.add_parser("extract", help="pull IOCs from a text file into feed-style CSV")
    e.add_argument("file")
    e.add_argument("--source", default="extracted")
    e.add_argument("--confidence", type=int, default=50)
    e.add_argument("--date", default=date.today().isoformat())
    n = sub.add_parser("normalize", help="clean and classify one indicator")
    n.add_argument("value")
    a = p.parse_args(argv)

    if a.cmd == "normalize":
        v, k = normalize(a.value)
        print("%s  (%s)" % (v, k or "unrecognised"))
        return 0 if k else 1
    if a.cmd == "extract":
        with open(a.file, encoding="utf-8", errors="replace") as fh:
            items = extract_iocs(fh.read())
        w = csv.writer(sys.stdout, lineterminator="\n")
        w.writerow(["indicator", "type", "source", "confidence", "first_seen", "last_seen", "tags"])
        for k, v in items:
            w.writerow([v, k, a.source, a.confidence, a.date, a.date, "extracted"])
        return 0

    as_of = parse_date(a.as_of) or date.today()
    entries = [x for f in a.feed for x in load_feed(f)]
    iocs = merge(entries, as_of, a.max_age)
    allow = load_allowlist(a.allowlist)
    rows = read_rows(a.logs)
    hits = correlate(iocs, rows, allow)
    # count how many matches the allow-list removed
    suppressed = len(correlate(iocs, rows, set())) - len(hits)
    results = aggregate(iocs, hits)
    hosts = host_correlation(results)
    print(render(results, hosts, len(iocs), len(rows), suppressed, as_of))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"as_of": str(as_of), "results": results, "hosts_with_multiple_indicators": hosts}, fh, indent=2)
        print("JSON written to " + a.json)
    return 1 if any(r["severity"] == "high" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
