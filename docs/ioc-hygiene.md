# IOC hygiene: using threat intelligence without drowning in noise

An **indicator of compromise (IOC)** is a clue that something bad happened or may happen: an IP, domain, URL, file hash or e-mail address linked to an attack. Feeds give you thousands. Used badly, they flood analysts with false positives. These are the habits this project builds in.

## 1. Know how strong each type of indicator is (Pyramid of Pain)

| Indicator | Cost to the attacker to change it | Notes |
|---|---|---|
| File hash | Trivial (change one byte) | Precise but short-lived |
| IP address | Easy | Can be shared hosting, so check before blocking |
| Domain name | Moderate | Cheap to register, but takes some effort |
| URL | Moderate | More specific than a domain |
| **Behavior (TTPs)** | **Hard** | Best for detection, and not something an IOC feed can express |

IOC matching finds known infrastructure. It does not replace behavioral detection.

## 2. Normalise before you compare

Indicators are shared "defanged" so nobody clicks them by accident, and written in different styles.

| As written | Clean form |
|---|---|
| `hxxps://Evil[.]Example.:443/Path/` | `https://evil.example/Path` |
| `203[.]0[.]113[.]99` | `203.0.113.99` |
| `EXAMPLE.COM.` | `example.com` |
| `a[at]bad[.]example` | `a@bad.example` |

Without this step, the same indicator in two feeds looks like two different things and a match is missed.

## 3. Score reliability, do not just match

This project combines feeds like this:

- **Confidence** comes from the feed (0 to 100).
- **More independent sources raise it:** `score = min(100, highest confidence + 10 per extra source)`.
- **Score maps to severity:** 80+ high, 50+ medium, below that low.

## 4. Age your indicators

Attackers abandon infrastructure, and the IP of a past botnet may belong to an innocent customer today. Any indicator not seen for more than 90 days (adjustable) is marked **STALE**, downgraded and flagged "verify before acting".

## 5. Match the way the data really looks

| Type | Matching rule here |
|---|---|
| IP | Exact (destination or source address) |
| Domain | Exact **or any subdomain** (`a.b.evil.example` matches `evil.example`), but `notevil.example` and `evil.example.com` do **not** |
| URL | Exact, or the IOC is a **path prefix** (`/upload` matches `/upload/data` but not `/uploads`) |
| Hash | Exact, case-insensitive |

URL hosts in logs are also checked against domain and IP indicators, and each log row counts once per indicator.

## 6. Keep an allow-list

Feeds sometimes contain shared or popular infrastructure (a CDN, a public resolver). Without an allow-list those entries alert forever. Keep a short, **reviewed** list with a comment for each entry.

## 7. A match is a lead, not a verdict

1. Was the connection **allowed or blocked**? A blocked attempt shows the control worked, but the host still tried.
2. **What did the host do next?** (new processes, more connections, file creation)
3. **Is more than one indicator hitting the same host?** Two different indicator types on one machine is a much stronger signal than one. The report ranks these hosts first.
4. **Is the indicator stale or low-confidence?** Verify before you block or isolate anything.
5. Record your decision and **feed back** wrong indicators so the feed owner can fix them.

## 8. Share safely

- Defang indicators in tickets and chat.
- Mark sharing limits (TLP) on anything sensitive.
- Never upload private files to public services. Search by hash instead.
