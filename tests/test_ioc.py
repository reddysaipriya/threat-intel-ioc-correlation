import contextlib
import io
import os
import sys
import tempfile
import unittest
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ioc_correlate as ic  # noqa: E402

DATA = os.path.join(os.path.dirname(__file__), "..", "data")
AS_OF = date(2026, 3, 14)


def feed(*rows):
    """rows: (value, source, confidence, first, last)"""
    return [{"value": ic.normalize(v)[0], "type": ic.normalize(v)[1], "source": s, "confidence": c,
             "first_seen": date.fromisoformat(f), "last_seen": date.fromisoformat(l), "tags": []} for v, s, c, f, l in rows]


class NormaliseTests(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(ic.refang("hxxps://evil[.]example[:]8080/a"), "https://evil.example:8080/a")
        self.assertEqual(ic.refang("a[at]b(.)com"), "a@b.com")

    def test_classify(self):
        cases = {"203.0.113.9": "ip", "999.1.1.1": None, "Evil.Example.": "domain", "http://a.example/x": "url",
                 "d41d8cd98f00b204e9800998ecf8427e": "md5", "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1",
                 "a" * 64: "sha256", "bob@evil.example": "email", "not an ioc": None}
        for v, k in cases.items():
            self.assertEqual(ic.classify(v), k, v)

    def test_normalize(self):
        self.assertEqual(ic.normalize("HXXPS://Evil[.]Example.:443/Path/"), ("https://evil.example/Path", "url"))
        self.assertEqual(ic.normalize("203[.]0[.]113[.]99"), ("203.0.113.99", "ip"))
        self.assertEqual(ic.normalize("EXAMPLE.COM."), ("example.com", "domain"))


class MergeTests(unittest.TestCase):
    def test_duplicate_sources_raise_score_and_cap_at_100(self):
        m = ic.merge(feed(("203.0.113.9", "A", 70, "2026-03-01", "2026-03-10"), ("203.0.113.9", "B", 75, "2026-03-02", "2026-03-12")), AS_OF, 90)
        r = m[("ip", "203.0.113.9")]
        self.assertEqual((r["score"], r["sources"]), (85, {"A", "B"}))
        self.assertEqual((str(r["first_seen"]), str(r["last_seen"])), ("2026-03-01", "2026-03-12"))
        m = ic.merge(feed(("1.2.3.4", "A", 95, "2026-03-01", "2026-03-10"), ("1.2.3.4", "B", 95, "2026-03-01", "2026-03-10")), AS_OF, 90)
        self.assertEqual(m[("ip", "1.2.3.4")]["score"], 100)

    def test_stale(self):
        m = ic.merge(feed(("old.example", "A", 80, "2025-09-01", "2025-10-01")), AS_OF, 90)
        self.assertTrue(m[("domain", "old.example")]["stale"])
        m = ic.merge(feed(("new.example", "A", 80, "2026-03-01", "2026-03-10")), AS_OF, 90)
        self.assertFalse(m[("domain", "new.example")]["stale"])

    def test_load_feed_skips_junk(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write("indicator,type,source,confidence,first_seen,last_seen,tags\n"
                     "hxxp://bad[.]example/x,,S,notanumber,2026-03-01,,a|b\n,,S,50,,,\nnot an ioc,,S,50,,,\n")
        try:
            rows = ic.load_feed(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["value"], rows[0]["confidence"], rows[0]["tags"]), ("http://bad.example/x", 50, ["a", "b"]))


class CorrelationTests(unittest.TestCase):
    def iocs(self):
        return ic.merge(feed(("203.0.113.99", "A", 80, "2026-03-01", "2026-03-12"), ("evil.example", "A", 60, "2026-03-01", "2026-03-12"),
                             ("http://203.0.113.150/upload", "A", 55, "2026-03-01", "2026-03-12"), ("a" * 64, "A", 90, "2026-03-01", "2026-03-12")), AS_OF, 90)

    def run_logs(self, rows, allow=frozenset()):
        return ic.aggregate(self.iocs(), ic.correlate(self.iocs(), rows, set(allow)))

    def test_ip_match(self):
        r = self.run_logs([{"host": "H1", "dest_ip": "203.0.113.99", "action": "allowed"}])
        self.assertEqual((r[0]["indicator"], r[0]["severity"], r[0]["hosts"]), ("203.0.113.99", "high", ["H1"]))

    def test_subdomain_matches_but_lookalike_does_not(self):
        r = self.run_logs([{"host": "H1", "domain": "a.b.evil.example"}, {"host": "H2", "domain": "notevil.example"},
                           {"host": "H3", "domain": "evil.example.com"}])
        self.assertEqual([x["hosts"] for x in r], [["H1"]])

    def test_url_prefix_match_on_path_boundary_only(self):
        r = self.run_logs([{"host": "H1", "url": "http://203.0.113.150/upload/data?x=1"}, {"host": "H2", "url": "http://203.0.113.150/uploads"}])
        self.assertEqual([x["hosts"] for x in r], [["H1"]])

    def test_hash_match_case_insensitive(self):
        r = self.run_logs([{"host": "H1", "file_hash": ("A" * 64)}])
        self.assertEqual(r[0]["type"], "sha256")

    def test_blocked_is_downgraded(self):
        r = self.run_logs([{"host": "H1", "dest_ip": "203.0.113.99", "action": "blocked"}])
        self.assertEqual(r[0]["severity"], "medium")

    def test_stale_is_downgraded_and_noted(self):
        m = ic.merge(feed(("old.example", "A", 85, "2025-09-01", "2025-10-01")), AS_OF, 90)
        r = ic.aggregate(m, ic.correlate(m, [{"host": "H1", "domain": "old.example"}], set()))
        self.assertEqual(r[0]["severity"], "medium")
        self.assertTrue(r[0]["stale"] and r[0]["notes"])

    def test_allowlist_suppresses_ip_and_domain_and_subdomain(self):
        rows = [{"host": "H1", "dest_ip": "203.0.113.99"}, {"host": "H2", "domain": "evil.example"}, {"host": "H3", "domain": "x.evil.example"}]
        self.assertEqual(self.run_logs(rows, {"203.0.113.99", "evil.example"}), [])

    def test_one_row_counts_once_per_indicator(self):
        r = self.run_logs([{"host": "H1", "domain": "evil.example", "url": "http://evil.example/login"}])
        self.assertEqual(r[0]["matches"], 1)

    def test_host_with_two_indicators_is_correlated(self):
        r = self.run_logs([{"host": "H1", "dest_ip": "203.0.113.99"}, {"host": "H1", "domain": "evil.example"}, {"host": "H2", "domain": "evil.example"}])
        hc = ic.host_correlation(r)
        self.assertEqual([h["host"] for h in hc], ["H1"])

    def test_no_match_no_results(self):
        self.assertEqual(self.run_logs([{"host": "H1", "dest_ip": "93.184.216.34", "domain": "news.example.com"}]), [])


class ExtractTests(unittest.TestCase):
    def test_extract(self):
        found = set(ic.extract_iocs("C2 at 203[.]0[.]113[.]99 and hxxps://bad[.]example/x. Mail a@bad[.]example. Drop invoice.pdf and stage2.bin. "
                                    "Internal 10.0.0.5. Hash " + "b" * 64))
        self.assertIn(("ip", "203.0.113.99"), found)
        self.assertIn(("url", "https://bad.example/x"), found)
        self.assertIn(("email", "a@bad.example"), found)
        self.assertIn(("sha256", "b" * 64), found)
        self.assertNotIn(("ip", "10.0.0.5"), found)                 # private addresses are not IOCs
        self.assertFalse([f for f in found if f[1] in ("invoice.pdf", "stage2.bin")])   # file names are not domains


class SampleDataTests(unittest.TestCase):
    def test_story(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ic.main(["correlate", "--feed", os.path.join(DATA, "feed_osint.csv"), "--feed", os.path.join(DATA, "feed_vendor.csv"),
                            "--logs", os.path.join(DATA, "proxy_dns_logs.csv"), "--allowlist", os.path.join(DATA, "allowlist.txt"), "--as-of", "2026-03-14"])
        out = buf.getvalue()
        self.assertEqual(code, 1)                                    # high-severity matches exist
        self.assertIn("HIGH  ip  203.0.113.99", out)
        self.assertIn("score 85", out)                               # two sources raise 75 to 85
        self.assertIn("STALE", out)                                  # old-botnet-c2.example
        self.assertNotIn("cdn-assets.example", out.split("HOSTS WITH")[0].replace("suppressed", ""))   # allow-listed
        self.assertIn("FIN-LT-07", out.split("HOSTS WITH MORE")[1])
        self.assertIn("WS-ACCT-03", out.split("HOSTS WITH MORE")[1])


if __name__ == "__main__":
    unittest.main()
