import os
import tempfile
import time

os.environ["GUARDIAN_HOME"] = tempfile.mkdtemp()
os.environ["GUARDIAN_NO_FEED"] = "1"

import pytest

from guardian import phase2, reputation as rep


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    rep._cache.clear()
    rep._bad_hosts.clear()
    rep.phishtank.keys, rep.phishtank.loaded = frozenset(), True
    monkeypatch.setattr(rep.config, "PHASE2_TIMEOUT", 0.5)


def fake(result, delay=0):
    def f(url):
        time.sleep(delay)
        if isinstance(result, Exception):
            raise result
        return result
    return f


def test_phishtank_feed_match():
    rep.phishtank.load("phish_id,url,x\n1,http://Bad.example/login?id=1,y\n2,http://worse.example/,y\n")
    assert rep.phishtank.contains("http://bad.example/login?id=1")
    assert rep.phishtank.contains("http://worse.example")
    assert not rep.phishtank.contains("http://bad.example/other")


def test_any_source_flagging_means_malicious(monkeypatch):
    monkeypatch.setattr(rep, "_gsb", fake(False))
    monkeypatch.setattr(rep, "_vt", fake(True))
    v = phase2.analyze("http://x.example/a")
    assert v.action == "block" and "VirusTotal" in v.sources


def test_not_found_anywhere_is_warning(monkeypatch):
    monkeypatch.setattr(rep, "_gsb", fake(False))
    monkeypatch.setattr(rep, "_vt", fake(False))
    v = phase2.analyze("http://y.example/")
    assert v.action == "warn" and not v.unavailable


def test_slow_source_cannot_hold_up_the_page(monkeypatch):
    monkeypatch.setattr(rep, "_gsb", fake(False, delay=3))
    monkeypatch.setattr(rep, "_vt", fake(False))
    t = time.time()
    v = phase2.analyze("http://z.example/")
    assert time.time() - t < 1.0
    assert v.action == "warn" and "Google Safe Browsing" in v.unavailable


def test_flag_still_bounded_by_time_limit(monkeypatch):
    monkeypatch.setattr(rep, "_gsb", fake(True))
    monkeypatch.setattr(rep, "_vt", fake(False, delay=3))
    t = time.time()
    v = phase2.analyze("http://w.example/")
    assert time.time() - t < 1.0
    assert v.action == "block" and v.risk == 33 and "VirusTotal" in v.unavailable


@pytest.mark.parametrize("pt,gsb,vt,risk", [
    (True, False, False, 33), (False, True, False, 33), (False, False, True, 33),
    (True, True, False, 66), (False, True, True, 66), (True, False, True, 66),
    (True, True, True, 100),
])
def test_risk_counts_sources(monkeypatch, pt, gsb, vt, risk):
    url = "http://risk.example/p"
    rep.phishtank.load("phish_id,url\n1,%s\n" % (url if pt else "http://other.example/"))
    monkeypatch.setattr(rep, "_gsb", fake(gsb))
    monkeypatch.setattr(rep, "_vt", fake(vt))
    v = phase2.analyze(url)
    assert v.action == "block" and v.risk == risk and len(v.sources) == risk // 33


def test_risk_survives_bad_host_cache(monkeypatch):
    monkeypatch.setattr(rep, "_gsb", fake(True))
    monkeypatch.setattr(rep, "_vt", fake(True))
    assert phase2.analyze("http://two.example/a").risk == 66
    assert phase2.analyze("http://two.example/b").risk == 66  # same host, answered from cache


def test_page_shows_percentage():
    from guardian import pages
    html = pages.malicious("http://x.example/", ["PhishTank", "VirusTotal"], 66).decode()
    assert "66%" in html and "2 of 3" in html


def test_missing_keys_reported_and_cached(monkeypatch):
    monkeypatch.setattr(rep, "_gsb", fake(rep.Unavailable("no key")))
    monkeypatch.setattr(rep, "_vt", fake(rep.Unavailable("no key")))
    v = phase2.analyze("http://q.example/")
    assert v.action == "warn" and set(v.unavailable) == {"Google Safe Browsing", "VirusTotal"}


def test_second_lookup_hits_cache_and_bad_host_blocks_subresources(monkeypatch):
    calls = []
    monkeypatch.setattr(rep, "_gsb", lambda u: calls.append(u) or True)
    monkeypatch.setattr(rep, "_vt", fake(False))
    assert phase2.analyze("http://bad2.example/page").action == "block"
    assert phase2.analyze("http://bad2.example/page").action == "block"
    assert len(calls) == 1
    assert phase2.analyze("http://bad2.example/script.js", quick=True).action == "block"


def test_quick_never_uses_network(monkeypatch):
    def boom(u):
        raise AssertionError("network used")
    monkeypatch.setattr(rep, "_gsb", boom)
    monkeypatch.setattr(rep, "_vt", boom)
    assert phase2.analyze("http://img.example/a.png", quick=True).action == "allow"
