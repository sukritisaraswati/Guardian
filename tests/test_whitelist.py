import os, tempfile
os.environ["GUARDIAN_HOME"] = tempfile.mkdtemp()
from guardian import whitelist

whitelist.ensure_db()
wl = whitelist.Whitelist()


def test_exact_and_subdomain():
    assert wl.lookup("google.com")[0] == "Search & Portals"
    assert wl.lookup("www.google.com")[1] == "google.com"
    assert wl.lookup("mail.google.com")[1] == "google.com"


def test_unknown_and_lookalike():
    assert wl.lookup("g00gle-login-secure.xyz") is None
    assert wl.lookup("google.com.evil.example") is None


def test_shared_hosting_not_inherited():
    assert wl.lookup("someuser.github.io") is None
    assert wl.lookup("someuser.blogspot.com") is None


def test_local_and_ip():
    assert whitelist.is_local("localhost") and whitelist.is_local("192.168.1.5")
    assert not whitelist.is_local("8.8.8.8") and wl.lookup("8.8.8.8") is None
