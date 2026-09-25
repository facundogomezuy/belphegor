"""Tests del modelo Finding."""

from belphegor.models import Finding


def test_finding_defaults():
    f = Finding(raw="algo")
    assert f.path == ""
    assert f.status == ""
    assert f.size == ""
    assert f.redirect == ""
    assert f.source == "gobuster"


def test_finding_to_dict():
    f = Finding(raw="/a (200)", path="/a", status="200", size="10", source="ffuf")
    d = f.to_dict()
    assert d == {
        "raw": "/a (200)",
        "path": "/a",
        "status": "200",
        "size": "10",
        "redirect": "",
        "source": "ffuf",
    }
