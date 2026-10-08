"""Regression: one successful provider must not make the entire scan appear green."""
import asyncio
from app import scanner


def make_stub(name, status, detections=0, suspicious=0):
    async def _call(url, api_key):
        return {"name": name, "status": status, "detections": detections, "suspicious": suspicious, "message": "test"}
    return _call


def test_partial_reputation_is_not_green(monkeypatch):
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY','fake-google-key')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-vt-key')
    monkeypatch.setattr(scanner, 'google_check', make_stub('Google Safe Browsing', 'error'))
    monkeypatch.setattr(scanner, 'virustotal_check', make_stub('VirusTotal', 'checked'))
    result = asyncio.run(scanner.analyse_url('https://example.com/', True, False))
    assert result['risk'] == 'unknown'
    assert result['title'] == 'Проверка выполнена частично'


def test_both_checked_can_be_low(monkeypatch):
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY','fake-google-key')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-vt-key')
    monkeypatch.setattr(scanner, 'google_check', make_stub('Google Safe Browsing', 'checked'))
    monkeypatch.setattr(scanner, 'virustotal_check', make_stub('VirusTotal', 'checked'))
    result = asyncio.run(scanner.analyse_url('https://example.com/', True, False))
    assert result['risk'] == 'low'


def test_detection_overrides_missing_provider(monkeypatch):
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY','fake-google-key')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-vt-key')
    monkeypatch.setattr(scanner, 'google_check', make_stub('Google Safe Browsing', 'error'))
    monkeypatch.setattr(scanner, 'virustotal_check', make_stub('VirusTotal', 'checked', detections=2))
    result = asyncio.run(scanner.analyse_url('https://example.com/', True, False))
    assert result['risk'] == 'danger'
