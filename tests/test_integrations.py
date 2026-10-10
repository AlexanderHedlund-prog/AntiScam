"""Offline tests for Google v5 protocol, caching, errors and VT quota."""
import asyncio

from fastapi.testclient import TestClient
import pytest

from app import scanner, reputation_quota
from app.main import app


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    scanner._GOOGLE_CACHE.clear()
    reputation_quota._CALLS.clear()
    monkeypatch.delenv('GOOGLE_SAFE_BROWSING_API_KEY', raising=False)
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload
    def json(self):
        return self.payload


def fake_client(monkeypatch, response, recorder):
    class Client:
        def __init__(self, *args, **kwargs):
            assert kwargs['follow_redirects'] is False
            assert kwargs['trust_env'] is False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, path, **kwargs):
            recorder.append((path, kwargs))
            return response
    monkeypatch.setattr(scanner.httpx, 'AsyncClient', Client)


def test_google_v5_no_threat_and_cache(monkeypatch):
    calls = []
    fake_client(monkeypatch, FakeResponse(200, {'threats': [], 'cacheDuration': '90s'}), calls)
    r1 = asyncio.run(scanner.google_check('https://example.com/a?token=a', 'private-test-key'))
    r2 = asyncio.run(scanner.google_check('https://example.com/a?token=a', 'private-test-key'))
    assert r1['status'] == 'checked' and r1['detections'] == 0
    assert r2 == r1 and len(calls) == 1
    assert calls[0][0] == 'https://safebrowsing.googleapis.com/v5/urls:search'
    assert calls[0][1]['params']['urls'] == 'https://example.com/a?token=a'
    assert 'alt' not in calls[0][1]['params']
    assert 'private-test-key' not in str(scanner._GOOGLE_CACHE)
    assert 'token=a' not in str(scanner._GOOGLE_CACHE)


def test_google_v5_threat(monkeypatch):
    calls = []
    fake_client(monkeypatch, FakeResponse(200, {'threats': [{'url': 'https://somewhere.test', 'threatTypes': ['SOCIAL_ENGINEERING']}], 'cacheDuration': '17s'}), calls)
    r = asyncio.run(scanner.google_check('https://somewhere.test', 'key'))
    assert r['status'] == 'checked' and r['detections'] == 1
    assert r['threats'] == ['SOCIAL_ENGINEERING']


@pytest.mark.parametrize('code', [403, 429, 500])
def test_google_fail_closed(monkeypatch, code):
    calls = []
    fake_client(monkeypatch, FakeResponse(code, {}), calls)
    assert asyncio.run(scanner.google_check('https://example.org', 'key'))['status'] == 'error'


def test_invalid_google_payload_never_marks_checked(monkeypatch):
    calls = []
    fake_client(monkeypatch, FakeResponse(200, {'threats': 'invalid'}), calls)
    assert asyncio.run(scanner.google_check('https://example.org', 'key'))['status'] == 'error'


def test_provider_status_only_boolean(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'secret-that-must-not-leak')
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY', 'another-secret')
    with TestClient(app) as c:
        result = c.get('/api/providers')
        assert result.status_code == 200
        data = result.json()
        assert data['google_safe_browsing']['configured'] is True
        assert data['virustotal']['configured'] is True
        assert data['google_safe_browsing']['version'] == 'v5'
        assert 'secret' not in result.text


def test_vt_uses_at_most_three_calls_per_process():
    assert asyncio.run(reputation_quota.take_virustotal_slot()) is True
    assert asyncio.run(reputation_quota.take_virustotal_slot()) is True
    assert asyncio.run(reputation_quota.take_virustotal_slot()) is True
    assert asyncio.run(reputation_quota.take_virustotal_slot()) is False
