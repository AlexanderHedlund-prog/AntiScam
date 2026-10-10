"""VT reliability tests: API mocked, no real files sent to VirusTotal."""
import asyncio
import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app, _TRAFFIC, _GLOBAL_TRAFFIC
from app import vt_file_submission as vt, file_scanner


class MockReply:
    def __init__(self, code, data=None):
        self.status_code = code
        self._data = data
    def json(self):
        return self._data


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key-private')
    monkeypatch.delenv('VT_STATUS_SIGNING_KEY', raising=False)
    vt._RECENT.clear(); vt._RECENT_TOKEN.clear(); vt._SESSIONS.clear(); vt._SUBMISSIONS.clear()
    _TRAFFIC.clear(); _GLOBAL_TRAFFIC.clear()
    async def slot(): return True
    monkeypatch.setattr(vt, 'take_virustotal_slot', slot)
    monkeypatch.setattr(file_scanner, 'take_virustotal_slot', slot)


class VTClient:
    def __init__(self, *args, **kwargs):
        self.calls = []
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def post(self, url, **kwargs):
        assert url.endswith('/api/v3/files')
        assert kwargs['files']['file'][0] == 'sample.bin'
        return MockReply(200, {'data': {'id': 'u-SampleAnalysisID-1234=='}})
    async def get(self, url, **kwargs):
        if '/analyses/' in url:
            return MockReply(200, {'data': {'attributes': {
                'status': 'completed', 'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 48, 'timeout': 1}}}})
        return MockReply(404, {})


def test_complete_lifecycle_after_server_restart(monkeypatch):
    monkeypatch.setattr(vt.httpx, 'AsyncClient', VTClient)
    monkeypatch.setattr(file_scanner.httpx, 'AsyncClient', VTClient)
    with TestClient(app) as client:
        resp = client.post('/api/scan-file',
                           data={'check_hash': 'true', 'submit_to_vt': 'true', 'vt_public_consent': 'true'},
                           files={'file': ('ordinary.txt', b'non-private demonstration data')})
        assert resp.status_code == 200
        data = resp.json()
        assert data['providers'][0]['status'] == 'pending'
        token = data['vt_analysis_token']
        assert token.startswith('v1.')
        # Free Render can spin down or restart between submission and report.
        vt._SESSIONS.clear(); vt._RECENT.clear(); vt._RECENT_TOKEN.clear()
        report = client.post('/api/vt-file-status', json={'token': token})
        assert report.status_code == 200
        result = report.json()
        assert result['status'] == 'checked'
        assert result['total'] == 48
        assert result['unavailable'] == 1
        assert result['detections'] == 0


def test_token_tampering_and_expiry(monkeypatch):
    token = vt._make_token('u-Mock1234==')
    assert vt._read_token(token) == 'u-Mock1234=='
    tampered = token[:-1] + ('a' if token[-1] != 'a' else 'b')
    assert vt._read_token(tampered) is None
    initial = time.time()
    monkeypatch.setattr(vt.time, 'time', lambda: initial + vt.TOKEN_TTL + 3)
    assert vt._read_token(token) is None


def test_token_survives_restart_and_key_derivation(monkeypatch):
    token = vt._make_token('abc1234==')
    vt._SESSIONS.clear()
    assert vt._read_token(token) == 'abc1234=='
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'another-key')
    assert vt._read_token(token) is None


def test_pending_and_no_stats_remain_pollable(monkeypatch):
    class PendingClient(VTClient):
        async def get(self, url, **kwargs):
            return MockReply(200, {'data': {'attributes': {'status': 'queued'}}})
    monkeypatch.setattr(vt.httpx, 'AsyncClient', PendingClient)
    token = vt._make_token('f1234567==')
    result = asyncio.run(vt.check_analysis(token))
    assert result['status'] == 'pending' and result['analysis_token'] == token
    class EmptyClient(VTClient):
        async def get(self, url, **kwargs):
            return MockReply(200, {'data': {'attributes': {'status': 'completed', 'stats': {'malicious': 0, 'undetected': 0}}}})
    monkeypatch.setattr(vt.httpx, 'AsyncClient', EmptyClient)
    empty = asyncio.run(vt.check_analysis(token))
    assert empty['status'] == 'pending' and empty['analysis_token'] == token


def test_429_is_retryable(monkeypatch):
    class TooMany(VTClient):
        async def get(self, url, **kwargs): return MockReply(429)
    monkeypatch.setattr(vt.httpx, 'AsyncClient', TooMany)
    token = vt._make_token('anotherAnalysis12345=')
    result = asyncio.run(vt.check_analysis(token))
    assert result['status'] == 'pending' and result['analysis_token'] == token


def test_duplicate_submission_reuses_token(monkeypatch):
    monkeypatch.setattr(vt.httpx, 'AsyncClient', VTClient)
    data = b'not confidential'
    digest = hashlib.sha256(data).hexdigest()
    first = asyncio.run(vt.submit_unknown_file(data, digest, 'a.txt'))
    second = asyncio.run(vt.submit_unknown_file(data, digest, 'a.txt'))
    assert first['status'] == second['status'] == 'pending'
    assert first['analysis_token'] == second['analysis_token']
    assert len(vt._SUBMISSIONS) == 1


def test_hash_must_match_upload_bytes():
    data = b'test'
    result = asyncio.run(vt.submit_unknown_file(data, 'a'*64, 'x.txt'))
    assert result['status'] == 'error' and not vt._SUBMISSIONS


def test_stats_counts_only_engines_that_replied():
    assert vt._normalize_stats({'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 10, 'timeout': 3}})['total'] == 10
    assert vt._normalize_stats({'stats': {'malicious': 0, 'undetected': 0, 'timeout': 5}})['status'] == 'no_data'
    assert vt._normalize_stats({'stats': {'malicious': -1}})['status'] == 'error'


def test_upload_without_consent_never_calls_external_service(monkeypatch):
    class NeverCalled:
        def __init__(self,*a,**k): raise AssertionError('VirusTotal must never be called without consent')
    monkeypatch.setattr(vt.httpx, 'AsyncClient', NeverCalled)
    monkeypatch.setattr(file_scanner.httpx, 'AsyncClient', NeverCalled)
    with TestClient(app) as c:
        response = c.post('/api/scan-file', data={'check_hash': 'true', 'submit_to_vt': 'true'},
                          files={'file': ('private.pptx', b'test presentation')})
        assert response.status_code == 422
