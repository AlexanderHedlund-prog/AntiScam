"""VirusTotal new file submission tests; never contact real network."""
import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.main import app, _TRAFFIC
from app import file_scanner, vt_file_submission as vt


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    _TRAFFIC.clear()
    vt._SUBMISSIONS.clear()
    vt._RECENT.clear()
    vt._RECENT_TOKEN.clear()
    vt._SESSIONS.clear()
    monkeypatch.delenv('VT_FILE_UPLOAD_ENABLED', raising=False)
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)


def test_upload_default_off_and_only_hash_uses_existing_path():
    with TestClient(app) as c:
        d = c.get('/api/providers').json()
        assert d['virustotal']['new_file_upload_enabled'] is False
        assert c.post('/api/scan-file', data={'check_hash': 'true', 'submit_to_vt': 'true', 'vt_public_consent': 'true'},
                      files={'file': ('test.txt', b'hello')}).status_code == 403
        report = c.post('/api/scan-file', files={'file': ('test.txt', b'hello')}).json()
    assert report['risk'] == 'unknown'
    assert report.get('vt_analysis_token') is None


def test_upload_permission_and_hash_permission_are_separate(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    with TestClient(app) as c:
        assert c.post('/api/scan-file', data={'submit_to_vt': 'true'},
                      files={'file': ('test.txt', b'hello')}).status_code == 422


def test_enabled_option_is_reflected_in_providers(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test')
    with TestClient(app) as c:
        assert c.get('/api/providers').json()['virustotal']['new_file_upload_enabled'] is True


class DummyResponse:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data
    def json(self):
        return self._data


class DummyVTClient:
    def __init__(self, *args, **kwargs): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def post(self, url, **kwargs):
        assert url == 'https://www.virustotal.com/api/v3/files'
        assert kwargs['files']['file'][0] == 'sample.bin'  # hide user filenames
        return DummyResponse(200, {'data': {'id': 'abcDEF1234==='}})
    async def get(self, url, **kwargs):
        if '/analyses/' in url:
            return DummyResponse(200, {'data': {'attributes': {'status': 'completed', 'stats': {'malicious': 4, 'suspicious': 1, 'undetected': 78}}}})
        return DummyResponse(404, {})


def test_full_submission_poll_and_external_detection(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test')
    monkeypatch.setattr(file_scanner.httpx, 'AsyncClient', DummyVTClient)
    monkeypatch.setattr(vt.httpx, 'AsyncClient', DummyVTClient)
    async def slot(): return True
    monkeypatch.setattr(file_scanner, 'take_virustotal_slot', slot)
    monkeypatch.setattr(vt, 'take_virustotal_slot', slot)
    with TestClient(app) as c:
        result = c.post('/api/scan-file', data={'check_hash': 'true', 'submit_to_vt': 'true', 'vt_public_consent': 'true'},
                        files={'file': ('private.name.pptx', b'hello file bytes')})
        assert result.status_code == 200
        data = result.json()
        assert data['providers'][0]['status'] == 'pending'
        token = data['vt_analysis_token']
        assert len(token) >= 32
        polled = c.post('/api/vt-file-status', json={'token': token}).json()
    assert polled['status'] == 'checked'
    assert polled['detections'] == 4
    assert polled['suspicious'] == 1
    assert polled['total'] == 83
    assert token not in vt._SESSIONS


def test_no_upload_for_existing_vt_report(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test')
    class KnownClient(DummyVTClient):
        async def post(self, *a, **k):
            raise AssertionError('SHOULD NOT SUBMIT')
        async def get(self, *a, **k):
            return DummyResponse(200, {'data': {'attributes': {'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 4}}}})
    monkeypatch.setattr(file_scanner.httpx, 'AsyncClient', KnownClient)
    async def slot(): return True
    monkeypatch.setattr(file_scanner, 'take_virustotal_slot', slot)
    with TestClient(app) as c:
        data = c.post('/api/scan-file', data={'check_hash': 'true', 'submit_to_vt': 'true', 'vt_public_consent': 'true'},
                      files={'file': ('file.txt', b'example')}).json()
    assert data['providers'][0]['status'] == 'checked'
    assert data['vt_analysis_token'] is None


def test_reject_unknown_or_guessed_poll_token():
    with TestClient(app) as c:
        resp = c.post('/api/vt-file-status', json={'token': 'abc'})
        assert resp.status_code == 422


def test_process_local_daily_cap_rejects_more_submissions(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test')
    async def slot(): return True
    monkeypatch.setattr(vt, 'take_virustotal_slot', slot)
    monkeypatch.setattr(vt.httpx, 'AsyncClient', DummyVTClient)
    async def do():
        return await asyncio.gather(*(vt.submit_unknown_file(f'data {i}'.encode(), __import__('hashlib').sha256(f'data {i}'.encode()).hexdigest(), 'n.txt') for i in range(9)))
    results = asyncio.run(do())
    assert sum(result['status'] == 'pending' for result in results) == 8
    assert results[-1]['status'] == 'error'


def test_progress_report_is_not_same_as_clean():
    assert vt._normalize_stats({'stats': {}})['status'] == 'no_data'
    assert vt._normalize_stats({'stats': {'malicious': 0, 'undetected': 6}})['status'] == 'checked'
    assert vt._normalize_stats({'stats': {'malicious': 2, 'undetected': 6}})['detections'] == 2


def test_never_upload_without_key_even_when_enabled(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    async def do():
        return await vt.submit_unknown_file(b'hello', 'a' * 64, 'a.txt')
    assert asyncio.run(do())['status'] == 'error'
