"""No internet access needed: all tests are deterministic."""
import asyncio
import socket
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import scanner


@pytest.fixture(autouse=True)
def no_keys(monkeypatch):
    monkeypatch.delenv('GOOGLE_SAFE_BROWSING_API_KEY', raising=False)
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)


def test_home_and_health():
    with TestClient(app) as client:
        assert client.get('/').status_code == 200
        assert 'AntiScam' in client.get('/').text
        assert client.get('/health').json()['status'] == 'ok'


def test_no_reputation_never_means_safe():
    with TestClient(app) as client:
        result = client.post('/api/scan', json={'url': 'https://example.com/files/slides.pptx'}).json()
    assert result['risk'] == 'unknown'
    assert result['content']['label'].startswith('Презентация')
    assert all(p['status'] == 'skipped' for p in result['providers'])
    assert result['header_probe']['status'] == 'skipped'
    assert '?' not in result['display_url']


def test_dangerous_extension():
    report = asyncio.run(scanner.analyse_url('https://example.org/download/invoice.pdf.exe', False, False))
    assert report['risk'] == 'caution'
    assert any('Двойное' in s['text'] for s in report['signals'])


@pytest.mark.parametrize('url', [
    'file:///etc/passwd',
    'javascript:alert(1)',
    'http://localhost:8000/',
    'http://127.0.0.1/',
    'http://192.168.1.2/',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1/',
    'http://example.com:8080/',
    'http://user:pass@example.com/',
    'http://example.com\\@localhost/',
])
def test_blocks_unsafe_urls(url):
    with pytest.raises(scanner.URLValidationError):
        scanner.validate_url(url)


def test_url_displays_without_secret():
    info = scanner.validate_url('https://example.org/view/file.pdf?token=SECRET123#private')
    assert 'SECRET123' not in info.safe_display
    assert 'private' not in info.safe_display


def test_external_threat_changes_result(monkeypatch):
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY', 'test-key')
    async def fake_google(url, key):
        assert key == 'test-key'
        return {'name': 'Google Safe Browsing', 'status': 'checked', 'detections': 1,
                'message': 'Совпадение в списках угроз.'}
    monkeypatch.setattr(scanner, 'google_check', fake_google)
    report = asyncio.run(scanner.analyse_url('https://example.com/test', True, False))
    assert report['risk'] == 'danger'


def test_virustotal_single_detection_is_caution(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    async def fake_vt(url, key):
        return {'name': 'VirusTotal', 'status': 'checked', 'detections': 1,
                'suspicious': 0, 'message': '1 detection'}
    monkeypatch.setattr(scanner, 'virustotal_check', fake_vt)
    report = asyncio.run(scanner.analyse_url('https://example.com/test', True, False))
    assert report['risk'] == 'caution'


def test_safe_head_gets_content_type(monkeypatch):
    async def fake_probe(link):
        return {'status': 'ok', 'mime': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'message': 'OK'}
    monkeypatch.setattr(scanner, 'probe_content', fake_probe)
    report = asyncio.run(scanner.analyse_url('https://example.com/download', False, True))
    assert '.pptx' in report['content']['label']
    assert report['content']['confidence'] == 'medium'
    assert report['risk'] == 'unknown'  # format detection is not malware detection


def test_dns_guard_blocks_private_resolution(monkeypatch):
    original_get = asyncio.BaseEventLoop.getaddrinfo
    async def fake_dns(self, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
    monkeypatch.setattr(asyncio.BaseEventLoop, 'getaddrinfo', fake_dns)
    async def run():
        return await scanner.GuardedResolver().resolve('public.example.com', 443)
    with pytest.raises(OSError, match='private'):
        asyncio.run(run())
    monkeypatch.setattr(asyncio.BaseEventLoop, 'getaddrinfo', original_get)


def test_malformed_input_api():
    with TestClient(app) as client:
        response = client.post('/api/scan', json={'url': 'http://localhost/'})
    assert response.status_code == 422
    assert 'Локальные' in response.json()['detail']
