"""Compact UI regression tests. No real user data or external API calls."""
import asyncio
from pathlib import Path

from fastapi.testclient import TestClient
from app.main import app
from app.file_scanner import analyse_file


BASE = Path(__file__).resolve().parents[1] / 'app' / 'static'


def test_unused_antivirus_removed_from_api_and_report(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    with TestClient(app) as client:
        status = client.get('/api/providers').json()
        assert 'clamav' not in status
        report = client.post('/api/scan-file', files={'file': ('example.txt', b'safe synthetic demonstration')}).json()
        assert report['risk'] == 'unknown'
        assert len(report['providers']) == 2
        assert len(report['checks']) == 3
        assert all('ClamAV' not in item['label'] for item in report['checks'])
        assert 'ClamAV' not in report['disclaimer']


def test_critical_consent_is_preserved(monkeypatch):
    monkeypatch.setenv('VT_FILE_UPLOAD_ENABLED', 'true')
    with TestClient(app) as client:
        response = client.post('/api/scan-file', data={'check_hash': 'true', 'submit_to_vt': 'true', 'vt_public_consent': 'false'},
                               files={'file': ('test.txt', b'ordinary sample')})
        assert response.status_code == 422
        text = client.get('/file').text
        assert 'id="file-vt-consent-opt"' in text
        assert 'файл целиком уйдёт в VirusTotal' in text
        assert '<details id="file-advanced"' in text
        assert 'id="file-vt-indicator"' in text
        assert 'ClamAV' not in text
        assert 'process-section' not in text


def test_report_keeps_partial_coverage_visible():
    report = asyncio.run(analyse_file(b'Rar!\x1a\x07\x00' + b'x' * 60, 'sample.rar', False))
    assert report['inspection_coverage']['status'] == 'partial'
    assert report['quick_verdict']['state'] != 'low'


def test_frontend_has_no_old_clamav_references():
    for filename in ('index.html', 'script.js'):
        text = (BASE / filename).read_text(encoding='utf-8')
        assert 'ClamAV' not in text
    assert 'file-advanced' in (BASE / 'index.html').read_text(encoding='utf-8')
