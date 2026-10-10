"""Synthetic tests only: no harmful code, no network access, no real malware."""
import asyncio
import io
import os
import zipfile

import pytest
from fastapi.testclient import TestClient
from app.main import app, _TRAFFIC
from app.local_malware import EICAR_TEST, inspect_malware_indicators
from app.file_scanner import analyse_file


@pytest.fixture(autouse=True)
def no_external_api(monkeypatch):
    _TRAFFIC.clear()
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)


def _zip(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for name, value in files.items():
            z.writestr(name, value)
    return b.getvalue()


def test_benign_presentation_remains_unknown_not_false_clean():
    report = asyncio.run(analyse_file(_zip({'ppt/presentation.xml': b'<p/>', '[Content_Types].xml': b'<types/>'}), 'deck.pptx', True))
    assert report['risk'] == 'unknown'
    assert report['own_malware_scan']['status'] == 'checked'
    assert report['providers'][0]['status'] == 'skipped'  # VT key not set
    assert len(report['providers']) == 2  # VirusTotal and AntiScam only
    assert report['checks'][2]['status'] == 'skipped'
    assert 'не' in report['quick_verdict']['note'].lower() or 'невозможно' in report['quick_verdict']['answer'].lower()


def test_embedded_test_signature_is_detected_but_not_called_virus():
    local = inspect_malware_indicators(b'prefix\n' + EICAR_TEST, 'test.txt')
    assert local['test_signatures'] == 1
    assert local['detections'] == 0  # Not actual malware
    report = asyncio.run(analyse_file(EICAR_TEST, 'test.txt', False))
    assert report['risk'] == 'caution'
    assert 'тестов' in report['quick_verdict']['note']


def test_encoded_powershell_warns_but_is_not_confirmed_malware():
    report = asyncio.run(analyse_file(b'powershell.exe -EncodedCommand AAAAAAAA', 'sample.ps1', False))
    assert report['risk'] == 'caution'
    assert any('PowerShell' in sig['text'] for sig in report['signals'])
    assert report['own_malware_scan']['detections'] == 0


def test_archive_members_scanned_without_extraction(tmp_path):
    contents = _zip({'deck/payload.ps1': b'powershell -enc QQ==', 'slides/slide.xml': b'<p/>'})
    result = inspect_malware_indicators(contents, 'sample.zip')
    assert result['suspicious'] >= 1
    assert result['inspected_members'] >= 1
    assert list(tmp_path.iterdir()) == []


def test_limit_archive_with_many_entries():
    contents = _zip({f'item{i}.txt': 'hello world' for i in range(65)})
    result = inspect_malware_indicators(contents, 'many.zip')
    assert result['inspected_members'] <= 24
    assert result['truncated'] is True


def test_non_zip_plain_text_no_false_alarm():
    local = inspect_malware_indicators(b'hello from school presentation', 'talk.txt')
    assert not local['findings']
    assert local['status'] == 'checked'


def test_file_api_has_local_scan_always_even_without_vt():
    with TestClient(app) as c:
        response = c.post('/api/scan-file', files={'file': ('my.pdf', b'%PDF-1.4\n%%EOF', 'application/pdf')})
    assert response.status_code == 200
    data = response.json()
    assert data['own_malware_scan']['status'] == 'checked'
    assert data['risk'] == 'unknown'
    assert data['checks'][2]['status'] == 'skipped'
    assert 'Подробности проверки' in c.get('/file').text
