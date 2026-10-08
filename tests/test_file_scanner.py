"""File scanner tests — only synthetic in-memory files, no network."""
import asyncio
import hashlib
import io
import zipfile
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app import file_scanner
from app.main import app, _TRAFFIC


@pytest.fixture(autouse=True)
def fresh_limit_and_no_token(monkeypatch):
    _TRAFFIC.clear()
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)


def office_pptx() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr('ppt/presentation.xml', '<ppt/>')
        zf.writestr('[Content_Types].xml', '<Types/>')
    return buffer.getvalue()


def test_distinct_pages_work():
    with TestClient(app) as c:
        assert c.get('/').status_code == 200
        assert c.get('/file').status_code == 200
        assert c.get('/about').status_code == 200
        assert '/api/scan-file' in c.get('/assets/script.js').text
        assert 'Проверка файла' in c.get('/file').text


def test_document_type_detection_does_not_claim_safe():
    with TestClient(app) as c:
        response = c.post('/api/scan-file', files={'file': ('slides.pptx', office_pptx(), 'application/octet-stream')})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['content']['label'] == 'Презентация PowerPoint (PPTX)'
    assert data['risk'] == 'unknown'
    assert len(data['sha256']) == 64
    assert data['providers'][0]['status'] == 'skipped'
    assert data['filename'] == 'slides.pptx'


def test_renamed_program_is_flagged():
    data = file_scanner.inspect_file(b'MZ' + b'\0' * 128, 'report.pdf')
    assert data['content']['label'] == 'Исполняемый файл Windows'
    assert any('не совпадает' in s['text'] for s in data['signals'])
    assert any(s['severity'] == 'high' for s in data['signals'])


def test_pdf_recognition():
    data = file_scanner.inspect_file(b'%PDF-1.7\n1 0 obj\n%%EOF', 'report.pdf')
    assert data['content']['label'] == 'PDF-документ'
    assert data['signals'] == []


def test_file_name_is_sanitized():
    data = file_scanner.inspect_file(b'%PDF-1.7\n', '..\\otherdir\\info.pdf')
    assert data['filename'] == 'info.pdf'


def test_empty_file_not_accepted():
    with TestClient(app) as c:
        resp = c.post('/api/scan-file', files={'file': ('empty.pdf', b'', 'application/pdf')})
    assert resp.status_code == 422


def test_large_body_is_rejected_before_parser():
    with TestClient(app) as c:
        resp = c.post('/api/scan-file', content=b'xx', headers={
            'content-type': 'multipart/form-data; boundary=hello',
            'content-length': str(file_scanner.MAX_MULTIPART_BYTES + 1),
        })
    assert resp.status_code == 413


def test_macro_detected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr('word/document.xml', '<document/>')
        zf.writestr('word/vbaProject.bin', b'fake')
    data = file_scanner.inspect_file(buffer.getvalue(), 'letter.docm')
    assert any('VBA' in s['text'] for s in data['signals'])


def test_hash_check_opt_in_no_api_key_does_not_upload():
    data = asyncio.run(file_scanner.analyse_file(b'%PDF-1.7\n', 'report.pdf', True))
    assert data['providers'][0]['status'] == 'skipped'
    assert 'не' in data['disclaimer'].lower()


def test_hash_lookup_existing_known_threat(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'fake')
    class Response:
        status_code = 200
        def json(self):
            return {'data': {'attributes': {'last_analysis_stats': {'malicious': 5, 'suspicious': 0, 'undetected': 50}}}}
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, **kwargs):
            assert url.endswith(hashlib.sha256(b'%PDF-1.7\n').hexdigest())
            return Response()
    monkeypatch.setattr(file_scanner.httpx, 'AsyncClient', FakeClient)
    data = asyncio.run(file_scanner.analyse_file(b'%PDF-1.7\n', 'x.pdf', True))
    assert data['risk'] == 'danger'
    assert data['providers'][0]['detections'] == 5


def test_large_file_in_memory_rejected():
    with pytest.raises(ValueError, match='8 МБ'):
        file_scanner.inspect_file(b'a' * (file_scanner.MAX_FILE_BYTES + 1), 'data.txt')
