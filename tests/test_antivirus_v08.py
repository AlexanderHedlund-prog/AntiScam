"""Synthetic tests only: no harmful code, no network access, no real malware."""
import asyncio
import io
import os
import struct
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app.main import app, _TRAFFIC
from app.local_malware import EICAR_TEST, inspect_malware_indicators
from app.clamav_engine import scan_clamav
from app.file_scanner import analyse_file


@pytest.fixture(autouse=True)
def no_external_api(monkeypatch):
    _TRAFFIC.clear()
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    monkeypatch.delenv('CLAMD_SOCKET_PATH', raising=False)


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
    assert report['providers'][2]['status'] == 'skipped'  # ClamAV missing
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


def test_clamav_not_configured():
    result = asyncio.run(scan_clamav(b'hello'))
    assert result['status'] == 'skipped'


def test_clamav_refuses_invalid_socket_path(monkeypatch):
    monkeypatch.setenv('CLAMD_SOCKET_PATH', 'https://malware.example/scan')
    result = asyncio.run(scan_clamav(b'hello'))
    assert result['status'] == 'error'


def test_clamav_unreachable_does_not_claim_clean(monkeypatch, tmp_path):
    monkeypatch.setenv('CLAMD_SOCKET_PATH', str(tmp_path / 'absent.sock'))
    result = asyncio.run(scan_clamav(b'hello'))
    assert result['status'] == 'error'
    assert 'проверен' in result['message']


def test_clamav_instream_protocol_and_detection(monkeypatch, tmp_path):
    async def run():
        received = []
        path = str(tmp_path / 'clamd.sock')
        monkeypatch.setenv('CLAMD_SOCKET_PATH', path)

        async def fake_daemon(reader, writer):
            assert await reader.readexactly(10) == b'zINSTREAM\x00'
            while True:
                amount = struct.unpack('>I', await reader.readexactly(4))[0]
                if amount == 0:
                    break
                received.append(await reader.readexactly(amount))
            writer.write(b'stream: Synthetic.Test FOUND\x00')
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_unix_server(fake_daemon, path=path)
        try:
            report = await scan_clamav(b'hello world!')
        finally:
            server.close()
            await server.wait_closed()
        assert b''.join(received) == b'hello world!'
        assert report['status'] == 'checked'
        assert report['detections'] == 1
        assert 'Synthetic.Test' in report['message']
    asyncio.run(run())


def test_clamav_clean_instream(monkeypatch, tmp_path):
    async def run():
        path = str(tmp_path / 'clamd.sock')
        monkeypatch.setenv('CLAMD_SOCKET_PATH', path)
        async def fake_daemon(reader, writer):
            await reader.readexactly(10)
            while True:
                n = struct.unpack('>I', await reader.readexactly(4))[0]
                if not n: break
                await reader.readexactly(n)
            writer.write(b'stream: OK\x00')
            await writer.drain(); writer.close(); await writer.wait_closed()
        server = await asyncio.start_unix_server(fake_daemon, path=path)
        try:
            report = await analyse_file(b'%PDF-1.7\n%%EOF', 'file.pdf', False)
        finally:
            server.close(); await server.wait_closed()
        assert report['risk'] == 'low'
        assert report['providers'][2]['status'] == 'checked'
        assert report['checks'][2]['status'] == 'checked'
    asyncio.run(run())


def test_quick_verdict_on_detected_local_clamav(monkeypatch):
    async def fake_scan(data):
        return {'status': 'checked', 'name': 'ClamAV (антивирусные сигнатуры)', 'detections': 1, 'message': 'Synthetic.Mock FOUND'}
    monkeypatch.setattr('app.file_scanner.scan_clamav', fake_scan)
    report = asyncio.run(analyse_file(b'plain file text', 'file.txt', False))
    assert report['risk'] == 'danger'
    assert 'не открывайте' in report['quick_verdict']['note'].lower()


def test_file_api_has_local_scan_always_even_without_vt():
    with TestClient(app) as c:
        response = c.post('/api/scan-file', files={'file': ('my.pdf', b'%PDF-1.4\n%%EOF', 'application/pdf')})
    assert response.status_code == 200
    data = response.json()
    assert data['own_malware_scan']['status'] == 'checked'
    assert data['risk'] == 'unknown'
    assert data['checks'][2]['status'] == 'skipped'
    assert 'Собственная проверка' in c.get('/file').text
