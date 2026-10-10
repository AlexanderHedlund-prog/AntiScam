"""Synthetic input only. No execution of malicious code or outbound network."""
import asyncio
import io
import zipfile
from fastapi.testclient import TestClient
from app.main import app, _TRAFFIC, _GLOBAL_TRAFFIC, _TRAFFIC_LOCK, check_rate_limit
from app.file_scanner import inspect_file, analyse_file
from app.local_malware import inspect_malware_indicators


def zip_bytes(entries, compress=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compress) as f:
        for name, value in entries.items():
            f.writestr(name, value)
    return out.getvalue()


def test_bidi_filename_flagged_and_removed_from_output():
    report = inspect_file(b'%PDF-1.5\n%%EOF', 'report\u202eexe.pdf')
    assert '\u202e' not in report['filename']
    assert any('невидимые символы' in s['text'] for s in report['signals'])


def test_zip_duplicate_names_warning():
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z:
        z.writestr('name.txt', 'one')
        z.writestr('NAME.txt', 'two')
    report = inspect_file(out.getvalue(), 'example.zip')
    assert any('повторяющиеся имена' in s['text'] for s in report['signals'])


def test_disguised_executable_inside_zip_is_flagged():
    z = zip_bytes({'photo.jpg': b'MZ' + b'fake-and-inert'})
    own = inspect_malware_indicators(z, 'photos.zip')
    assert any('исполняемый код' in f['text'] for f in own['findings'])


def test_large_zip_member_triggers_incomplete_coverage():
    archive = zip_bytes({'payload.txt': b'A' * 250000})
    report = asyncio.run(analyse_file(archive, 'assets.zip', False))
    assert report['inspection_coverage']['status'] == 'partial'
    assert report['own_malware_scan']['truncated'] is True
    assert 'слишком большие вложения' in ' '.join(report['inspection_coverage']['limitations'])
    assert report['risk'] != 'low'


def test_simple_pdf_has_bounded_coverage_and_unknown_av():
    report = asyncio.run(analyse_file(b'%PDF-1.6\n%%EOF', 'school.pdf', False))
    assert report['inspection_coverage']['status'] == 'bounded'
    assert report['risk'] == 'unknown'
    assert 'не полноценное антивирусное' in report['inspection_coverage']['explanation']


def test_api_renders_coverage_and_security_headers():
    with TestClient(app) as client:
        response = client.get('/file')
        assert response.status_code == 200
        assert 'file-coverage' in response.text
        assert "default-src 'none'" in response.headers['content-security-policy']
        assert response.headers['x-content-type-options'] == 'nosniff'
        reply = client.post('/api/scan-file', files={'file': ('one.pdf', b'%PDF-1.7\n%%EOF', 'application/pdf')})
        assert reply.status_code == 200
        assert reply.json()['inspection_coverage']['status'] == 'bounded'


def test_file_size_limit_rejects_upload_before_analysis():
    with TestClient(app) as client:
        too_big = client.post('/api/scan-file', files={'file': ('huge.dat', b'0' * (9 * 1024 * 1024), 'application/octet-stream')})
        assert too_big.status_code == 413


def test_global_limiter_prevents_unbounded_traffic():
    import app.main as api
    async def check():
        async with _TRAFFIC_LOCK:
            old_global = list(_GLOBAL_TRAFFIC)
            old_traffic = dict(_TRAFFIC)
            _GLOBAL_TRAFFIC.clear(); _TRAFFIC.clear()
            original = api._GLOBAL_PER_MINUTE
            api._GLOBAL_PER_MINUTE = 2
        try:
            assert await check_rate_limit('testing-global-a')
            assert await check_rate_limit('testing-global-b')
            assert not await check_rate_limit('testing-global-c')
        finally:
            async with _TRAFFIC_LOCK:
                api._GLOBAL_PER_MINUTE = original
                _GLOBAL_TRAFFIC.clear(); _GLOBAL_TRAFFIC.extend(old_global)
                _TRAFFIC.clear(); _TRAFFIC.update(old_traffic)
    asyncio.run(check())


def test_vt_upload_remains_disabled_by_default(monkeypatch):
    from app.vt_file_submission import uploads_enabled
    monkeypatch.delenv('VT_FILE_UPLOAD_ENABLED', raising=False)
    assert not uploads_enabled()
