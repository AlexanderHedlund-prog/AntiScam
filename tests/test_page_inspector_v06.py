"""No network is accessed in these tests."""
import asyncio
import socket

from fastapi.testclient import TestClient
from app.main import app
from app import scanner, page_inspector


def test_static_html_extracts_title_without_script_execution():
    data = b'<html><head><title>School presentation</title></head><body><script>window.bad=1;</script><p>Fine</p></body></html>'
    r = page_inspector.summarise_page(data, 'https://example.com/path', 'text/html')
    assert r['kind'] == 'HTML-страница'
    assert r['title'] == 'School presentation'
    assert r['scripts'] == 1
    assert r['signals'] == []


def test_login_form_posts_password_to_other_domain():
    r = page_inspector.summarise_page(
        b'<form action="https://stranger.example/log"><input type="password" name="pw"></form>',
        'https://accounts.example.com/auth', 'text/html')
    assert any(s['severity'] == 'high' and 'пароля' in s['text'] for s in r['signals'])


def test_regular_login_form_does_not_flag_external_post():
    r = page_inspector.summarise_page(
        b'<form action="/login"><input type="password"></form>',
        'https://example.com', 'text/html')
    assert not r['signals']


def test_hidden_external_iframe_and_meta_refresh_detected():
    doc = (b'<iframe src="https://other.example/a" width="0"></iframe>'
           b'<meta http-equiv="refresh" content="0;url=https://else.example/download">')
    r = page_inspector.summarise_page(doc, 'https://example.com', 'text/html')
    assert len(r['signals']) == 2


def test_links_to_executables_not_downloaded():
    r = page_inspector.summarise_page(b'<a href="/installer.exe">Download</a>', 'https://example.com', 'text/html')
    assert r['suspicious_links'] == 1
    assert len(r['signals']) == 1


def test_disguised_exe_is_not_treated_as_html():
    r = page_inspector.summarise_page(b'MZ' + b'X'*100, 'https://example.com/file.pdf', 'text/html')
    assert r['kind'].startswith('Исполняемый файл')
    assert len([s for s in r['signals'] if s['severity'] == 'high']) >= 1


def test_pdf_header_detected():
    r = page_inspector.summarise_page(b'%PDF-1.7\n123', 'https://example.com/presentation.pdf', 'application/pdf')
    assert r['kind'] == 'PDF-документ'


def test_zip_is_not_decompressed():
    r = page_inspector.summarise_page(b'PK\x03\x04' + b'\xff'*80, 'https://example.com/file.zip', 'application/zip')
    assert r['kind'].startswith('ZIP')


def test_bounded_inspection_not_default(monkeypatch):
    async def never(*args):
        raise AssertionError('Inspection should only run after explicit consent')
    monkeypatch.setattr(page_inspector, 'inspect_page', never)
    with TestClient(app) as client:
        r = client.post('/api/scan', json={'url': 'https://example.com'})
        assert r.status_code == 200
        assert r.json()['page_inspection']['status'] == 'skipped'


def test_inspection_added_to_local_signals_and_content(monkeypatch):
    async def fake(*args):
        return {'status': 'ok', 'message': 'OK', 'signals': [
            {'severity':'high','text':'Форма для пароля отправляет данные на другой домен','source':'page'}],
            'kind': 'HTML-страница', 'mime': 'text/html', 'title': 'Test', 'final_host':'example.com'}
    monkeypatch.setattr(page_inspector, 'inspect_page', fake)
    with TestClient(app) as client:
        r = client.post('/api/scan', json={'url':'https://example.com', 'inspect_page': True})
        j = r.json()
        assert r.status_code == 200
        assert j['page_inspection']['status'] == 'ok'
        assert j['risk'] == 'caution'
        assert len(j['signals']) == 1
        assert j['content']['label'] == 'HTML-страница'


def test_guarded_resolver_blocks_internal_dns(monkeypatch):
    async def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, 'getaddrinfo', fake_getaddrinfo)
        try:
            await scanner.GuardedResolver().resolve('example.com', 443)
        except OSError:
            return True
        return False
    assert asyncio.run(run())


def test_guarded_resolver_blocks_mixed_public_private_dns(monkeypatch):
    async def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, 'getaddrinfo', fake_getaddrinfo)
        try:
            await scanner.GuardedResolver().resolve('example.com', 443)
        except OSError:
            return True
        return False
    assert asyncio.run(run())


def test_unsafe_redirect_fails_before_network_followup(monkeypatch):
    calls = []
    class Response:
        status = 302
        headers = {'Location': 'http://169.254.169.254/latest/meta-data/'}
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Session:
        def __init__(self, *args, **kwargs):
            assert kwargs['trust_env'] is False
            assert kwargs['auto_decompress'] is False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        def get(self, url, **kw):
            calls.append((url, kw))
            return Response()
    monkeypatch.setattr(page_inspector.aiohttp, 'ClientSession', Session)
    r = asyncio.run(page_inspector.inspect_page(scanner.validate_url('https://example.com')))
    assert r['status'] == 'blocked'
    assert len(calls) == 1 and calls[0][1]['allow_redirects'] is False


def test_parsed_html_never_echoes_secret_in_url():
    assert scanner.validate_url('https://example.com/file?api_key=sensitive').safe_display == 'https://example.com/file'


def test_failed_requested_preview_stays_partial_even_if_both_reputation_bases_clean(monkeypatch):
    async def good_google(*args):
        return {'name': 'Google Safe Browsing', 'status': 'checked', 'detections': 0, 'message': 'No matching threats'}
    async def good_vt(*args):
        return {'name': 'VirusTotal', 'status': 'checked', 'detections': 0, 'message': '0 threats'}
    async def failed_inspect(*args):
        return {'status': 'incomplete', 'message': 'No safe response', 'signals': []}
    monkeypatch.setattr(scanner, 'google_check', good_google)
    monkeypatch.setattr(scanner, 'virustotal_check', good_vt)
    monkeypatch.setattr(page_inspector, 'inspect_page', failed_inspect)
    report = asyncio.run(scanner.analyse_url('https://example.com', True, False, True))
    assert report['risk'] == 'unknown'
    assert report['title'] == 'Проверка выполнена частично'


def test_timeout_of_page_inspector_is_fail_closed(monkeypatch):
    async def slow(*args):
        raise asyncio.TimeoutError()
    monkeypatch.setattr(page_inspector, '_inspect_page_unlimited', slow)
    report = asyncio.run(page_inspector.inspect_page(scanner.validate_url('https://example.com')))
    assert report['status'] == 'incomplete'
