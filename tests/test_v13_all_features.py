"""v1.3 deterministic + integration regressions. No external hosts are contacted."""
import asyncio
import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.scanner import validate_url, analyse_url
from app.local_url_analysis import analyse_locally
from app.page_inspector import summarise_page, _result
from app.remote_file import remote_summary, MAX_DOWNLOAD
from app.file_scanner import inspect_file

STATIC = Path(__file__).resolve().parents[1] / 'app' / 'static'


def test_download_static_pdf_safe_data_not_declared_clean():
    result = remote_summary(b'%PDF-1.7\n1 0 obj\n/JavaScript /OpenAction\nendobj\n', 'https://example.com/demo.pdf', 'application/pdf')
    assert result['status'] == 'ok'
    assert any('PDF' in s['text'] or 'активн' in s['text'] for s in result['signals'])
    assert result['sha256'] and result['size'] > 0


def test_download_masqueraded_executable_detected():
    result = remote_summary(b'MZ' + b'0'*200, 'https://example.com/slides.pdf', 'application/pdf')
    assert result['status'] == 'ok'
    assert any(s['severity'] == 'high' for s in result['signals'])


def test_html_refused_even_if_file_named_pdf():
    assert remote_summary(b'<html>Fake login</html>', 'https://example.com/f.pdf', 'application/pdf')['status'] == 'not_file'
    assert remote_summary(b'example', 'https://example.com/f.pdf', 'text/html')['status'] == 'not_file'


def test_password_form_to_external_domain_alerts():
    html = b'<html><title>Google Account</title><form action="https://elsewhere.net/post"><input type="password"></form></html>'
    report = summarise_page(html, 'https://login-portal.test/', 'text/html')
    assert report['forms'] == 1
    assert any(s['severity'] == 'high' for s in report['signals'])
    assert any('Заголовок' in s['text'] for s in report['signals'])


def test_plain_login_form_without_external_action_not_high_risk():
    report = summarise_page(b'<html><form action="/signin"><input type="password"></form></html>',
                            'https://example.com/', 'text/html')
    assert not any(s['severity'] == 'high' for s in report['signals'])


def test_redirect_chain_result_contains_no_private_query():
    report = _result('ok', 'test', redirect_chain=[{'host': 'a.example.com', 'scheme': 'https'}, {'host': 'b.example.org', 'scheme': 'https'}])
    assert 'secret' not in str(report)
    assert len(report['redirect_chain']) == 2


def test_brand_typo_with_login_lure_warned():
    report = analyse_locally(validate_url('https://paypa1-login.example.com/signin'))
    assert any(s['category'] == 'brand_spoof' for s in report['signals'])
    report2 = analyse_locally(validate_url('https://paypal.com/'))
    assert not any(s['category'] == 'brand_spoof' for s in report2['signals'])


def test_punycode_mixed_scripts():
    host = 'рaypal.example.com'.encode('idna').decode('ascii')
    report = analyse_locally(validate_url('https://' + host))
    assert any(s['category'] == 'mixed_script' for s in report['signals'])


def test_office_pdf_zip_additional_static_signals():
    pdf = inspect_file(b'%PDF-1.7\n/RichMedia /XFA\n', 'test.pdf')
    assert any('PDF' in s['text'] for s in pdf['signals'])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', '<w:document>DDEAUTO foo</w:document>')
    report = inspect_file(buf.getvalue(), 'test.docx')
    assert any('DDE' in s['text'] for s in report['signals'])


def test_six_features_appear_in_web_interface():
    with TestClient(app) as client:
        assert client.get('/health').json()['version'] == '1.3.2'
        html = client.get('/').text
    for marker in ['download-opt', 'download-inspection', 'redirect-chain', 'print-report', 'inspect-page-opt', 'own-analysis']:
        assert marker in html
    js = (STATIC/'script.js').read_text()
    assert "window.print()" in js
    assert "inspect_download: $('download-opt').checked" in js
    assert 'innerHTML = ' not in js


def test_remote_downloader_is_opt_in(monkeypatch):
    # Avoid external APIs by disabling consent; remote downloader should never be invoked.
    import app.remote_file as module
    async def deny_fetch(_link):
        raise AssertionError('NO download without opt-in')
    monkeypatch.setattr(module, 'inspect_remote_file', deny_fetch)
    report = asyncio.run(analyse_url('https://example.com/test.pdf', False, False, False, False))
    assert report['download_inspection']['status'] == 'skipped'


def test_remote_download_is_called_only_when_requested(monkeypatch):
    import app.remote_file as module
    async def fake_fetch(_link):
        return {'status': 'ok', 'message':'test', 'signals':[{'severity':'high','text':'test marker'}]}
    monkeypatch.setattr(module, 'inspect_remote_file', fake_fetch)
    report = asyncio.run(analyse_url('https://example.com/download.pdf', False, False, False, True))
    assert report['download_inspection']['status'] == 'ok'
    assert report['risk'] == 'caution'


def test_private_ips_blocked_in_redirect_validation():
    from app.scanner import URLValidationError
    import pytest
    for url in ['http://127.0.0.1/admin', 'http://169.254.169.254/latest', 'http://localhost/', 'https://10.0.0.2/', 'file:///etc/passwd']:
        with pytest.raises(URLValidationError): validate_url(url)


def test_download_budget():
    assert MAX_DOWNLOAD == 2*1024*1024
