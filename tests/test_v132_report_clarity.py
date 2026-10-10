"""Regressions from October v1.3.1 real-browser review, no external requests."""
import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app import scanner, remote_file, page_inspector

STATIC = Path(__file__).resolve().parents[1] / 'app' / 'static'


def test_version_and_text_markers():
    with TestClient(app) as client:
        assert client.get('/health').json()['version'] == '1.3.2'
        index = client.get('/').text
    assert index.count('v1.3.2') >= 2
    assert 'id="download-meta"' in index


def test_json_is_not_misdescribed_as_html(monkeypatch):
    async def inspector(_):
        return {'status':'ok', 'kind':'Данные JSON (по Content-Type)', 'mime':'application/json',
                'signals':[], 'message':'Ответ прочитан', 'bytes_read':681}
    monkeypatch.setattr(page_inspector, 'inspect_page', inspector)
    result = asyncio.run(scanner.analyse_url('https://httpbingo.org/redirect/2', False, False, True, False))
    assert 'JSON' in result['content']['label']
    assert 'фрагмент HTML' not in result['content']['basis']
    assert 'фрагмент HTML' not in result['disclaimer']
    assert 'фрагмент HTML' not in result['local_analysis']['summary']
    script = (STATIC / 'script.js').read_text()
    assert "const htmlResponse = info.status === 'ok'" in script
    assert "classList.toggle('hidden', !htmlResponse)" in script


def test_html_instead_of_file_has_separate_neutral_state(monkeypatch):
    assert remote_file.remote_summary(b'<html><body>Welcome</body></html>', 'https://example.com/demo.pdf', 'text/html')['status'] == 'not_file'
    async def html_response(_):
        return {'status':'not_file', 'kind':'HTML-страница', 'message':'По адресу находится веб-страница, не файл', 'signals':[]}
    monkeypatch.setattr(remote_file, 'inspect_remote_file', html_response)
    report = asyncio.run(scanner.analyse_url('https://example.com/', False, False, False, True))
    assert report['download_inspection']['status'] == 'not_file'
    assert report['content']['label'].startswith('HTML-страница')
    assert report['risk'] == 'unknown'
    assert 'файл получен' not in report['content']['basis'].lower()
    script=(STATIC/'script.js').read_text()
    assert "'Это веб-страница, не файл'" in script
    assert "$('download-meta').classList.toggle('hidden', info.status !== 'ok')" in script


def test_html_not_file_does_not_discredit_two_clean_provider_reports(monkeypatch):
    async def clean_google(*_): return {'name':'Google Safe Browsing', 'status':'checked', 'detections':0, 'message':'Not found'}
    async def clean_vt(*_): return {'name':'VirusTotal', 'status':'checked', 'detections':0, 'suspicious':0, 'message':'Not found'}
    async def html_response(_): return {'status':'not_file', 'kind':'HTML-страница', 'signals':[]}
    monkeypatch.setattr(scanner, 'google_check', clean_google)
    monkeypatch.setattr(scanner, 'virustotal_check', clean_vt)
    monkeypatch.setattr(remote_file, 'inspect_remote_file', html_response)
    report = asyncio.run(scanner.analyse_url('https://example.com/', True, False, False, True))
    assert report['risk'] == 'low'  # Not falsely a failed antivirus check.


def test_download_success_without_av_keeps_unknown_risk_but_explains_it(monkeypatch):
    async def pdf(_): return {'status':'ok', 'kind':'PDF-документ', 'size':13312, 'signals':[]}
    monkeypatch.setattr(remote_file, 'inspect_remote_file', pdf)
    report = asyncio.run(scanner.analyse_url('https://www.w3.org/dummy.pdf', False, False, False, True))
    assert report['risk'] == 'unknown'
    assert report['quick_verdict']['answer'] == 'Антивирусный статус не установлен'
    assert 'Файл получен' in report['quick_verdict']['note']


def test_http_404_is_explicit_and_not_a_virus_warning(monkeypatch):
    class Resp:
        status=404
        headers={}
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return None
    class Session:
        def __init__(self,*args,**kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return None
        def get(self,*args,**kwargs): return Resp()
        def head(self,*args,**kwargs): return Resp()
    monkeypatch.setattr(page_inspector.aiohttp, 'ClientSession', Session)
    report = asyncio.run(page_inspector.inspect_page(scanner.validate_url('https://httpbingo.org/status/404')))
    assert report['status'] == 'incomplete'
    assert report['http_status'] == 404
    assert 'страница не найдена' in report['message']
    assert 'не является признаком вируса' in report['message']
    head = asyncio.run(scanner.probe_content(scanner.validate_url('https://httpbingo.org/status/404')))
    assert head['http_status'] == 404
    assert 'страница не найдена' in head['message']


def test_inactive_bases_not_called_missing_consent(monkeypatch):
    async def failure(*_): raise AssertionError('External API must not be called')
    monkeypatch.setattr(scanner, 'google_check', failure)
    monkeypatch.setattr(scanner, 'virustotal_check', failure)
    report = asyncio.run(scanner.analyse_url('https://example.com', False, False, False, False))
    assert all(p['status']=='skipped' for p in report['providers'])
    js=(STATIC/'script.js').read_text()
    assert 'выключена в настройках' in js
    assert 'согласие на передачу URL не предоставлено' not in js
