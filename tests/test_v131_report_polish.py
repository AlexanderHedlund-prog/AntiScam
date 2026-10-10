"""Regression tests for v1.3.1: accurate download summaries and report layout."""
import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.scanner import analyse_url

BASE = Path(__file__).resolve().parents[1] / 'app' / 'static'


def test_opted_in_real_pdf_has_no_file_not_downloaded_falsehood(monkeypatch):
    from app import remote_file

    async def demo_pdf(_link):
        return {'status': 'ok', 'kind': 'PDF-документ', 'size': 13312,
                'message': 'Файл получен и проверен статически.', 'signals': []}

    monkeypatch.setattr(remote_file, 'inspect_remote_file', demo_pdf)
    report = asyncio.run(analyse_url('https://www.w3.org/example/demo.pdf', False, False, False, True))
    assert report['download_inspection']['status'] == 'ok'
    assert report['content']['label'] == 'PDF-документ'
    assert report['content']['confidence'] == 'high'
    assert 'Файл получен' in report['content']['basis']
    assert 'файл не загружался' not in report['content']['basis'].lower()
    assert 'Файл по ссылке был получен' in report['disclaimer']
    assert 'загрузки не выполняются' not in report['disclaimer']
    assert report['risk'] == 'unknown'  # No external antivirus verdict.


def test_guessed_format_remains_a_guess_without_network(monkeypatch):
    result = asyncio.run(analyse_url('https://example.com/demo.pdf', False, False, False, False))
    assert result['content']['confidence'] == 'low'
    assert 'не загружался' in result['content']['basis']
    assert result['download_inspection']['status'] == 'skipped'


def test_page_scan_is_not_misreported_as_file_analysis(monkeypatch):
    import app.page_inspector as pi

    async def mock_inspect(_):
        return {'status': 'ok', 'message': 'HTML fragment only', 'signals': [], 'mime': 'text/html', 'kind': 'HTML-страница'}

    monkeypatch.setattr(pi, 'inspect_page', mock_inspect)
    report = asyncio.run(analyse_url('https://example.com/', False, False, True, False))
    assert report['content']['label'] == 'HTML-страница'
    assert 'фрагмент HTML' in report['content']['basis']
    assert 'Содержимое веб-страницы полностью не исследовалось.' not in report['disclaimer']


def test_no_double_large_verdict_or_duplicate_passive_message():
    index = (BASE / 'index.html').read_text(encoding='utf-8')
    js = (BASE / 'script.js').read_text(encoding='utf-8')
    assert 'id="url-quick-verdict"' in index
    assert '<span class="own-tag">v1.3.1</span>' in index
    assert 'id="risk-banner"' not in index
    assert 'ПОДРОБНЫЙ РЕЗУЛЬТАТ' not in index
    assert 'id="url-signal-section"' in index
    assert 'signal passive' not in js
    assert 'СОДЕРЖИМОЕ ПОЛУЧЕННОГО ФАЙЛА' in js


def test_print_rules_keep_provider_cards_intact_and_stamp():
    css = (BASE / 'styles.css').read_text(encoding='utf-8')
    assert 'break-inside:avoid-page!important' in css
    assert '.provider, .signal' in css
    assert '.report-stamp' in css
    with TestClient(app) as client:
        assert client.get('/health').json()['version'] == '1.3.1'
        assert client.get('/').status_code == 200
        assert client.get('/agreement').status_code == 200


def test_download_local_url_summary_does_not_deny_fetch(monkeypatch):
    from app import remote_file

    async def response(_link):
        return {'status': 'ok', 'kind':'PDF-документ', 'size':4, 'message':'test', 'signals':[]}

    monkeypatch.setattr(remote_file, 'inspect_remote_file', response)
    result=asyncio.run(analyse_url('https://example.com/demo.pdf', False,False,False,True))
    local=result['local_analysis']
    assert 'Отдельно выполнен статический анализ' in local['summary']
    assert 'Результат проверки полученного файла' in local['limitations']
    assert 'Мы не загружали сайт' not in local['limitations']


def test_skip_notices_collapsed_only_in_url_reports():
    js=(BASE/'script.js').read_text(encoding='utf-8')
    assert "availableProviders.every(provider => provider.status === 'skipped')" in js
    assert 'Google Safe Browsing и VirusTotal не запрашивались' in js
