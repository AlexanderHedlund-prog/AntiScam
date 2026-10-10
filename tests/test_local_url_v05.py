"""Synthetic samples only; no real-world malicious site is accessed."""
import asyncio
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.scanner import analyse_url, validate_url
from app.local_url_analysis import analyse_locally


@pytest.mark.parametrize('url,expected', [
    ('https://example.com/document.pdf', 'none'),
    ('https://accounts.google.com/', 'none'),
    ('https://accounts.google.co.jp/', 'none'),
    ('https://www.paypal.com/', 'none'),
    ('https://steamcommunity.com/', 'none'),
    ('http://example.net/', 'medium'),
    ('https://bit.ly/id', 'medium'),
    ('https://example.org/invoice.pdf.exe', 'high'),
    ('https://paypal-login.example.net/', 'high'),
    ('https://paypa1-verify.example.net/', 'high'),
    ('https://accounts.google.com.suspicious.test/', 'high'),
    ('https://example.net/?redirect=https%3A%2F%2Fother.example.org%2Flogin', 'medium'),
    ('https://example.net/?url=https%3A%2F%2Fsub.example.net%2Fnews', 'none'),
    ('https://example.net/?access_token=mytoken', 'medium'),
    ('https://example.net/?file=invoice.pdf.exe', 'high'),
    ('https://xn--e1afmkfd.xn--p1ai/', 'medium'),
    ('https://exaмple.com/', 'high'),
])
def test_local_analysis_classes(url, expected):
    report = analyse_locally(validate_url(url))
    assert report['level'] == expected
    assert report['status'] == 'completed'
    assert len(report['checks']) == 4
    assert 'открытия' in report['method']


def test_unknown_url_without_remote_checks_remains_unknown(monkeypatch):
    monkeypatch.delenv('GOOGLE_SAFE_BROWSING_API_KEY', raising=False)
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    report = asyncio.run(analyse_url('https://newsite.example.com/page', False, False))
    assert report['risk'] == 'unknown'
    assert report['local_analysis']['level'] == 'none'
    assert all(p['status'] == 'skipped' for p in report['providers'])


def test_local_high_signal_never_claims_confirmed_virus():
    report = asyncio.run(analyse_url('https://paypal-login.suspicious.example/test', False, False))
    assert report['risk'] == 'caution'
    assert report['local_analysis']['level'] == 'high'
    assert all(p['status'] == 'skipped' for p in report['providers'])
    assert 'вируса' in report['disclaimer'] or 'вредоносные' in report['disclaimer']


def test_private_url_token_is_not_echoed_in_display():
    report = asyncio.run(analyse_url('https://example.com/?access_token=PRIVATE123', False, False))
    assert 'PRIVATE123' not in report['display_url']
    assert 'PRIVATE123' not in str(report['local_analysis'])
    assert report['local_analysis']['level'] == 'medium'


def test_ui_and_api_v05():
    with TestClient(app) as client:
        assert client.get('/health').json()['version'] == '1.3.2'
        html = client.get('/').text
        assert 'id="own-analysis"' in html
        assert 'id="own-checks"' in html
        res = client.post('/api/scan', json={
            'url': 'https://google-login.example.net/',
            'share_with_services': False,
            'inspect_headers': False
        })
        assert res.status_code == 200
        data = res.json()
        assert data['local_analysis']['status'] == 'completed'
        assert data['local_analysis']['level'] == 'high'
        assert data['risk'] == 'caution'
        assert data['providers'][0]['status'] == 'skipped'


def test_long_query_is_bounded_and_no_live_url_fetched():
    report = asyncio.run(analyse_url('https://example.com/?a=' + 'x' * 700, False, False))
    assert report['local_analysis']['level'] == 'low'
    assert report['header_probe']['status'] == 'skipped'
    assert report['local_analysis']['limitations']
