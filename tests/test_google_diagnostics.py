"""Regression tests for Safe Browsing v5 and safe diagnostic messages."""
import asyncio
import httpx
from app import scanner


def _run_case(monkeypatch, status, body, expected):
    scanner._GOOGLE_CACHE.clear()
    real_client = httpx.AsyncClient
    seen = {}
    def handler(request):
        seen['path'] = request.url.path
        seen['query'] = str(request.url.query)
        return httpx.Response(status, json=body) if isinstance(body, dict) else httpx.Response(status, content=body)
    def client_factory(*args, **kwargs):
        kwargs['transport'] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)
    monkeypatch.setattr(scanner.httpx, 'AsyncClient', client_factory)
    result = asyncio.run(scanner.google_check('https://example.com/', 'hidden-test-key'))
    assert expected in result['message']
    assert 'hidden-test-key' not in str(result)
    assert '/v5/urls:search' in seen['path']
    assert 'alt=json' in seen['query']
    return result


def test_google_v5_success(monkeypatch):
    result = _run_case(monkeypatch, 200, {'threats': [], 'cacheDuration': '5s'}, 'не найдено')
    assert result['status'] == 'checked'


def test_google_403_diagnostic(monkeypatch):
    result = _run_case(monkeypatch, 403, {'error': 'blocked'}, 'HTTP 403')
    assert result['status'] == 'error'


def test_google_200_non_json(monkeypatch):
    result = _run_case(monkeypatch, 200, b'\x00\xffnot-json', 'не в формате JSON')
    assert result['status'] == 'error'


def test_google_429(monkeypatch):
    result = _run_case(monkeypatch, 429, {'error': 'quota'}, 'HTTP 429')
    assert result['status'] == 'error'


def test_google_invalid_shape(monkeypatch):
    result = _run_case(monkeypatch, 200, {'threats': 'bad'}, 'Неожиданный формат')
    assert result['status'] == 'error'
