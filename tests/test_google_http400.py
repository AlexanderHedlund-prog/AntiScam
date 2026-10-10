"""Mock-only regressions for non-leaking provider diagnostics."""
import asyncio
import httpx
from app import scanner


def _check(monkeypatch, status, body, expected_reason):
    scanner._GOOGLE_CACHE.clear()
    original = httpx.AsyncClient
    def handle(req):
        assert req.method == 'GET'
        assert req.url.path == '/v5/urls:search'
        assert req.url.params.get('urls') == 'https://example.com/'
        assert 'alt' not in req.url.params
        return httpx.Response(status_code=status, json=body) if isinstance(body, dict) else httpx.Response(status_code=status, content=body)
    def factory(*args, **kwargs):
        return original(*args, transport=httpx.MockTransport(handle), **kwargs)
    monkeypatch.setattr(scanner.httpx, 'AsyncClient', factory)
    response = asyncio.run(scanner.google_check('https://example.com/', 'secret-example-key'))
    assert response['status'] == 'error'
    assert response['diagnostic_code'] == expected_reason
    assert 'secret-example-key' not in str(response)
    return response


def test_invalid_api_key_google400(monkeypatch):
    data = {'error': {'code': 400, 'message': 'API key not valid. Please pass a valid API key.', 'details': [{'reason': 'API_KEY_INVALID'}]}}
    r = _check(monkeypatch, 400, data, 'API_KEY_INVALID')
    assert 'API-ключ' in r['message']


def test_api_disabled_google400(monkeypatch):
    data = {'error': {'code': 400, 'details': [{'reason': 'API_KEY_SERVICE_BLOCKED'}]}}
    r = _check(monkeypatch, 400, data, 'API_NOT_ENABLED')
    assert 'Google Cloud' in r['message']


def test_restricted_referrer_google400(monkeypatch):
    data = {'error': {'details': [{'reason': 'API_KEY_HTTP_REFERRER_BLOCKED'}]}}
    r = _check(monkeypatch, 400, data, 'KEY_RESTRICTION')
    assert 'Render' in r['message']


def test_generic_google400_does_not_echo_sensitive_remote_text(monkeypatch):
    data = {'error': {'code': 400, 'message': 'malformed token=SECRETUSERDATA url=https://example.com/?token=XXXX'}}
    r = _check(monkeypatch, 400, data, 'HTTP_400_UNCLASSIFIED')
    assert 'SECRETUSERDATA' not in str(r)
    assert 'XXXX' not in str(r)


def test_proto_error_reason_google400(monkeypatch):
    data = b'\x02type.googleapis.com/google.rpc.ErrorInfo: API_KEY_INVALID Google says secret-token-XYZ'
    r = _check(monkeypatch, 400, data, 'API_KEY_INVALID')
    assert 'secret-token-XYZ' not in str(r)


def test_invalid_arguments_google400(monkeypatch):
    data = {'error': {'status': 'INVALID_ARGUMENT'}}
    r = _check(monkeypatch, 400, data, 'INVALID_ARGUMENT')
    assert 'параметры' in r['message']
