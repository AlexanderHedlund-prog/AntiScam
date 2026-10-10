"""Google v5 binary protobuf response regression tests. No real keys or HTTP calls."""
import asyncio
import httpx
import pytest
from app import scanner
from app.safe_browsing_wire import _SearchUrlsResponse, decode_search_urls


@pytest.fixture(autouse=True)
def clear_cache():
    scanner._GOOGLE_CACHE.clear()


def _google_mock(monkeypatch, content, content_type='application/x-protobuf'):
    original = httpx.AsyncClient
    def handler(request):
        assert request.url.path == '/v5/urls:search'
        assert request.url.params.get('urls') == 'https://example.com/'
        assert request.url.params.get('key') == 'test-key'
        return httpx.Response(200, content=content, headers={'Content-Type': content_type})
    def client_factory(*args, **kwargs):
        return original(*args, transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(scanner.httpx, 'AsyncClient', client_factory)
    return asyncio.run(scanner.google_check('https://example.com/', 'test-key'))


def test_binary_proto_clean(monkeypatch):
    proto = _SearchUrlsResponse()
    proto.cache_duration.seconds = 120
    report = _google_mock(monkeypatch, proto.SerializeToString())
    assert report['status'] == 'checked'
    assert report['detections'] == 0
    assert 'не найдено' in report['message']
    assert len(scanner._GOOGLE_CACHE) == 1


def test_binary_proto_dangerous(monkeypatch):
    proto = _SearchUrlsResponse()
    proto.cache_duration.seconds = 42
    match = proto.threats.add()
    match.url = 'https://example.com/'
    match.threat_types.extend([1, 2])
    report = _google_mock(monkeypatch, proto.SerializeToString())
    assert report['status'] == 'checked'
    assert report['detections'] == 1
    assert report['threats'] == ['MALWARE', 'SOCIAL_ENGINEERING']


@pytest.mark.parametrize('content', [b'', b'<html>Server error</html>', b'not a protobuf', b'\x00\xffbad', b'\x12\x01\x00'])
def test_invalid_binary_never_treated_as_safe(monkeypatch, content):
    report = _google_mock(monkeypatch, content)
    assert report['status'] == 'error'
    assert report['detections'] == 0
    assert not scanner._GOOGLE_CACHE


def test_proto_with_unknown_fields_cannot_be_marked_safe():
    # Valid protobuf unknown field only, but not a real v5 SearchUrlsResponse.
    with pytest.raises(ValueError):
        decode_search_urls(b'\x18\x01')


def test_unknown_threat_type_is_still_suspicious(monkeypatch):
    proto = _SearchUrlsResponse()
    proto.cache_duration.seconds = 10
    proto.threats.add().threat_types.append(123)
    report = _google_mock(monkeypatch, proto.SerializeToString())
    assert report['detections'] == 1
    assert 'UNKNOWN_THREAT_TYPE_123' in report['threats']
