"""Safe Browsing v5 SearchUrlsResponse binary Protocol Buffers decoder.

Uses a tiny, explicit subset of Google's documented wire schema, not ad-hoc
parsing of possibly malicious response bytes. URL strings from the response
are never displayed or logged. If parsing is uncertain, callers fail closed.
"""
from __future__ import annotations

from google.protobuf import descriptor_pb2, descriptor_pool, duration_pb2, message_factory
from google.protobuf.message import DecodeError

MAX_RESPONSE_BYTES = 65_536
_TYPE_NAMES = {
    0: 'THREAT_TYPE_UNSPECIFIED',
    1: 'MALWARE',
    2: 'SOCIAL_ENGINEERING',
    3: 'UNWANTED_SOFTWARE',
    4: 'POTENTIALLY_HARMFUL_APPLICATION',
}


def _build_message_type():
    f = descriptor_pb2.FileDescriptorProto()
    f.name = 'antiscam/safe_browsing_v5_response.proto'
    f.package = 'antiscam_safebrowsing_v5'
    f.syntax = 'proto3'
    f.dependency.append('google/protobuf/duration.proto')

    threat = f.message_type.add()
    threat.name = 'ThreatUrl'
    field = threat.field.add()
    field.name, field.number, field.label, field.type = 'url', 1, 1, 9  # string
    field = threat.field.add()
    field.name, field.number, field.label, field.type = 'threat_types', 2, 3, 5  # repeated enum number

    result = f.message_type.add()
    result.name = 'SearchUrlsResponse'
    field = result.field.add()
    field.name, field.number, field.label, field.type = 'threats', 1, 3, 11
    field.type_name = '.antiscam_safebrowsing_v5.ThreatUrl'
    field = result.field.add()
    field.name, field.number, field.label, field.type = 'cache_duration', 2, 1, 11
    field.type_name = '.google.protobuf.Duration'

    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(duration_pb2.DESCRIPTOR.serialized_pb)
    pool.Add(f)
    return message_factory.GetMessageClass(
        pool.FindMessageTypeByName('antiscam_safebrowsing_v5.SearchUrlsResponse')
    )


_SearchUrlsResponse = _build_message_type()


def decode_search_urls(data: bytes) -> dict:
    """Convert a structurally valid binary protobuf to the REST JSON-shaped dict.

    Requires cache_duration field to prevent arbitrary binary responses,
    even valid protobuf unknown-fields, from being called clean.
    """
    if not data or len(data) > MAX_RESPONSE_BYTES:
        raise ValueError('Missing or oversize Safe Browsing protobuf response')
    response = _SearchUrlsResponse()
    try:
        response.ParseFromString(data)
    except (DecodeError, ValueError) as exc:
        raise ValueError('Invalid Safe Browsing protobuf response') from exc
    if not response.HasField('cache_duration'):
        raise ValueError('Safe Browsing protobuf missing cache duration')
    duration = response.cache_duration
    if duration.seconds < 0 or duration.nanos < 0 or duration.nanos >= 1_000_000_000:
        raise ValueError('Invalid Safe Browsing cache duration')
    return {
        'threats': [
            {
                'threatTypes': [
                    _TYPE_NAMES.get(int(t), f'UNKNOWN_THREAT_TYPE_{t}')
                    for t in match.threat_types
                ],
            }
            for match in response.threats
        ],
        'cacheDuration': f'{duration.seconds + duration.nanos / 1_000_000_000:.9f}s',
    }
