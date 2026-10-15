"""v1.4: verdicts say what evidence exists, without a new AV engine.

All HTTP/provider responses are mocked. No user file or URL reaches third parties.
"""
import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from app import file_scanner, scanner
from app.file_assessment import assess_file
from app.local_malware import EICAR_TEST
from app.main import app


def checked(malicious=0, suspicious=0, total=72):
    return {'name':'VirusTotal (по SHA-256)','status':'checked',
            'detections':malicious, 'suspicious':suspicious, 'total':total}


def test_four_real_world_outcomes_have_clear_next_step():
    danger = assess_file(checked(4), [], False)
    assert danger['risk'] == 'danger' and 'Не открывайте' in danger['recommendation']
    caution = assess_file(checked(1), [], False)
    assert caution['risk'] == 'caution' and 'риск' in caution['quick_verdict']['answer']
    low = assess_file(checked(), [], False)
    assert low['risk'] == 'low' and 'не обнаружено' in low['quick_verdict']['answer']
    unknown = assess_file({'status':'no_data'}, [], False)
    assert unknown['risk'] == 'unknown' and 'антивирусной проверки' in unknown['quick_verdict']['answer'].lower()
    assert all(report['recommendation'] for report in (danger,caution,low,unknown))
    assert 'точно безопасен' not in str(low)


def test_eicar_only_never_claims_real_malware_even_if_av_detections_are_high(monkeypatch):
    async def result(*_): return checked(66, 0, 75)
    monkeypatch.setattr(file_scanner, 'virustotal_hash_lookup', result)
    report = asyncio.run(file_scanner.analyse_file(EICAR_TEST, 'eicar.com.txt', True))
    assert report['eicar_test_only'] is True
    assert report['risk'] == 'caution'
    assert 'не настоящий вирус' in report['quick_verdict']['answer']
    # A larger file containing the test string is not automatically exempt.
    other = asyncio.run(file_scanner.analyse_file(EICAR_TEST + b'other payload', 'payload.txt', True))
    assert other['eicar_test_only'] is False
    assert other['risk'] == 'danger'


def test_partial_archive_does_not_turn_green_after_clean_vt(monkeypatch):
    async def result(*_): return checked()
    monkeypatch.setattr(file_scanner, 'virustotal_hash_lookup', result)
    report = asyncio.run(file_scanner.analyse_file(b'Rar!\x1a\x07\x00payload', 'archive.rar', True))
    assert report['inspection_coverage']['status'] == 'partial'
    assert report['risk'] != 'low'
    assert 'полной' not in report['quick_verdict']['answer'].lower()


def test_hash_lookup_exposes_only_bounded_detection_names(monkeypatch):
    class Reply:
        status_code=200
        def json(self):
            return {'data':{'attributes':{'last_analysis_date':1760000000,
                'last_analysis_stats':{'malicious':3,'undetected':12,'timeout':4},
                'last_analysis_results': {f'AV{i}': {'category':'malicious','result':'Example.Sample'} for i in range(10)}}}}
    class Client:
        def __init__(self,*a,**kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self,*a): return None
        async def get(self,*a,**kw): return Reply()
    async def slot(): return True
    monkeypatch.setattr(file_scanner.httpx,'AsyncClient',Client)
    monkeypatch.setattr(file_scanner,'take_virustotal_slot',slot)
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','private-test-key')
    report = asyncio.run(file_scanner.virustotal_hash_lookup('a'*64, True))
    assert report['total'] == 15 and report['unavailable'] == 4
    assert len(report['engine_findings']) == 5
    assert report['last_analysis_date'] == 1760000000


def test_no_consent_does_not_query_external_service(monkeypatch):
    async def stop(*_): raise AssertionError('No VirusTotal request without consent')
    monkeypatch.setattr(file_scanner, 'take_virustotal_slot', stop)
    report = asyncio.run(file_scanner.analyse_file(b'example data', 'example.txt', False))
    assert report['providers'][0]['status'] == 'skipped'
    assert report['risk'] == 'unknown'


def test_url_also_has_specific_recommended_action(monkeypatch):
    report = asyncio.run(scanner.analyse_url('https://paypa1-login.invalid/', False, False))
    assert report['risk'] == 'caution'
    assert 'Не переходите' in report['recommendation']


def test_v140_assets_and_no_extra_scan_server():
    with TestClient(app) as client:
        assert client.get('/health').json()['version'] == '1.4.0'
        assert client.get('/file').status_code == 200
    source = Path('app/static/script.js').read_text()
    assert 'data.eicar_test_only' in source or 'lastFileReport.eicar_test_only' in source
    assert 'next-check' in source
    assert 'window.print()' in source
    assert 'http://localhost:3310' not in source
