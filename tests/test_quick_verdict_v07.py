"""Clear answers must not overclaim that JavaScript can prove malware absence."""
import asyncio
from app.quick_verdict import build_quick_verdict
from app import scanner, file_scanner


def test_all_four_url_states_distinct():
    a = [build_quick_verdict(risk, kind='url') for risk in ('danger', 'caution', 'low', 'unknown')]
    assert len({v['answer'] for v in a}) == 4
    assert all(v['state'] == risk for risk, v in zip(('danger', 'caution', 'low', 'unknown'), a))


def test_no_false_certainty_on_clean_link_or_file():
    for kind in ('url', 'file'):
        verdict = build_quick_verdict('low', kind=kind)
        assert 'не обнаружено' in verdict['answer'].lower()
        assert 'нет вируса' not in verdict['answer'].lower()
        assert 'не ' in verdict['note'].lower() or 'может' in verdict['note'].lower()


def test_phishing_does_not_claim_virus():
    verdict = build_quick_verdict('danger', kind='url')
    assert 'угроз' in verdict['answer'].lower()
    assert 'фишинг' in verdict['note'].lower()


def test_suspicion_not_called_confirmed():
    for kind in ('url', 'file'):
        verdict = build_quick_verdict('caution', kind=kind)
        assert 'не подтверждён' in verdict['answer']


def test_unknown_is_explicit():
    for kind in ('url', 'file'):
        verdict = build_quick_verdict('unknown', kind=kind)
        assert verdict['state'] == 'unknown'
        assert 'невозможно' in verdict['answer'].lower()


def test_url_endpoint_report_has_quick_verdict(monkeypatch):
    monkeypatch.delenv('GOOGLE_SAFE_BROWSING_API_KEY', raising=False)
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    report = asyncio.run(scanner.analyse_url('https://example.com/', False, False))
    assert report['quick_verdict']['state'] == 'unknown'
    assert report['risk'] == 'unknown'


def test_file_report_has_quick_verdict_without_vt():
    report = asyncio.run(file_scanner.analyse_file(b'hello world', 'readme.txt', False))
    assert report['quick_verdict']['state'] == 'unknown'


def test_file_risky_extension_cannot_be_called_clean():
    report = asyncio.run(file_scanner.analyse_file(b'MZ'+b'0'*80, 'presentation.pdf', False))
    assert report['quick_verdict']['state'] in ('caution', 'danger')
