"""Synthetic-only security regression tests; never executes unsafe content."""
import asyncio
import io
import zipfile
from fastapi.testclient import TestClient
from app.file_scanner import inspect_file, analyse_file
from app.main import app


def make_zip(entries, *, compression=zipfile.ZIP_DEFLATED):
    buff = io.BytesIO()
    with zipfile.ZipFile(buff, 'w', compression=compression) as zf:
        for key, value in entries.items():
            zf.writestr(key, value)
    return buff.getvalue()


def messages(report):
    return '\n'.join(x['text'] for x in report['signals'])


def test_zip_lists_bounded_member_metadata():
    z = make_zip({'report.pdf': 'not-an-actual-pdf', 'image.png': b'1234'})
    report = inspect_file(z, 'docs.zip')
    assert report['archive']['count'] == 2
    assert {i['name'] for i in report['archive']['preview']} == {'report.pdf', 'image.png'}
    assert len(report['checks']) == 3
    assert report['content']['label'] == 'ZIP-архив'


def test_nested_unsafe_content_produces_warnings():
    z = make_zip({'photos.jpg.exe': b'MZmock', 'backup.zip': b'PKtest', '../escape.txt': 'test'})
    msg = messages(inspect_file(z, 'mydocs.zip'))
    assert 'маскирующим' in msg
    assert 'другой архив' in msg
    assert 'небезопасные пути' in msg


def test_macro_aware_office_container_and_preview():
    z = make_zip({'ppt/presentation.xml': '<presentation/>', 'ppt/vbaProject.bin': b'mock',
                  'ppt/embeddings/1.bin': b'not-real-macro'})
    report = inspect_file(z, 'lecture.pptx')
    assert report['content']['label'].startswith('Презентация PowerPoint')
    assert 'VBA' in messages(report)
    assert 'встроенные объекты' in messages(report)
    assert len(report['archive']['preview']) == 2


def test_external_relationships_checked_as_metadata_only():
    z = make_zip({'word/document.xml': '<a/>',
                  'word/_rels/document.xml.rels': '<Relationships><Relationship TargetMode="External" Target="https://example.org"/></Relationships>'})
    report = inspect_file(z, 'file.docx')
    assert 'внешние ресурсы' in messages(report)
    assert report['archive']['preview'] == []


def test_archive_bomb_metadata_warning():
    z = make_zip({'big.txt': b'0' * (3 * 1024 * 1024)})
    assert 'архивная бомба' in messages(inspect_file(z, 'compressed.zip'))


def test_archive_encrypted_flag_in_directory():
    z = make_zip({'a.txt': b'test'})
    # Set encrypted flag in central directory only. Do not decrypt file.
    raw = bytearray(z)
    index = raw.index(b'PK\x01\x02')
    flags = int.from_bytes(raw[index+8:index+10], 'little')
    raw[index+8:index+10] = (flags | 1).to_bytes(2, 'little')
    assert 'зашифрованные' in messages(inspect_file(bytes(raw), 'folder.zip'))


def test_office_external_rels_suspicious_case_insensitive():
    z = make_zip({'xl/workbook.xml': 'x', 'xl/_rels/workbook.xml.rels': '<r targetmode=\'EXTERNAL\'/>'})
    assert 'внешние ресурсы' in messages(inspect_file(z, 'sheet.xlsx'))


def test_pdf_active_embedded_and_encrypted():
    pdf = b'%PDF-1.7\n<< /OpenAction 1 /EmbeddedFile 2 /Encrypt 3 >>'
    warning = messages(inspect_file(pdf, 'report.pdf'))
    assert 'активных действий' in warning
    assert 'встроенного вложения' in warning
    assert 'шифрования' in warning


def test_program_disguised_as_pdf_is_suspicious():
    report = inspect_file(b'MZ' + b'\0'*64, 'receipt.pdf')
    assert report['content']['label'] == 'Исполняемый файл Windows'
    assert any(s['severity'] == 'high' for s in report['signals'])
    assert 'не совпадает' in messages(report)


def test_svg_and_html_active_code():
    svg = inspect_file(b'<?xml version="1.0"?><svg onload="alert(1)"/>', 'art.svg')
    assert svg['content']['label'].startswith('Изображение SVG')
    assert 'активный код' in messages(svg)
    html = inspect_file(b'<!doctype html><html><script>ok</script></html>', 'index.html')
    assert 'активный код' in messages(html)


def test_other_archive_format_discloses_not_inspected():
    report = inspect_file(b'Rar!\x1a\x07\0' + b'00', 'archive.rar')
    assert report['archive'] is None
    assert 'не анализировались' in messages(report)


def test_no_false_green_without_external_report():
    report = asyncio.run(analyse_file(b'%PDF-1.5\n%%EOF', 'report.pdf', False))
    assert report['risk'] == 'unknown'
    assert report['providers'][0]['status'] == 'skipped'


def test_api_renders_new_ui_and_metadata():
    with TestClient(app) as c:
        assert c.get('/health').json()['version'] == '1.3.1'
        page = c.get('/file')
        assert page.status_code == 200
        assert 'file-checks' in page.text
        assert 'archive-items' in page.text
        response = c.post('/api/scan-file', files={'file': ('doc.zip', make_zip({'hello.txt': 'hello'}), 'application/zip')})
    assert response.status_code == 200
    body = response.json()
    assert body['archive']['count'] == 1
    assert len(body['checks']) == 3


def test_file_preview_not_unsafe_html():
    z = make_zip({'<img src=x onerror=alert(1)>.txt': b'a'})
    report = inspect_file(z, 'test.zip')
    assert '<img' in report['archive']['preview'][0]['name']
    # Browser uses textContent, never innerHTML, for the names.
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / 'app/static/script.js').read_text()
    assert 'name.textContent = member.name' in js


def test_preview_is_capped():
    z = make_zip({f'{i:02}.txt': str(i) for i in range(30)})
    report = inspect_file(z, 'test.zip')
    assert report['archive']['count'] == 30
    assert len(report['archive']['preview']) == 10

