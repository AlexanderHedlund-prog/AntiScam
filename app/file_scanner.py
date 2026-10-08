"""Conservative, offline file metadata inspection + optional VirusTotal HASH lookup.

Never runs, extracts, opens or uploads the input to outside services.
No local malware engine is bundled: results are NOT antivirus certification.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from pathlib import PurePath
from typing import Any

import httpx

from app.reputation_quota import take_virustotal_slot

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_MULTIPART_BYTES = MAX_FILE_BYTES + 1024 * 1024
SCRIPT_EXT = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.ps1', '.js', '.jse', '.hta', '.jar', '.msi', '.apk', '.lnk', '.sh', '.py', '.com'}
MACRO_EXT = {'.docm', '.xlsm', '.pptm'}
DOC_EXT = {'.pdf', '.docx', '.pptx', '.xlsx', '.odt', '.odp', '.ods', '.doc', '.ppt', '.xls'}
FILES_INSIDE_RE = re.compile(r'\.(?:pdf|docx?|pptx?|xlsx?|jpg|png)\.(?:exe|scr|bat|cmd|js|vbs|ps1|lnk)$', re.I)


def _safe_filename(name: str | None) -> str:
    # A filename is untrusted user input, even when sent by a browser.
    value = (name or 'без_названия').replace('\\', '/').split('/')[-1]
    value = ''.join(ch for ch in value if ch.isprintable() and ord(ch) >= 32)
    return (value.strip() or 'без_названия')[:130]


def _magic(data: bytes) -> tuple[str, str]:
    p = data[:512]
    if p.startswith(b'%PDF-'): return 'PDF-документ', 'pdf'
    if p.startswith(b'MZ'): return 'Исполняемый файл Windows', 'executable'
    if p.startswith(b'\x7fELF'): return 'Исполняемый файл Linux', 'executable'
    if p.startswith((b'\xfe\xed\xfa\xce', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe')): return 'Программа macOS', 'executable'
    if p.startswith(b'PK\x03\x04') or p.startswith(b'PK\x05\x06'): return 'ZIP-архив', 'zip'
    if p.startswith(b'\x89PNG\r\n\x1a\n'): return 'Изображение PNG', 'image'
    if p.startswith(b'\xff\xd8\xff'): return 'Изображение JPEG', 'image'
    if p.startswith((b'GIF89a', b'GIF87a')): return 'Изображение GIF', 'image'
    if p.startswith(b'RIFF') and p[8:12] == b'WEBP': return 'Изображение WebP', 'image'
    if p.startswith(b'Rar!\x1a\x07'): return 'RAR-архив', 'archive'
    if p.startswith(b'7z\xbc\xaf\x27\x1c'): return '7z-архив', 'archive'
    if p.startswith(b'\x1f\x8b'): return 'GZIP-архив', 'archive'
    if p.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'): return 'Документ Microsoft Office старого формата', 'office_legacy'
    if len(p) > 12 and p[4:8] == b'ftyp': return 'Медиафайл MP4', 'media'
    stripped = p.lstrip(b'\xef\xbb\xbf \t\n\r').lower()
    if stripped.startswith((b'<!doctype html', b'<html')): return 'HTML-страница', 'html'
    if stripped.startswith(b'<?xml'): return 'XML-документ', 'xml'
    if b'\x00' not in p:
        try:
            data[:min(len(data), 4096)].decode('utf-8')
            return 'Текстовый файл', 'text'
        except UnicodeDecodeError:
            pass
    return 'Неизвестный бинарный формат', 'unknown'


def _signal(severity: str, message: str) -> dict[str, str]:
    return {'severity': severity, 'text': message}


def inspect_file(data: bytes, uploaded_name: str) -> dict[str, Any]:
    """Inspect file bytes without executing, extracting or network access."""
    if not data:
        raise ValueError('Нельзя проверить пустой файл.')
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('Файл слишком большой. Максимальный размер — 8 МБ.')
    name = _safe_filename(uploaded_name)
    ext = PurePath(name.lower()).suffix.lower()
    label, kind = _magic(data)
    signals: list[dict[str, str]] = []
    if kind == 'zip':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                names = {info.filename.lower() for info in infos[:2000]}
                if 'ppt/presentation.xml' in names:
                    label, kind = 'Презентация PowerPoint (PPTX)', 'presentation'
                elif 'word/document.xml' in names:
                    label, kind = 'Документ Microsoft Word (DOCX)', 'document'
                elif 'xl/workbook.xml' in names:
                    label, kind = 'Таблица Microsoft Excel (XLSX)', 'spreadsheet'
                elif 'mimetype' in names:
                    # Office OpenDocument files are ZIP-based. Inspect only tiny mimetype.
                    info = next((i for i in infos if i.filename.lower() == 'mimetype'), None)
                    if info and info.file_size < 150 and not info.flag_bits & 1:
                        mime = archive.read(info).decode('ascii', errors='replace')
                        if mime == 'application/vnd.oasis.opendocument.presentation':
                            label, kind = 'Презентация OpenDocument (ODP)', 'presentation'
                        elif mime == 'application/vnd.oasis.opendocument.text':
                            label, kind = 'Документ OpenDocument (ODT)', 'document'
                        elif mime == 'application/vnd.oasis.opendocument.spreadsheet':
                            label, kind = 'Таблица OpenDocument (ODS)', 'spreadsheet'
                if len(infos) > 1000:
                    signals.append(_signal('medium', 'В архиве слишком много элементов; проверяйте его отдельно.'))
                if sum(i.file_size for i in infos) > 256 * 1024 * 1024:
                    signals.append(_signal('high', 'При распаковке архив может потребовать очень много места.'))
                if any(i.file_size > 2 * 1024 * 1024 and i.file_size / max(1, i.compress_size) > 150 for i in infos):
                    signals.append(_signal('high', 'У архива подозрительно высокая степень сжатия.'))
                if any(i.flag_bits & 1 for i in infos):
                    signals.append(_signal('medium', 'Некоторые части архива зашифрованы, их содержимое не анализировалось.'))
                if any('vbaproject.bin' in n for n in names):
                    signals.append(_signal('high', 'В документе обнаружены макросы VBA. Не разрешайте их запуск.'))
                if any('/embeddings/' in n for n in names):
                    signals.append(_signal('medium', 'В Office-файле есть встроенные объекты.'))
                if any(PurePath(n).suffix.lower() in SCRIPT_EXT for n in names):
                    signals.append(_signal('high', 'Архив содержит файлы с исполняемыми расширениями.'))
                if any(FILES_INSIDE_RE.search(n) for n in names):
                    signals.append(_signal('high', 'Внутри архива есть имя с маскирующим двойным расширением.'))
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError):
            signals.append(_signal('medium', 'Архив повреждён или имеет неподдерживаемый формат.'))
    if kind == 'executable':
        signals.append(_signal('high', 'Содержимое похоже на исполняемую программу. Не запускайте неизвестные файлы.'))
    if ext in SCRIPT_EXT:
        signals.append(_signal('high', 'Расширение файла связано с программами или скриптами.'))
    if ext in MACRO_EXT:
        signals.append(_signal('medium', 'Расширение допускает макросы, даже если их наличие не подтверждено.'))
    if FILES_INSIDE_RE.search(name):
        signals.append(_signal('high', 'Двойное расширение маскирует исполняемый файл под документ.'))
    expected = {
        '.pdf': {'pdf'}, '.pptx': {'presentation'}, '.docx': {'document'},
        '.xlsx': {'spreadsheet'}, '.png': {'image'}, '.jpg': {'image'}, '.jpeg': {'image'},
        '.zip': {'zip'}, '.exe': {'executable'},
    }
    if ext in expected and kind not in expected[ext]:
        signals.append(_signal('high' if kind == 'executable' else 'medium',
                               'Фактический формат не совпадает с расширением имени файла.'))
    # Search a *small bounded part* for potentially active PDF content. Not a PDF parser.
    if kind == 'pdf' and (b'/JavaScript' in data[:250000] or b'/Launch' in data[:250000]):
        signals.append(_signal('medium', 'В PDF встречаются признаки активного содержимого.'))

    return {
        'filename': name,
        'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'content': {'label': label, 'basis': 'Предварительное определение по сигнатуре файла и структуре контейнера; не антивирусное сканирование'},
        'signals': signals,
    }


async def virustotal_hash_lookup(digest: str, consent: bool) -> dict[str, Any]:
    provider = 'VirusTotal (по SHA-256)'
    if not consent:
        return {'name': provider, 'status': 'skipped', 'message': 'Вы не разрешили проверку хеша по внешней базе.'}
    key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return {'name': provider, 'status': 'skipped', 'message': 'API-ключ VirusTotal ещё не подключён.'}
    if not await take_virustotal_slot():
        return {'name': provider, 'status': 'error', 'message': 'Лимит бесплатных проверок VirusTotal. Повторите примерно через минуту.'}
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
            resp = await client.get(f'https://www.virustotal.com/api/v3/files/{digest}',
                                    headers={'x-apikey': key, 'accept': 'application/json'})
        if resp.status_code == 404:
            return {'name': provider, 'status': 'no_data', 'message': 'В базе нет отчёта для этого SHA-256. Файл не отправлялся.'}
        if resp.status_code == 429:
            return {'name': provider, 'status': 'error', 'message': 'Превышен лимит VirusTotal.'}
        if resp.status_code in (401, 403):
            return {'name': provider, 'status': 'error', 'message': 'Ключ VirusTotal отклонён: проверьте права API.'}
        if resp.status_code != 200:
            return {'name': provider, 'status': 'error', 'message': f'База временно недоступна (HTTP {resp.status_code}).'}
        stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if not stats:
            return {'name': provider, 'status': 'no_data', 'message': 'Отчёт есть, но данных о результатах сканирования нет.'}
        malicious = max(0, int(stats.get('malicious', 0)))
        suspicious = max(0, int(stats.get('suspicious', 0)))
        total = sum(max(0, int(v)) for v in stats.values() if isinstance(v, int))
        return {'name': provider, 'status': 'checked', 'detections': malicious,
                'suspicious': suspicious, 'total': total,
                'message': f'Результаты имеющегося отчёта: {malicious} опасных, {suspicious} подозрительных из {total}.'}
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return {'name': provider, 'status': 'error', 'message': 'Не удалось получить результаты из базы.'}


async def analyse_file(data: bytes, uploaded_name: str, consent: bool) -> dict[str, Any]:
    report = inspect_file(data, uploaded_name)
    reputation = await virustotal_hash_lookup(report['sha256'], consent)
    signals = report['signals']
    if reputation.get('status') == 'checked' and reputation.get('detections', 0) >= 2:
        risk, title, detail = 'danger', 'Обнаружены известные угрозы', 'Согласно базе VirusTotal, несколько систем отметили файл как опасный.'
    elif signals or reputation.get('detections', 0) or reputation.get('suspicious', 0):
        risk, title, detail = 'caution', 'Есть повод насторожиться', 'Выявлены подозрительные признаки. Они не доказывают наличие вируса.'
    elif reputation.get('status') == 'checked':
        risk, title, detail = 'low', 'Известных угроз не найдено', 'По существующему отчёту известные угрозы не выявлены, но это не означает, что файл безопасен.'
    else:
        risk, title, detail = 'unknown', 'Безопасность не установлена', 'Тип файла определён, но без результата антивирусной проверки нельзя сделать вывод о наличии вирусов.'
    return {**report, 'risk': risk, 'title': title, 'detail': detail,
            'providers': [reputation],
            'disclaimer': 'Файл не запускался и не отправлялся в VirusTotal. Сервис определяет формат и проверяет доступные данные по SHA-256, но не заменяет антивирус.'}
