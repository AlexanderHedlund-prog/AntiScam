"""Conservative file inspection and VirusTotal hash lookup.

With separate user permission AND an explicit owner setting, a previously
unknown file can also be uploaded to VirusTotal (public submission).
No uploaded bytes are executed. No result certifies that a file is safe.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import stat
import zipfile
import unicodedata
from pathlib import PurePath
from typing import Any

import httpx

from app.reputation_quota import take_virustotal_slot
from app.file_assessment import assess_file
from app.local_malware import inspect_malware_indicators, EICAR_TEST
from app.vt_file_submission import submit_unknown_file, uploads_enabled

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_MULTIPART_BYTES = MAX_FILE_BYTES + 1024 * 1024
SCRIPT_EXT = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.ps1', '.js', '.jse', '.hta', '.jar', '.msi', '.apk', '.lnk', '.sh', '.py', '.com', '.pif'}
MACRO_EXT = {'.docm', '.xlsm', '.pptm'}
NESTED_ARCHIVES = {'.zip', '.rar', '.7z', '.iso', '.img', '.tar', '.gz'}
MAX_ARCHIVE_PREVIEW = 10
MAX_REL_FILES = 16
MAX_REL_BYTES = 32 * 1024
DOC_EXT = {'.pdf', '.docx', '.pptx', '.xlsx', '.odt', '.odp', '.ods', '.doc', '.ppt', '.xls'}
FILES_INSIDE_RE = re.compile(r'\.(?:pdf|docx?|pptx?|xlsx?|jpg|png)\.(?:exe|scr|bat|cmd|js|vbs|ps1|lnk)$', re.I)


def _safe_filename(name: str | None) -> str:
    # A filename is untrusted user input, even when sent by a browser.
    value = (name or 'без_названия').replace('\\', '/').split('/')[-1]
    value = ''.join(ch for ch in value if ch.isprintable() and ord(ch) >= 32 and unicodedata.category(ch) != 'Cf')
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
    if stripped.startswith(b'<svg') or b'<svg ' in stripped[:400]: return 'Изображение SVG (векторное)', 'svg'
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


def _entry_name(name: str) -> str:
    """Return a bounded, non-control filename for display as text (never HTML)."""
    clean = ''.join(ch if ch.isprintable() else ' ' for ch in name)
    return clean[:110] + ('…' if len(clean) > 110 else '')


def _zip_summary(data: bytes, signals: list[dict[str, str]]) -> tuple[str, str, dict[str, Any]]:
    """Read ZIP central directory metadata; never extract/upload/run members.

    Only tiny allowlisted XML/ODF metadata may be decompressed with strict limits.
    """
    label, kind = 'ZIP-архив', 'zip'
    result: dict[str, Any] = {'count': 0, 'preview': [], 'note': 'Показаны только имена и типы элементов; их содержимое не запускалось и не проверялось антивирусом.'}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            result['count'] = len(infos)
            names = {info.filename.lower() for info in infos[:2000]}
            if len(infos) > 2000:
                signals.append(_signal('medium', 'Список вложений очень большой; часть метаданных проверена выборочно.'))
            if len({info.filename.lower() for info in infos}) != len(infos):
                # Duplicate names (including case-insensitive variants) can confuse extractors.
                signals.append(_signal('medium', 'В ZIP есть повторяющиеся имена; разные программы могут открыть разные вложения.'))
            is_office = False
            if 'ppt/presentation.xml' in names:
                label, kind, is_office = 'Презентация PowerPoint (PPTX)', 'presentation', True
            elif 'word/document.xml' in names:
                label, kind, is_office = 'Документ Microsoft Word (DOCX)', 'document', True
            elif 'xl/workbook.xml' in names:
                label, kind, is_office = 'Таблица Microsoft Excel (XLSX)', 'spreadsheet', True
            elif 'mimetype' in names:
                info = next((i for i in infos if i.filename.lower() == 'mimetype'), None)
                if info and info.file_size < 150 and not (info.flag_bits & 1) and info.compress_size <= 200:
                    mime = archive.read(info).decode('ascii', errors='replace')
                    odf = {
                        'application/vnd.oasis.opendocument.presentation': ('Презентация OpenDocument (ODP)', 'presentation'),
                        'application/vnd.oasis.opendocument.text': ('Документ OpenDocument (ODT)', 'document'),
                        'application/vnd.oasis.opendocument.spreadsheet': ('Таблица OpenDocument (ODS)', 'spreadsheet'),
                    }
                    if mime in odf:
                        label, kind = odf[mime]
                        is_office = True

            if len(infos) > 1000:
                signals.append(_signal('medium', 'В архиве очень много элементов; содержимое не проверялось полностью.'))
            if sum(i.file_size for i in infos) > 256 * 1024 * 1024:
                signals.append(_signal('high', 'Суммарный размер после распаковки превышает 256 МБ: возможна архивная бомба.'))
            if any(i.file_size > 2 * 1024 * 1024 and i.file_size / max(1, i.compress_size) > 150 for i in infos):
                signals.append(_signal('high', 'В архиве есть сильно сжатые большие элементы — возможна архивная бомба.'))
            if any(i.flag_bits & 1 for i in infos):
                signals.append(_signal('medium', 'В архиве присутствуют зашифрованные элементы: их содержимое недоступно для анализа.'))
            if any(n.endswith(('.rels',)) and ('_rels/' in n) for n in names) and not is_office:
                pass  # Relationship XML only meaningful inside recognized Office containers.
            if any('vbaproject.bin' in n for n in names):
                signals.append(_signal('high', 'В Office-документе обнаружен файл макросов VBA. Не разрешайте запуск макросов.'))
            if any('/embeddings/' in n or n.startswith('embeddings/') for n in names):
                signals.append(_signal('medium', 'В документе обнаружены встроенные объекты или вложения.'))
            if any(PurePath(n).suffix.lower() in SCRIPT_EXT for n in names):
                signals.append(_signal('high', 'Архив содержит файл с расширением программы или скрипта.'))
            if any(FILES_INSIDE_RE.search(n) for n in names):
                signals.append(_signal('high', 'В архиве есть файл с двойным расширением, маскирующим исполняемый файл.'))
            if any(PurePath(n).suffix.lower() in MACRO_EXT for n in names):
                signals.append(_signal('medium', 'В архив вложен Office-документ с поддержкой макросов.'))
            if any(PurePath(n).suffix.lower() in NESTED_ARCHIVES for n in names if not n.endswith('/')):
                signals.append(_signal('medium', 'Внутри есть другой архив или образ диска; вложенное содержимое не раскрывалось.'))
            if any(n.startswith('/') or re.match(r'^[a-z]:[/\\]', n, re.I) or '..' in n.replace('\\', '/').split('/') for n in names):
                signals.append(_signal('medium', 'В архиве есть небезопасные пути файлов. Не распаковывайте его без проверки.'))
            if any(stat.S_ISLNK((i.external_attr >> 16) & 0xFFFF) for i in infos):
                signals.append(_signal('medium', 'В ZIP-архиве обнаружены символические ссылки.'))

            # Minimal metadata checks: never deserialize XML and never extract on disk.
            if is_office:
                relationship_count = 0
                external_target = False
                for info in infos:
                    if relationship_count >= MAX_REL_FILES:
                        break
                    if not info.filename.lower().endswith('.rels') or info.is_dir():
                        continue
                    if info.file_size > MAX_REL_BYTES or info.compress_size > MAX_REL_BYTES or info.flag_bits & 1:
                        continue
                    relationship_count += 1
                    try:
                        text = archive.read(info)
                    except (RuntimeError, ValueError, OSError, zipfile.BadZipFile):
                        continue
                    if re.search(rb'TargetMode\s*=\s*["\']External["\']', text, re.I):
                        external_target = True
                # DDE/AUTOEXEC-style fields are not executed; inspect small Office XML only.
                dangerous_fields = False
                for info in infos[:1000]:
                    if not info.filename.lower().endswith(('document.xml', 'workbook.xml', 'presentation.xml')):
                        continue
                    if info.file_size > 64 * 1024 or info.compress_size > 64 * 1024 or info.flag_bits & 1:
                        continue
                    try:
                        fragment = archive.read(info).lower()
                        if b'ddeauto' in fragment or b'dde ' in fragment:
                            dangerous_fields = True
                    except (RuntimeError, OSError, ValueError, zipfile.BadZipFile):
                        pass
                if dangerous_fields:
                    signals.append(_signal('high', 'В Office-документе обнаружены признаки DDE-команд. Не разрешайте запуск внешних действий.'))
                if external_target:
                    signals.append(_signal('medium', 'В Office-документе найдены ссылки на внешние ресурсы. Они могут быть обычными гиперссылками, но требуют внимания.'))

            relevant = [i for i in infos if not i.is_dir()]
            # For office containers, avoid flooding users with XML internals.
            if is_office:
                relevant = [i for i in relevant if '/embeddings/' in i.filename.lower() or 'vbaproject.bin' in i.filename.lower() or PurePath(i.filename.lower()).suffix in SCRIPT_EXT | MACRO_EXT | NESTED_ARCHIVES]
                if not relevant:
                    result['note'] = 'Это структурированный документ Office; технические XML-компоненты не показываются. Макросы, вложения и внешние ссылки проверены по доступным признакам.'
            for i in relevant[:MAX_ARCHIVE_PREVIEW]:
                ext = PurePath(i.filename.lower()).suffix.lower().removeprefix('.')
                result['preview'].append({'name': _entry_name(i.filename), 'kind': (ext.upper() if ext else 'Без расширения')})
            if len(relevant) > MAX_ARCHIVE_PREVIEW:
                result['note'] += f' Показаны первые {MAX_ARCHIVE_PREVIEW} из {len(relevant)} доступных имён.'
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError, NotImplementedError):
        signals.append(_signal('medium', 'ZIP-контейнер повреждён или не может быть прочитан.'))
        result['note'] = 'Список содержимого получить не удалось.'
    return label, kind, result


def inspect_file(data: bytes, uploaded_name: str) -> dict[str, Any]:
    """Inspect data conservatively. A filename or type check is not an antivirus scan."""
    if not data:
        raise ValueError('Нельзя проверить пустой файл.')
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('Файл слишком большой. Максимальный размер — 8 МБ.')
    name = _safe_filename(uploaded_name)
    has_bidi = any(unicodedata.bidirectional(c) in {'RLO', 'LRO', 'RLE', 'LRE', 'PDF', 'RLI', 'LRI', 'FSI', 'PDI'} for c in (uploaded_name or ''))
    ext = PurePath(name.lower()).suffix.lower()
    label, kind = _magic(data)
    signals: list[dict[str, str]] = []
    archive: dict[str, Any] | None = None
    if has_bidi:
        signals.append(_signal('high', 'Имя файла содержит невидимые символы направления письма, которые могут скрывать расширение.'))
    if kind == 'zip':
        label, kind, archive = _zip_summary(data, signals)
    elif kind == 'archive':
        signals.append(_signal('medium', 'Внутренние файлы этого формата архива не анализировались.'))
    if kind == 'executable':
        signals.append(_signal('high', 'Фактическое содержимое — исполняемая программа. Не запускайте неизвестные файлы.'))
    if ext in SCRIPT_EXT:
        signals.append(_signal('high', 'Имя файла имеет расширение исполняемой программы или скрипта.'))
    if ext in MACRO_EXT:
        signals.append(_signal('medium', 'Расширение допускает макросы, даже если их наличие не подтверждено.'))
    if FILES_INSIDE_RE.search(name):
        signals.append(_signal('high', 'Двойное расширение маскирует исполняемый файл под документ.'))
    expected = {
        '.pdf': {'pdf'}, '.pptx': {'presentation'}, '.pptm': {'presentation'},
        '.docx': {'document'}, '.docm': {'document'}, '.xlsx': {'spreadsheet'}, '.xlsm': {'spreadsheet'},
        '.odt': {'document'}, '.odp': {'presentation'}, '.ods': {'spreadsheet'},
        '.png': {'image'}, '.jpg': {'image'}, '.jpeg': {'image'}, '.gif': {'image'}, '.webp': {'image'},
        '.zip': {'zip'}, '.rar': {'archive'}, '.7z': {'archive'}, '.gz': {'archive'},
        '.exe': {'executable'}, '.dll': {'executable'},
        '.mp4': {'media'}, '.svg': {'svg'}, '.html': {'html'}, '.htm': {'html'},
    }
    if ext in expected and kind not in expected[ext]:
        signals.append(_signal('high' if kind == 'executable' else 'medium',
                               'Фактический формат не совпадает с расширением имени файла.'))
    if kind == 'pdf':
        head = data[:min(len(data), 1024 * 1024)]
        if re.search(rb'/(?:JavaScript|JS|Launch|OpenAction|AA|RichMedia|XFA)\b', head):
            signals.append(_signal('medium', 'В PDF есть признаки активных действий, скриптов или автоматического открытия.'))
        if b'/EmbeddedFile' in head or b'/Filespec' in head:
            signals.append(_signal('medium', 'В PDF есть признаки встроенного вложения.'))
        if b'/Encrypt' in head:
            signals.append(_signal('medium', 'PDF содержит признаки шифрования: полный анализ содержимого недоступен.'))
    if kind in {'html', 'svg'}:
        head = data[:min(len(data), 256 * 1024)].lower()
        if b'<script' in head or b'onload=' in head or b'onerror=' in head or b'javascript:' in head:
            signals.append(_signal('medium', 'В HTML/SVG встречается активный код. Не открывайте неизвестные файлы без осторожности.'))
    if kind == 'unknown':
        signals.append(_signal('medium', 'Формат файла не распознан по сигнатуре.'))

    return {
        'filename': name,
        'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'content': {'label': label, 'basis': 'Предварительное определение по сигнатуре и структуре файла — не полноценная антивирусная проверка.'},
        'archive': archive,
        'signals': signals,
        'checks': [
            {'label': 'Формат и расширение', 'result': 'Проверены по доступным признакам'},
            {'label': 'Макросы и вложения', 'result': 'Проверены известные признаки, не всё содержимое'},
            {'label': 'Известная репутация файла', 'result': 'Отдельный запрос к VirusTotal по SHA-256, только с разрешения'},
        ],
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
        attributes = resp.json().get('data', {}).get('attributes', {})
        if not isinstance(attributes, dict):
            return {'name': provider, 'status': 'error', 'message': 'Неверный формат отчёта VirusTotal.'}
        stats = attributes.get('last_analysis_stats', {})
        if not isinstance(stats, dict):
            return {'name': provider, 'status': 'error', 'message': 'Неверная статистика отчёта VirusTotal.'}
        if not stats:
            return {'name': provider, 'status': 'no_data', 'message': 'Отчёт есть, но данных о результатах сканирования нет.'}
        counts = {}
        for category in ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout', 'failure', 'type-unsupported'):
            amount = stats.get(category, 0)
            if type(amount) is not int or amount < 0:
                return {'name': provider, 'status': 'error', 'message': 'VirusTotal вернул некорректные числа срабатываний.'}
            counts[category] = amount
        malicious, suspicious = counts['malicious'], counts['suspicious']
        total = sum(counts[c] for c in ('malicious', 'suspicious', 'harmless', 'undetected'))
        if total < 1:
            return {'name': provider, 'status': 'no_data', 'message': 'В отчёте VirusTotal нет результатов антивирусных движков. Считать файл проверенным нельзя.'}
        # Show at most five explicitly reported names, without trusting third-party markup.
        details = []
        raw_results = attributes.get('last_analysis_results', {})
        if isinstance(raw_results, dict):
            for name, result in raw_results.items():
                if len(details) >= 5:
                    break
                if not isinstance(result, dict) or result.get('category') not in ('malicious', 'suspicious'):
                    continue
                details.append({'engine': str(name)[:75],
                                'category': result['category'],
                                'detection': str(result.get('result') or 'Обнаружение без названия')[:120]})
        date = attributes.get('last_analysis_date')
        date = date if type(date) is int and 0 < date < 4102444800 else None
        return {'name': provider, 'status': 'checked', 'detections': malicious,
                'suspicious': suspicious, 'total': total, 'unavailable': sum(counts[c] for c in ('timeout', 'failure', 'type-unsupported')),
                'engine_findings': details, 'last_analysis_date': date,
                'message': f'Результаты имеющегося отчёта: {malicious} опасных, {suspicious} подозрительных из {total} ответивших систем. Это проверка известного SHA-256, а не сканирование загруженных байтов.'}
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return {'name': provider, 'status': 'error', 'message': 'Не удалось получить результаты из базы.'}


async def analyse_file(data: bytes, uploaded_name: str, consent: bool, *, submit_to_vt: bool = False) -> dict[str, Any]:
    """Run bounded static checks and optionally query VirusTotal.

    Static heuristics and reputation data can miss new threats; neither means
    that a file is guaranteed safe.
    """
    # CPU-heavy static analysis is offloaded so one archive cannot block the event loop.
    report, own = await asyncio.gather(
        asyncio.to_thread(inspect_file, data, uploaded_name),
        asyncio.to_thread(inspect_malware_indicators, data, uploaded_name),
    )
    # The local checks run on every uploaded file. No external upload.
    # Only the file's digest goes to VT after the user explicitly opts in.
    reputation = await virustotal_hash_lookup(report['sha256'], consent)
    if submit_to_vt and consent and reputation.get('status') == 'no_data' and 'В базе нет отчёта' in reputation.get('message', ''):
        reputation = await submit_unknown_file(data, report['sha256'], report['filename'])
    signals = list(report['signals'])
    inspection_partial = bool(own['truncated']) or report['content']['label'] in {'RAR-архив', '7z-архив', 'GZIP-архив', 'Неизвестный бинарный формат', 'Документ Microsoft Office старого формата'}
    if report['archive'] and any('зашифрованные элементы' in x['text'] or 'архивная бомба' in x['text'] or 'не может быть прочитан' in x['text'] for x in signals):
        inspection_partial = True
    for finding in own['findings']:
        severity = 'medium' if finding['severity'] == 'test' else finding['severity']
        signals.append(_signal(severity, finding['text'] + (' (' + finding['location'] + ')' if finding['location'] else '')))
    # Only the exact official benign EICAR test file is exempted from AV
    # detections. An arbitrary file *containing* EICAR may still be malicious.
    eicar_only = data.rstrip(b'\r\n') == EICAR_TEST
    judgement = assess_file(reputation, signals, inspection_partial, eicar_only=eicar_only)
    risk, title, detail = judgement['risk'], judgement['title'], judgement['detail']
    coverage = {
        'status': 'partial' if inspection_partial else 'bounded',
        'title': 'Часть содержимого недоступна' if inspection_partial else 'Выполнен ограниченный статический анализ',
        'explanation': (
            'Некоторые вложения не были прочитаны или формат не позволяет их раскрыть. Отсутствие находок не подтверждает безопасность.'
            if inspection_partial else
            'Проверены доступные признаки без запуска файлов. Это не полноценное антивирусное сканирование.'
        ),
        'inspected_members': own['inspected_members'],
        'limitations': own.get('limitations', []),
    }
    report['checks'] = [
        {'label': 'Формат и расширение', 'result': 'Проверены без запуска файла', 'status': 'checked'},
        {'label': 'Макросы, вложения, подозрительный код', 'result': f'Собственный анализ: {own["inspected_members"]} вложенных элементов. Это не антивирус.', 'status': 'partial' if inspection_partial else 'checked'},
        {'label': 'База VirusTotal (SHA-256)', 'result': reputation.get('message', 'Нет отчёта'), 'status': reputation.get('status', 'no_data')},
    ]
    quick_verdict = judgement['quick_verdict']
    antivirus_stage = ('Идёт новое сканирование VirusTotal' if reputation.get('status') == 'pending'
                       else 'Готовый отчёт VirusTotal получен' if reputation.get('status') == 'checked'
                       else 'Готового отчёта VirusTotal нет' if reputation.get('status') == 'no_data'
                       else 'VirusTotal не запускался' if reputation.get('status') == 'skipped'
                       else 'Ошибка проверки VirusTotal')
    summary_steps = {
        'local': 'Готово: формат, структура и подозрительные признаки исследованы без запуска файла.',
        'antivirus': antivirus_stage,
        'message': ('Зайдите за результатом нового сканирования через 30–60 секунд.' if reputation.get('status') == 'pending'
                    else ('Можно запросить новое сканирование по отдельному согласию.' if uploads_enabled() else 'Новое сканирование выключено владельцем сайта; готового отчёта нет.') if reputation.get('status') == 'no_data'
                    else 'Отсутствие обнаружений не гарантирует безопасность.'),
    }
    return {**report, 'signals': signals, 'inspection_coverage': coverage, 'own_malware_scan': own,
            'risk': risk, 'title': title, 'detail': detail,
            'quick_verdict': quick_verdict, 'recommendation': judgement['recommendation'], 'eicar_test_only': eicar_only,
            'vt_analysis_token': reputation.get('analysis_token'),
            'scan_progress': summary_steps,
            'providers': [reputation, own],
            'disclaimer': 'Собственный анализ не запускает файл. Поиск отчёта VirusTotal передаёт только SHA-256. С отдельного согласия на новое сканирование файл целиком передаётся VirusTotal и может стать доступным его сообществу. Ни одна проверка не гарантирует отсутствие вирусов.'}
