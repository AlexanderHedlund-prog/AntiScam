"""Opt-in inspection of a small public download without executing it.

Hard limits: public DNS pinned for EVERY HTTP hop, 2 MiB, 3 redirects, no
cookies/credentials/proxy/decompression, no persistence or VT uploading.
No untrusted document is rendered or recursively fetched.
"""
from __future__ import annotations

import asyncio
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit, unquote

import aiohttp

from app.scanner import GuardedResolver, URLValidationError, validate_url
from app.file_scanner import inspect_file
from app.local_malware import inspect_malware_indicators

MAX_DOWNLOAD = 2 * 1024 * 1024
MAX_HOPS = 3
FILE_EXT = frozenset({'.pdf', '.doc', '.docx', '.docm', '.ppt', '.pptx', '.pptm', '.xls', '.xlsx', '.xlsm',
                      '.zip', '.7z', '.rar', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.webp',
                      '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.js', '.jar', '.apk', '.svg', '.html'})


def remote_summary(data: bytes, url: str, mime: str) -> dict:
    """Deterministic byte analysis. Never advertises itself as a virus scan."""
    mime = mime.split(';', 1)[0].lower().strip()
    prefix = data[:256].lstrip().lower()
    if mime in ('text/html', 'application/xhtml+xml') or prefix.startswith((b'<!doctype html', b'<html')):
        return {'status': 'not_file', 'kind': 'HTML-страница', 'message': 'По адресу находится веб-страница (HTML), а не скачиваемый файл. Для её анализа включите «Посмотреть содержимое страницы».', 'signals': []}
    filename = PurePosixPath(unquote(urlsplit(url).path)).name[:150] or 'download.bin'
    file_report = inspect_file(data, filename)
    malware = inspect_malware_indicators(data, filename)
    signals = list(file_report['signals']) + [
        {'severity': f['severity'], 'text': f['text']} for f in malware['findings'] if f['severity'] in {'high', 'medium'}
    ]
    if malware['truncated']:
        signals.append({'severity': 'medium', 'text': 'Часть вложений не удалось проверить в пределах лимитов.'})
    return {'status': 'ok', 'message': 'Файл целиком получен в пределах 2 МБ и проверен только статически. Не запускался и не отправлялся в VirusTotal.',
            'kind': file_report['content']['label'], 'size': len(data), 'sha256': file_report['sha256'],
            'signals': signals[:15], 'coverage': 'partial' if malware['truncated'] else 'bounded',
            'filename': filename}


def _empty(status: str, message: str, **extra):
    return {'status': status, 'message': message, 'signals': [], 'redirect_chain': [], **extra}


async def _download(link):
    timeout = aiohttp.ClientTimeout(total=12, connect=3, sock_read=5)
    connector = aiohttp.TCPConnector(resolver=GuardedResolver(), use_dns_cache=False, force_close=True,
                                     limit=1, ssl=True)
    current = link.original
    chain = []
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False,
                                         auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
                                         headers={'User-Agent': 'AntiScam-FileInspector/1.3',
                                                  'Accept': 'application/octet-stream,*/*;q=0.5',
                                                  'Accept-Encoding': 'identity'}) as session:
            for hop in range(MAX_HOPS + 1):
                valid = validate_url(current)
                chain.append({'host': valid.host, 'scheme': valid.scheme})  # no query/path secrets
                async with session.get(current, allow_redirects=False, max_field_size=8190) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        if hop >= MAX_HOPS or not response.headers.get('Location'):
                            return _empty('incomplete', 'Слишком много переадресаций или нет следующего адреса.', redirect_chain=chain)
                        next_url = urljoin(current, response.headers['Location'])
                        try:
                            validate_url(next_url)
                        except URLValidationError:
                            return _empty('blocked', 'Перенаправление на закрытый или внутренний адрес заблокировано.', redirect_chain=chain)
                        current = next_url
                        continue
                    if response.status >= 400:
                        return _empty('incomplete', f'Сервер вернул HTTP {response.status}.', redirect_chain=chain)
                    if response.headers.get('Content-Encoding', '').strip().lower() not in ('', 'identity'):
                        return _empty('incomplete', 'Сжатый HTTP-ответ не распаковывается ради безопасности.', redirect_chain=chain)
                    mime = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                    if mime in ('text/html', 'application/xhtml+xml'):
                        return _empty('not_file', 'По адресу находится веб-страница (HTML), а не скачиваемый файл. Для её анализа включите «Посмотреть содержимое страницы».', kind='HTML-страница', redirect_chain=chain)
                    size_header = response.headers.get('Content-Length', '')
                    if size_header.isdecimal() and int(size_header) > MAX_DOWNLOAD:
                        return _empty('incomplete', 'Файл больше 2 МБ — загрузка отменена.', redirect_chain=chain)
                    # Do not turn generic URLs into a crawler or bulk file downloader.
                    suffix = PurePosixPath(unquote(urlsplit(current).path)).suffix.lower()
                    attachment = response.headers.get('Content-Disposition', '').lower().startswith('attachment')
                    known_mime = mime in {'application/pdf', 'application/zip', 'application/octet-stream',
                                          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                          'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                                          'image/png', 'image/jpeg'}
                    if suffix not in FILE_EXT and not attachment and not known_mime:
                        return _empty('incomplete', 'Не удалось подтвердить, что ссылка ведёт на файл. Загрузка не выполнялась.', redirect_chain=chain)
                    buf = bytearray()
                    async for chunk in response.content.iter_chunked(32768):
                        if len(buf) + len(chunk) > MAX_DOWNLOAD:
                            return _empty('incomplete', 'Размер файла превысил 2 МБ — проверка остановлена.', redirect_chain=chain)
                        buf.extend(chunk)
                    if not buf:
                        return _empty('incomplete', 'Файл пустой.', redirect_chain=chain)
                    result = remote_summary(bytes(buf), current, mime)
                    result['redirect_chain'] = chain
                    result['final_host'] = valid.host
                    return result
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError, ValueError, URLValidationError):
        return _empty('incomplete', 'Не удалось безопасно получить файл (DNS, сертификат, соединение или тайм-аут).', redirect_chain=chain)
    return _empty('incomplete', 'Получение файла не завершено.', redirect_chain=chain)


_REMOTE_SLOTS = asyncio.Semaphore(1)


async def inspect_remote_file(link):
    try:
        await asyncio.wait_for(_REMOTE_SLOTS.acquire(), timeout=0.2)
    except asyncio.TimeoutError:
        return _empty('incomplete', 'Сервис проверки скачиваемых файлов занят. Попробуйте позже.')
    try:
        try:
            return await asyncio.wait_for(_download(link), timeout=14)
        except asyncio.TimeoutError:
            return _empty('incomplete', 'Время загрузки файла истекло.')
    finally:
        _REMOTE_SLOTS.release()
