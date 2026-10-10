"""Opt-in, bounded, static preview of external pages for AntiScam.

Not a browser or antivirus. DNS pinning through a guarded resolver is used on
*every* HTTP connection. No JS execution, archive unpacking or follow-on loads.
"""
from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit, unquote

import aiohttp

from app.scanner import GuardedResolver, URLValidationError, validate_url
from app.local_url_analysis import OFFICIAL_DOMAINS

MAX_PREVIEW = 128 * 1024
MAX_REDIRECTS = 3
DANGEROUS_EXT = {'.exe', '.msi', '.scr', '.bat', '.cmd', '.ps1', '.hta', '.vbs', '.jar', '.apk', '.dmg', '.pkg', '.js', '.lnk'}
DOC_EXT = {'.pdf', '.jpg', '.png', '.doc', '.docx', '.ppt', '.pptx'}


def _origin_host(url: str) -> str:
    return (urlsplit(url).hostname or '').lower().rstrip('.')


def _signal(level: str, description: str) -> dict[str, str]:
    return {'severity': level, 'text': description, 'source': 'page'}


def _looks_like_download(url: str) -> bool:
    try:
        ext = PurePosixPath(unquote(urlsplit(url).path).lower()).suffix
    except ValueError:
        return False
    return ext in DANGEROUS_EXT


class StaticHTMLInspector(HTMLParser):
    """Extract only safe explanatory data; HTML and scripts are never rendered."""
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.host = _origin_host(page_url)
        self.title_parts: list[str] = []
        self.in_title = False
        self.forms: list[dict[str, object]] = []
        self.current_form: dict[str, object] | None = None
        self.hidden_external_frames = 0
        self.external_refreshes = 0
        self.executable_links = 0
        self.external_scripts = 0
        self.total_scripts = 0
        self.script_text_parts: list[str] = []
        self.in_script = False
        self.form_count = 0
        self.insecure_password_form = 0
        self.password_fields = 0
        self.form_external_count = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title':
            self.in_title = True
        if tag == 'form':
            self.form_count += 1
            if len(self.forms) < 24:
                action = str(attrs.get('action') or '')
                try:
                    action_url = urljoin(self.page_url, action)
                    action_host = _origin_host(action_url)
                except (ValueError, TypeError):
                    action_host = ''
                form = {'password': False, 'external': bool(action_host and action_host != self.host), 'action_host': action_host}
                self.forms.append(form)
                if form['external']:
                    self.form_external_count += 1
                self.current_form = form
        if tag == 'input' and self.current_form is not None:
            if str(attrs.get('type') or '').lower() == 'password':
                self.current_form['password'] = True
                self.password_fields += 1
                if urlsplit(self.page_url).scheme == 'http':
                    self.insecure_password_form += 1
        if tag == 'iframe':
            src = str(attrs.get('src') or '')
            style = str(attrs.get('style') or '').lower().replace(' ', '')
            hidden = ('display:none' in style or 'visibility:hidden' in style or str(attrs.get('hidden') or '') != '' or str(attrs.get('width') or '') in {'0', '1'} or str(attrs.get('height') or '') in {'0', '1'})
            try:
                external = bool(_origin_host(urljoin(self.page_url, src)) not in {'', self.host})
            except (ValueError, TypeError):
                external = False
            if hidden and external:
                self.hidden_external_frames += 1
        if tag == 'meta' and str(attrs.get('http-equiv') or '').lower() == 'refresh':
            match = re.search(r'url\s*=\s*[\'\"]?([^;\'\"]+)', str(attrs.get('content') or ''), re.I)
            if match:
                try:
                    dest = urljoin(self.page_url, match.group(1).strip())
                    if _origin_host(dest) not in {'', self.host}:
                        self.external_refreshes += 1
                except (ValueError, TypeError):
                    pass
        if tag in {'a', 'iframe', 'script'}:
            ref = str(attrs.get('href' if tag == 'a' else 'src') or '')
            if tag == 'a' and ref and _looks_like_download(ref):
                self.executable_links += 1
        if tag == 'script':
            self.total_scripts += 1
            self.in_script = True
            src = str(attrs.get('src') or '')
            if src:
                try:
                    if _origin_host(urljoin(self.page_url, src)) not in {'', self.host}:
                        self.external_scripts += 1
                except (ValueError, TypeError):
                    pass

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False
        if tag == 'form':
            self.current_form = None
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data):
        if self.in_title and len(''.join(self.title_parts)) < 200:
            self.title_parts.append(data[:200])
        if self.in_script and len(self.script_text_parts) < 30:
            self.script_text_parts.append(data[:1500])

    def report(self) -> dict[str, object]:
        signals: list[dict[str, str]] = []
        if any(f['password'] and f['external'] for f in self.forms):
            signals.append(_signal('high', 'Форма для пароля отправляет данные на другой домен. Проверьте подлинность страницы.'))
        if self.insecure_password_form:
            signals.append(_signal('high', 'Форма ввода пароля расположена на незашифрованной HTTP-странице.'))
        if self.form_external_count and self.password_fields == 0:
            signals.append(_signal('low', 'Есть форма, передающая данные на другой домен. Это бывает и у легитимных сервисов.'))
        # Brand words in a title are weak evidence. Alert only together with a login form.
        title_lower = ' '.join(self.title_parts).lower()
        if self.password_fields:
            for brand, roots in OFFICIAL_DOMAINS.items():
                if brand in title_lower and not any(self.host == r or self.host.endswith('.' + r) for r in roots):
                    signals.append(_signal('medium', 'Заголовок страницы упоминает известный сервис, но форма пароля находится на другом домене. Возможна имитация входа.'))
                    break
        if self.hidden_external_frames:
            signals.append(_signal('medium', 'На странице есть скрытый iframe, ведущий на другой домен. Это может быть легитимным виджетом или признаком риска.'))
        if self.external_refreshes:
            signals.append(_signal('medium', 'Страница содержит автоматический переход на другой домен через meta refresh. Переход не выполнялся.'))
        if self.executable_links:
            signals.append(_signal('medium', 'На странице обнаружены ссылки на исполняемые файлы или скрипты. Файлы не загружались.'))
        code = ' '.join(self.script_text_parts).lower()
        if re.search(r'(?:eval\s*\(\s*atob\s*\(|document\.write\s*\(\s*unescape\s*\()', code):
            signals.append(_signal('medium', 'Во встроенном скрипте обнаружен приём сокрытия кода. Это не доказывает наличие вируса.'))
        title = ' '.join(' '.join(self.title_parts).split())[:120]
        return {
            'title': title or 'Заголовок не обнаружен',
            'forms': self.form_count,
            'password_fields': self.password_fields,
            'scripts': self.total_scripts,
            'external_scripts': self.external_scripts,
            'suspicious_links': self.executable_links,
            'signals': signals[:10],
        }


def _sniff(data: bytes) -> str | None:
    if data.startswith(b'MZ'):
        return 'Исполняемый файл Windows (PE/MZ)'
    if data.startswith(b'\x7fELF'):
        return 'Исполняемый файл Linux (ELF)'
    if data.startswith(b'%PDF-'):
        return 'PDF-документ'
    if data.startswith((b'PK\x03\x04', b'PK\x05\x06')):
        return 'ZIP / Office / APK (структура не анализировалась)'
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'PNG-изображение'
    if data.startswith(b'\xff\xd8\xff'):
        return 'JPEG-изображение'
    return None


def summarise_page(data: bytes, url: str, declared_type: str, truncated: bool = False) -> dict:
    """Pure static classification; can be tested without network access."""
    declared_type = declared_type.lower().split(';', 1)[0].strip()
    kind = _sniff(data)
    signals: list[dict[str, str]] = []
    if kind and ('Исполняемый' in kind):
        signals.append(_signal('high', 'Ссылка ведёт на исполняемый файл. Не скачивайте и не запускайте его из неизвестного источника.'))
    if kind and 'Исполняемый' in kind and declared_type in {'application/pdf', 'text/html', 'image/png', 'image/jpeg'}:
        signals.append(_signal('high', 'Фактическая сигнатура исполняемого файла не совпадает с заявленным Content-Type.'))
    if not kind and declared_type in {'text/html', 'application/xhtml+xml'}:
        kind = 'HTML-страница (по Content-Type)'
    elif not kind and declared_type == 'application/json':
        kind = 'Данные JSON (по Content-Type)'
    elif not kind and declared_type in {'application/xml', 'text/xml'}:
        kind = 'XML-документ (по Content-Type)'
    is_html = ((kind is None or kind == 'HTML-страница (по Content-Type)') and (declared_type in {'text/html', 'application/xhtml+xml'} or data[:1024].lower().lstrip().startswith((b'<!doctype html', b'<html'))))
    description: dict = {'kind': kind or ('Текст' if declared_type.startswith('text/') else 'Неизвестный формат'),
                         'title': 'Не определён', 'forms': 0, 'scripts': 0, 'external_scripts': 0,
                         'suspicious_links': 0, 'signals': signals, 'truncated': truncated}
    if is_html:
        html = StaticHTMLInspector(url)
        try:
            html.feed(data.decode('utf-8', errors='replace'))
            parsed = html.report()
            description.update(parsed)
            description['kind'] = 'HTML-страница'
            description['signals'] = signals + parsed['signals']
        except (ValueError, AssertionError):
            description['signals'].append(_signal('low', 'Не удалось полностью разобрать HTML.'))
    return description


def _result(status: str, message: str, **kw):
    return {'status': status, 'message': message, 'final_host': None, 'destination': None,
            'redirects': 0, 'redirect_chain': [], 'mime': None, 'kind': None, 'title': None,
            'forms': 0, 'scripts': 0, 'external_scripts': 0, 'suspicious_links': 0,
            'signals': [], 'bytes_read': 0, 'truncated': False, **kw}


async def _inspect_page_unlimited(link) -> dict:
    """GET at most 128 KiB with guarded DNS for each hop, max 3 redirects.

    No JS, cookies, credentials, decompression, next-hop resources, or downloads.
    Static binary magic identification is not an antivirus scan.
    """
    timeout = aiohttp.ClientTimeout(total=10, connect=3, sock_read=4)
    connector = aiohttp.TCPConnector(resolver=GuardedResolver(), use_dns_cache=False,
                                     force_close=True, limit=2, ssl=True)
    url = link.original
    chain = []
    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, trust_env=False, auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            headers={'User-Agent': 'AntiScam-StaticInspector/0.6', 'Accept': 'text/html,text/plain,application/octet-stream,*/*;q=0.1',
                     'Accept-Encoding': 'identity'},
        ) as session:
            for hop in range(MAX_REDIRECTS + 1):
                valid = validate_url(url)
                chain.append({'host': valid.host, 'scheme': valid.scheme})
                async with session.get(url, allow_redirects=False, max_field_size=8190) as resp:
                    if resp.status in {301, 302, 303, 307, 308}:
                        target = resp.headers.get('Location', '')
                        if not target or hop == MAX_REDIRECTS:
                            return _result('incomplete', 'Переадресаций слишком много или не указан следующий адрес.', redirects=hop, redirect_chain=chain)
                        url = urljoin(url, target)
                        try:
                            validate_url(url)
                        except URLValidationError:
                            return _result('blocked', 'Переадресация ведёт на запрещённый или внутренний адрес. Запрос остановлен.', redirects=hop + 1, redirect_chain=chain)
                        continue
                    if resp.status >= 400:
                        explanation = ('HTTP 404 — страница не найдена. Сервер ответил, но запрошенный ресурс отсутствует. Сам по себе код 404 не является признаком вируса.'
                                       if resp.status == 404 else f'Сервер ответил HTTP {resp.status}; содержимое не удалось проверить.')
                        return _result('incomplete', explanation, http_status=resp.status, redirects=hop, redirect_chain=chain,
                                       final_host=valid.host, destination=valid.safe_display)
                    declared = resp.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                    if resp.headers.get('Content-Encoding', '').lower().strip() not in {'', 'identity'}:
                        return _result('incomplete', 'Сайт передал сжатый ответ; содержимое не распаковывалось ради безопасности.',
                                       final_host=valid.host, destination=valid.safe_display, redirects=hop, redirect_chain=chain, mime=declared)
                    sample = await resp.content.read(MAX_PREVIEW + 1)
                    truncated = len(sample) > MAX_PREVIEW
                    data = sample[:MAX_PREVIEW]
                    if not data:
                        return _result('incomplete', 'Сайт вернул пустой ответ; анализ содержимого невозможен.',
                                       final_host=valid.host, redirects=hop, redirect_chain=chain, mime=declared)
                    parsed = summarise_page(data, url, declared, truncated)
                    if valid.host != link.host:
                        parsed['signals'].append(_signal('medium', 'После переадресации конечный сайт находится на другом домене.'))
                    if link.scheme == 'https' and valid.scheme == 'http':
                        parsed['signals'].append(_signal('medium', 'Ссылка переадресовала с HTTPS на незашифрованный HTTP.'))
                    return _result('ok', ('Прочитан ограниченный фрагмент HTML без выполнения JavaScript.'
                                          if str(parsed.get('kind', '')).startswith('HTML-страница') else
                                          'Прочитан ограниченный фрагмент ответа сервера без выполнения содержимого.')
                                   + ' Это не антивирусная проверка.',
                                   final_host=valid.host, destination=f"{valid.scheme}://{valid.host}", redirects=hop, mime=declared,
                                   bytes_read=len(data), redirect_chain=chain, **parsed)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError, URLValidationError):
        return _result('incomplete', 'Не удалось безопасно получить страницу (соединение, DNS, сертификат или тайм-аут).', redirect_chain=chain)
    return _result('incomplete', 'Не удалось получить содержимое страницы.')


_PAGE_FETCH_SLOTS = asyncio.Semaphore(2)


async def inspect_page(link) -> dict:
    """Protect small shared Render instances from concurrent network fetch floods."""
    try:
        await asyncio.wait_for(_PAGE_FETCH_SLOTS.acquire(), timeout=1.0)
    except asyncio.TimeoutError:
        return _result('incomplete', 'Сервис проверки содержимого занят; попробуйте немного позже.')
    try:
        try:
            return await asyncio.wait_for(_inspect_page_unlimited(link), timeout=12.0)
        except asyncio.TimeoutError:
            return _result('incomplete', 'Общее время проверки страницы истекло. Повторите позже.')
    finally:
        _PAGE_FETCH_SLOTS.release()
