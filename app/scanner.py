"""URL analysis: conservative heuristics, reputation lookups and SSRF-safe HEAD probe.

This tool checks URL reputation and declared content type. It is NOT an antivirus
scanner, browser sandbox, or guarantee that a document is free of malware.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from app.reputation_quota import take_virustotal_slot
from urllib.parse import unquote, urljoin, urlsplit

import aiohttp
import httpx
from aiohttp.abc import AbstractResolver

URL_MAX_LENGTH = 2048
SUSPICIOUS_EXT = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".apk", ".dmg", ".pkg", ".jar", ".js", ".hta", ".lnk", ".iso", ".reg", ".com"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
DOCUMENT_EXT = {".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt"}
PRESENTATION_EXT = {".ppt", ".pptx", ".odp", ".key"}
SPREADSHEET_EXT = {".xls", ".xlsx", ".ods", ".csv"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}
MEDIA_EXT = {".mp3", ".mp4", ".avi", ".mov", ".webm", ".wav"}
SHORT_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "clck.ru", "goo.su", "shorturl.at"}
CONTENT_MIMES = {
    "application/pdf": "PDF-документ",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "Презентация PowerPoint (.pptx)",
    "application/vnd.ms-powerpoint": "Презентация PowerPoint (.ppt)",
    "application/vnd.oasis.opendocument.presentation": "Презентация OpenDocument (.odp)",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Документ Word (.docx)",
    "application/msword": "Документ Word (.doc)",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Таблица Excel (.xlsx)",
    "application/vnd.ms-excel": "Таблица Excel (.xls)",
    "application/zip": "ZIP-архив",
    "application/x-rar-compressed": "RAR-архив",
    "application/x-7z-compressed": "7z-архив",
    "application/x-msdownload": "Исполняемый файл",
    "application/vnd.android.package-archive": "Приложение Android (.apk)",
    "text/html": "Веб-страница",
    "application/xhtml+xml": "Веб-страница",
    "text/plain": "Текстовый документ",
}


class URLValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ValidURL:
    original: str
    host: str
    path: str
    safe_display: str
    ext: str
    scheme: str


def validate_url(raw: str) -> ValidURL:
    raw = raw.strip()
    if not raw or len(raw) > URL_MAX_LENGTH:
        raise URLValidationError("Введите ссылку длиной до 2048 символов.")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise URLValidationError("Ссылка не должна содержать пробелы или управляющие символы.")
    try:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
            raise URLValidationError("Поддерживаются только ссылки http:// и https://.")
        if parts.username is not None or parts.password is not None:
            raise URLValidationError("Ссылки со встроенным логином или паролем запрещены.")
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port  # raises ValueError for malformed port
        if not host or len(host) > 253 or ("." not in host and host != "localhost"):
            raise URLValidationError("Введите корректное доменное имя.")
        if port is not None and port != (443 if parts.scheme.lower() == "https" else 80):
            raise URLValidationError("Проверка нестандартных портов отключена ради безопасности.")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".onion")):
            raise URLValidationError("Локальные и внутренние адреса не поддерживаются.")
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                raise URLValidationError("Локальные и служебные IP-адреса проверять нельзя.")
        except ValueError as exc:
            if isinstance(exc, URLValidationError):
                raise
            # Do not trust string appearance for DNS-based address shortcuts.
            try:
                host.encode("idna")
            except UnicodeError as err:
                raise URLValidationError("Некорректное доменное имя.") from err
        if "\\" in raw or "\\" in parts.netloc:
            raise URLValidationError("Ссылки с обратной косой чертой не поддерживаются.")
        path = parts.path or "/"
        # Never return fragments, queries, or auth tokens in public display labels.
        disp_path = (path[:110] + "…") if len(path) > 110 else path
        safe_display = f"{parts.scheme.lower()}://{host}{disp_path}"
        filename = PurePosixPath(unquote(path).split("/")[-1]).name
        ext = PurePosixPath(filename).suffix.lower()
        return ValidURL(raw, host, path, safe_display, ext, parts.scheme.lower())
    except URLValidationError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise URLValidationError("Не удалось прочитать адрес ссылки.") from exc


def guess_content(link: ValidURL, mime: str | None = None) -> dict[str, str]:
    """Content-Type is server self-report, not proof of real bytes."""
    suffix = link.ext
    if mime:
        mime = mime.split(";", 1)[0].strip().lower()
        if mime in CONTENT_MIMES:
            return {"label": CONTENT_MIMES[mime], "basis": "Заголовок Content-Type (указан сервером)", "confidence": "medium"}
        if mime.startswith("image/"):
            return {"label": "Изображение", "basis": "Заголовок Content-Type", "confidence": "medium"}
        if mime.startswith("video/") or mime.startswith("audio/"):
            return {"label": "Медиафайл", "basis": "Заголовок Content-Type", "confidence": "medium"}
    if suffix in PRESENTATION_EXT:
        label = "Презентация"
    elif suffix in DOCUMENT_EXT:
        label = "Документ"
    elif suffix in SPREADSHEET_EXT:
        label = "Таблица"
    elif suffix in ARCHIVE_EXT:
        label = "Архив"
    elif suffix in IMAGE_EXT:
        label = "Изображение"
    elif suffix in MEDIA_EXT:
        label = "Медиафайл"
    elif suffix in SUSPICIOUS_EXT:
        label = "Потенциально опасный исполняемый файл / скрипт"
    elif suffix in MACRO_EXT:
        label = "Документ с поддержкой макросов"
    else:
        label = "Веб-страница или неизвестный формат"
    if suffix:
        label += f" ({suffix})"
        return {"label": label, "basis": "Предположение по расширению адреса, файл не загружался", "confidence": "low"}
    return {"label": label, "basis": "Формат не подтверждён; содержимое не скачивалось", "confidence": "unknown"}


def heuristic_signals(link: ValidURL) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    host = link.host
    lower_path = unquote(link.path).lower()
    if link.scheme == "http":
        signals.append({"severity": "medium", "text": "Соединение HTTP не шифруется."})
    try:
        ipaddress.ip_address(host)
        signals.append({"severity": "medium", "text": "Вместо доменного имени используется IP-адрес."})
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        signals.append({"severity": "medium", "text": "В домене есть Punycode — проверьте написание адреса."})
    if host in SHORT_DOMAINS or any(host.endswith("." + d) for d in SHORT_DOMAINS):
        signals.append({"severity": "medium", "text": "Сокращённая ссылка скрывает конечный адрес."})
    if link.ext in SUSPICIOUS_EXT:
        signals.append({"severity": "high", "text": "Адрес похож на исполняемый файл или скрипт; не запускайте его без проверки."})
    if link.ext in MACRO_EXT:
        signals.append({"severity": "medium", "text": "Файл может содержать активные макросы."})
    if re.search(r"\.(?:pdf|docx?|pptx?|xlsx?|jpg|png)\.(?:exe|scr|bat|cmd|js|vbs)$", lower_path):
        signals.append({"severity": "high", "text": "Двойное расширение может маскировать программу под документ."})
    if host.count(".") >= 4:
        signals.append({"severity": "low", "text": "Очень длинный поддомен: убедитесь, что домен настоящий."})
    return signals


class GuardedResolver(AbstractResolver):
    """Resolve only public IPs. Returned addresses are used directly by aiohttp.

    No DNS caching; every redirect requires a fresh guarded request. This mitigates
    SSRF and DNS-rebinding routes to internal/cloud metadata endpoints.
    """

    async def resolve(self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_UNSPEC) -> list[dict[str, Any]]:
        # Fast-fail obvious internal DNS names and private literal addresses.
        validate_url(f"https://{host}/")
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
        if not results:
            raise OSError("DNS did not return an address")
        public = []
        for family_result, _, proto, _, address in results:
            ip = ipaddress.ip_address(address[0])
            if not ip.is_global:
                raise OSError("DNS returned a private / reserved address")
            public.append({"hostname": host, "host": address[0], "port": port,
                           "family": family_result, "proto": proto, "flags": socket.AI_NUMERICHOST})
        return public

    async def close(self) -> None:
        pass


async def probe_content(link: ValidURL) -> dict[str, Any]:
    """Only HEAD, no page scripts, no file download. Up to 3 redirects.

    This is intentionally conservative; servers without HEAD support may return
    'unknown'. A content-type assertion does not verify file bytes.
    """
    timeout = aiohttp.ClientTimeout(total=7, connect=3, sock_read=3)
    connector = aiohttp.TCPConnector(
        resolver=GuardedResolver(), use_dns_cache=False,
        force_close=True, limit=3, ssl=True,
    )
    curr = link.original
    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, trust_env=False,
            auto_decompress=False,
            headers={"User-Agent": "AntiScam-URL-Inspector/0.1 (HEAD only)", "Accept": "*/*"},
        ) as session:
            for step in range(4):
                validate_url(curr)
                async with session.head(curr, allow_redirects=False, max_field_size=8190) as resp:
                    if resp.status in {301, 302, 303, 307, 308}:
                        dest = resp.headers.get("Location")
                        if not dest or step == 3:
                            return {"status": "unknown", "message": "Цепочка переадресаций слишком длинная."}
                        curr = urljoin(curr, dest)
                        validate_url(curr)  # no private / localhost / ports in redirects
                        continue
                    if resp.status == 405 or resp.status == 501:
                        return {"status": "unknown", "message": "Сервер не поддерживает проверку заголовков HEAD."}
                    if resp.status >= 400:
                        return {"status": "unknown", "message": f"Сервер ответил кодом {resp.status}; формат не подтверждён."}
                    declared = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    # Do not include full redirected URL (possible secret query string).
                    return {"status": "ok", "mime": declared or None,
                            "message": "Формат определён по HTTP-заголовкам, без загрузки содержимого.",
                            "redirected": step > 0}
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, URLValidationError, ValueError):
        return {"status": "unknown", "message": "Не удалось безопасно получить заголовки страницы."}
    return {"status": "unknown", "message": "Не удалось определить формат."}


def _inactive(provider: str, why: str) -> dict[str, Any]:
    return {"name": provider, "status": "skipped", "message": why, "detections": 0}


# v5 URL Lookup requires respecting server-provided cacheDuration, including negatives.
# Cache keys are digests; no full URLs or access tokens are retained in memory.
_GOOGLE_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def _google_cache_seconds(value: Any) -> float:
    if not isinstance(value, str) or not value.endswith('s'):
        return 0.0
    try:
        seconds = float(value[:-1])
    except ValueError:
        return 0.0
    # Keep official cache duration (at most 24h) without inventing a longer TTL.
    return max(0.0, min(seconds, 86400.0))


def _google_failure_hint(response: httpx.Response) -> tuple[str, str]:
    """Map Google errors to safe, fixed diagnostics; never echo response text.

    Google errors may be JSON or protobuf. The latter often contains ASCII
    google.rpc.ErrorInfo reason identifiers. We inspect these only internally.
    Never expose raw URL, API key, request path or upstream payload.
    """
    raw_bytes = getattr(response, 'content', b'')
    raw = raw_bytes[:8192].decode('utf-8', errors='ignore').upper()
    reason = ''
    try:
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get('error'), dict):
            err = payload['error']
            details = err.get('details', [])
            if isinstance(details, list):
                for detail in details:
                    if isinstance(detail, dict) and isinstance(detail.get('reason'), str):
                        reason = detail['reason'].upper()
                        break
            if not reason and isinstance(err.get('status'), str):
                reason = err['status'].upper()
    except (ValueError, TypeError):
        pass

    combined = reason + ' ' + raw
    if 'API_KEY_INVALID' in combined or 'API KEY NOT VALID' in combined:
        return ('API_KEY_INVALID', 'Google отклонил API-ключ. Проверьте, что он скопирован из Google Cloud без ошибок.')
    if 'API_KEY_SERVICE_BLOCKED' in combined or 'SERVICE_DISABLED' in combined or 'API HAS NOT BEEN USED' in combined or 'ACCESS_NOT_CONFIGURED' in combined:
        return ('API_NOT_ENABLED', 'Доступ к Google Safe Browsing API не разрешён в проекте Google Cloud. Проверьте включение API и ограничения ключа.')
    if ('API_KEY_HTTP_REFERRER_BLOCKED' in combined or 'API_KEY_IP_ADDRESS_BLOCKED' in combined
        or 'API_KEY_ANDROID_APP_BLOCKED' in combined or 'API_KEY_IOS_APP_BLOCKED' in combined
        or 'API_KEY_RESTRICTION' in combined or 'REFERER' in combined and 'BLOCKED' in combined):
        return ('KEY_RESTRICTION', 'Google отклонил запрос из-за ограничений API-ключа. Для серверного Render не подходит ограничение по сайтам (HTTP referrer).')
    if 'API_KEY' in combined and ('BLOCKED' in combined or 'RESTRICT' in combined):
        return ('KEY_RESTRICTION', 'Проверьте ограничения ключа в Google Cloud: ему должен быть разрешён Safe Browsing API и вызов с сервера.')
    if ('INVALID_ARGUMENT' in combined or 'INVALID URL' in combined or
        ('INVALID' in combined and 'URLS' in combined)):
        return ('INVALID_ARGUMENT', 'Google отклонил параметры запроса. Проверьте URL и версию API; нужен Safe Browsing v5 urls:search.')
    if response.status_code == 400:
        return ('HTTP_400_UNCLASSIFIED', 'Google вернул HTTP 400. Точная причина не распознана: проверьте действительность ключа, Safe Browsing API и ограничения в Google Cloud.')
    return (f'HTTP_{response.status_code}', f'Google Safe Browsing: ошибка HTTP {response.status_code}. Проверка не выполнена.')


async def google_check(url: str, api_key: str | None) -> dict[str, Any]:
    """Check an explicit URL with Google's Safe Browsing v5 API.

    Errors are described by category, without logging/requesting the user's API key.
    A failed/malformed lookup is NEVER treated as a clean URL.
    """
    provider = 'Google Safe Browsing'
    if not api_key:
        return _inactive(provider, 'API-ключ не настроен.')
    cache_key = hashlib.sha256((api_key + '\0' + url).encode()).hexdigest()
    now = time.monotonic()
    existing = _GOOGLE_CACHE.get(cache_key)
    if existing and existing[0] > now:
        return dict(existing[1])
    if existing:
        del _GOOGLE_CACHE[cache_key]

    try:
        # Explicitly request JSON so parsing does not depend on provider defaults.
        # The URL is only sent after the user authorises sending it to services.
        async with httpx.AsyncClient(timeout=12, trust_env=False, follow_redirects=False) as client:
            resp = await client.get(
                'https://safebrowsing.googleapis.com/v5/urls:search',
                params={'urls': url, 'key': api_key, 'alt': 'json'},
                headers={'Accept': 'application/json'},
            )
    except httpx.TimeoutException:
        return {'name': provider, 'status': 'error', 'detections': 0,
                'message': 'Google Safe Browsing не ответил вовремя (тайм-аут). Повторите позже.'}
    except httpx.RequestError:
        return {'name': provider, 'status': 'error', 'detections': 0,
                'message': 'Ошибка сетевого соединения с Google Safe Browsing.'}

    if resp.status_code == 429:
        return {'name': provider, 'status': 'error', 'detections': 0,
                'message': 'Google Safe Browsing ограничил число запросов (HTTP 429). Повторите позже.'}
    if resp.status_code in (401, 403):
        diagnostic_code, explanation = _google_failure_hint(resp)
        return {'name': provider, 'status': 'error', 'detections': 0,
                'diagnostic_code': diagnostic_code, 'message': explanation}
    if resp.status_code != 200:
        diagnostic_code, explanation = _google_failure_hint(resp)
        return {'name': provider, 'status': 'error', 'detections': 0,
                'diagnostic_code': diagnostic_code, 'message': explanation}

    try:
        body = resp.json()
    except ValueError:
        return {'name': provider, 'status': 'error', 'detections': 0,
                'message': 'Google Safe Browsing вернул ответ не в формате JSON; проверка не выполнена.'}
    if not isinstance(body, dict) or not isinstance(body.get('threats', []), list):
        return {'name': provider, 'status': 'error', 'detections': 0,
                'message': 'Неожиданный формат ответа Google Safe Browsing; проверка не выполнена.'}

    threats = body.get('threats', [])
    types = sorted({str(t) for match in threats if isinstance(match, dict)
                    for t in (match.get('threatTypes') or []) if isinstance(t, str)})
    output = {'name': provider, 'status': 'checked', 'detections': len(threats),
              'threats': types,
              'message': 'Google сообщает о возможной угрозе по ссылке.' if threats
                         else 'Совпадений в известных списках Google не найдено.'}
    duration = _google_cache_seconds(body.get('cacheDuration'))
    if duration > 0:
        if len(_GOOGLE_CACHE) >= 512:
            # Bound memory on free Render instances.
            oldest_key = next(iter(_GOOGLE_CACHE))
            del _GOOGLE_CACHE[oldest_key]
        _GOOGLE_CACHE[cache_key] = (time.monotonic() + duration, output)
    return output


async def virustotal_check(url: str, api_key: str | None) -> dict[str, Any]:
    provider = 'VirusTotal'
    if not api_key:
        return _inactive(provider, 'API-ключ не настроен.')
    if not await take_virustotal_slot():
        return {'name': provider, 'status': 'error', 'detections': 0,
                'message': 'Лимит бесплатных проверок VirusTotal. Повторите примерно через минуту.'}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    try:
        async with httpx.AsyncClient(timeout=8, trust_env=False, follow_redirects=False) as client:
            resp = await client.get(f'https://www.virustotal.com/api/v3/urls/{url_id}',
                                    headers={'x-apikey': api_key, 'accept': 'application/json'})
        if resp.status_code == 404:
            return {'name': provider, 'status': 'no_data', 'message': 'Нет готового отчёта по этому URL.', 'detections': 0}
        if resp.status_code == 429:
            return {'name': provider, 'status': 'error', 'message': 'Превышен лимит VirusTotal.', 'detections': 0}
        if resp.status_code in (401, 403):
            return {'name': provider, 'status': 'error', 'message': 'Ключ VirusTotal отклонён: проверьте права API.', 'detections': 0}
        if resp.status_code != 200:
            return {'name': provider, 'status': 'error', 'message': f'Проверка недоступна (HTTP {resp.status_code}).', 'detections': 0}
        stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if not stats:
            return {'name': provider, 'status': 'no_data', 'message': 'Отчёт найден, но результатов анализа нет.', 'detections': 0}
        malicious = max(0, int(stats.get('malicious', 0)))
        suspicious = max(0, int(stats.get('suspicious', 0)))
        total = sum(max(0, int(v)) for v in stats.values() if isinstance(v, int))
        return {'name': provider, 'status': 'checked', 'detections': malicious,
                'suspicious': suspicious, 'total': total,
                'message': f'Готовый отчёт: {malicious} опасных, {suspicious} подозрительных из {total}.'}
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return {'name': provider, 'status': 'error', 'message': 'Сервис временно недоступен.', 'detections': 0}


async def analyse_url(raw: str, consent: bool, inspect_headers: bool) -> dict[str, Any]:
    link = validate_url(raw)
    gkey = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    vkey = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    signals = heuristic_signals(link)
    calls: list[Any] = []
    if consent:
        calls.extend([google_check(link.original, gkey), virustotal_check(link.original, vkey)])
    if inspect_headers:
        calls.append(probe_content(link))
    results = await asyncio.gather(*calls) if calls else []
    providers = results[:2] if consent else [
        _inactive("Google Safe Browsing", "Не разрешена передача URL внешним сервисам."),
        _inactive("VirusTotal", "Не разрешена передача URL внешним сервисам."),
    ]
    probe = results[-1] if inspect_headers else {"status": "skipped", "message": "Запрос заголовков не выполнялся."}
    content = guess_content(link, probe.get("mime") if probe.get("status") == "ok" else None)

    google_hit = any(p["name"] == "Google Safe Browsing" and p["status"] == "checked" and p.get("detections", 0) > 0 for p in providers)
    vt_mal = next((p.get("detections", 0) for p in providers if p["name"] == "VirusTotal" and p["status"] == "checked"), 0)
    vt_susp = next((p.get("suspicious", 0) for p in providers if p["name"] == "VirusTotal" and p["status"] == "checked"), 0)
    checked_any = any(p["status"] == "checked" for p in providers)
    high_signal = any(s["severity"] == "high" for s in signals)
    medium_signal = any(s["severity"] == "medium" for s in signals)
    if google_hit or vt_mal >= 2:
        risk = "danger"
        title = "Есть сообщения о возможной угрозе"
        detail = "Один или несколько сервисов указали на потенциальную опасность. Лучше не открывать эту ссылку."
    elif vt_mal > 0 or vt_susp > 0 or high_signal or medium_signal:
        risk = "caution"
        title = "Требуется осторожность"
        detail = "Есть признаки риска. Они не доказывают наличие вируса, но ссылку лучше не открывать без дополнительной проверки."
    elif checked_any and any(p["status"] != "checked" for p in providers):
        # A clean report from one database cannot make an incomplete check green.
        risk = "unknown"
        title = "Проверка выполнена частично"
        detail = "Одна из баз не ответила или не содержит данных по ссылке. Обнаруженных угроз недостаточно, чтобы подтвердить безопасность."
    elif checked_any:
        risk = "low"
        title = "Известных угроз не обнаружено"
        detail = "Это не гарантия безопасности: новые угрозы могут отсутствовать в базах."
    else:
        risk = "unknown"
        title = "Недостаточно данных"
        detail = "Без доступных внешних проверок нельзя сделать вывод о безопасности ссылки."
    return {
        "domain": link.host,
        "display_url": link.safe_display,
        "risk": risk,
        "title": title,
        "detail": detail,
        "content": content,
        "signals": signals,
        "providers": providers,
        "header_probe": {"status": probe["status"], "message": probe["message"]},
        "disclaimer": "Проверяется репутация URL и заявленный формат, а не наличие вируса внутри скачиваемого файла. Базы угроз могут ошибаться в обе стороны.",
    }
