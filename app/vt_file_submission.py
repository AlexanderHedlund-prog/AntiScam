"""Optional, explicit, public VirusTotal file submission for non-confidential samples.

Disabled by default. Never store file bytes or disclose API key. The website
operator must verify their account terms before enabling this on a public site.
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
from collections import deque
from typing import Any

import httpx

from app.reputation_quota import take_virustotal_slot

SUBMISSION_MAX_BYTES = 8 * 1024 * 1024  # below public API 32MB upload threshold
MAX_DAILY_SUBMISSIONS = 8  # process-local cap, not a distributed quota
TOKEN_TTL = 30 * 60
_SESSIONS: dict[str, dict[str, Any]] = {}
_RECENT: dict[str, float] = {}
_SUBMISSIONS: deque[float] = deque()
_LOCK = asyncio.Lock()


def uploads_enabled() -> bool:
    """Owner must explicitly enable after reviewing VirusTotal terms/privacy."""
    return os.getenv('VT_FILE_UPLOAD_ENABLED', '').strip().lower() == 'true'


def _provider(status: str, message: str, **kwargs: Any) -> dict[str, Any]:
    return {'name': 'VirusTotal (новый анализ)', 'status': status, 'message': message, **kwargs}


def _normalize_stats(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return _provider('error', 'VirusTotal вернул некорректный отчёт.')
    counts = payload.get('stats')
    if not isinstance(counts, dict):
        return _provider('no_data', 'Анализ завершён, но итоговые данные пока отсутствуют.')
    try:
        malicious = max(0, int(counts.get('malicious', 0)))
        suspicious = max(0, int(counts.get('suspicious', 0)))
        total = sum(max(0, int(n)) for n in counts.values() if isinstance(n, int) and not isinstance(n, bool))
    except (ValueError, TypeError, OverflowError):
        return _provider('error', 'VirusTotal вернул некорректные числа в отчёте.')
    if total < 1:
        return _provider('no_data', 'Сканирование завершилось без доступных результатов антивирусов.')
    return _provider('checked', f'Новое сканирование завершено: {malicious} опасных, {suspicious} подозрительных из {total}. Полная безопасность не гарантируется.',
                     detections=malicious, suspicious=suspicious, total=total)


def _cleanup(now: float) -> None:
    for token, obj in list(_SESSIONS.items()):
        if now - obj['time'] > TOKEN_TTL:
            del _SESSIONS[token]
    for digest, when in list(_RECENT.items()):
        if now - when > 3600:
            del _RECENT[digest]
    while _SUBMISSIONS and now - _SUBMISSIONS[0] > 86400:
        _SUBMISSIONS.popleft()


async def submit_unknown_file(data: bytes, digest: str, filename: str) -> dict[str, Any]:
    """Only call after both separate upload permission and no VT hash report.

    * No outbound request when upload feature is off.
    * No file persistence and no file data in logs.
    * Limit submission count to protect the public API key.
    """
    if not uploads_enabled():
        return _provider('error', 'Новые загрузки VirusTotal отключены владельцем сайта. Сверка SHA-256 остаётся доступной.')
    key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return _provider('error', 'Не настроен API-ключ VirusTotal.')
    if not data or len(data) > SUBMISSION_MAX_BYTES:
        return _provider('error', 'Разрешены только непустые файлы размером не более 8 МБ.')

    now = time.monotonic()
    async with _LOCK:
        _cleanup(now)
        if digest in _RECENT:
            return _provider('pending', 'Такой файл уже был отправлен недавно. Подождите и снова проверьте его SHA-256.')
        if len(_SUBMISSIONS) >= MAX_DAILY_SUBMISSIONS:
            return _provider('error', 'Дневной лимит новых отправок исчерпан; обычная проверка хеша доступна.')
        # Reserve before upload to avoid concurrent duplicate submissions.
        _SUBMISSIONS.append(now)
        _RECENT[digest] = now

    if not await take_virustotal_slot():
        async with _LOCK:
            _RECENT.pop(digest, None)
            try:
                _SUBMISSIONS.remove(now)
            except ValueError:
                pass
        return _provider('error', 'Лимит обращений к VirusTotal. Попробуйте позже.')
    # A harmless generic name avoids disclosure of potentially identifying filenames.
    try:
        async with httpx.AsyncClient(timeout=25, trust_env=False, follow_redirects=False) as client:
            resp = await client.post('https://www.virustotal.com/api/v3/files',
                                     headers={'x-apikey': key, 'accept': 'application/json'},
                                     files={'file': ('sample.bin', data, 'application/octet-stream')})
    except httpx.HTTPError:
        return _provider('error', 'Не удалось связаться с VirusTotal для отправки файла. Попробуйте позже.')
    if resp.status_code == 429:
        return _provider('error', 'VirusTotal ограничил количество запросов. Попробуйте позже.')
    if resp.status_code in (401, 403):
        return _provider('error', 'VirusTotal отклонил запрос: проверьте ключ и разрешённые возможности API.')
    if resp.status_code != 200:
        return _provider('error', f'VirusTotal не принял файл (HTTP {resp.status_code}).')
    try:
        analysis_id = resp.json()['data']['id']
        if not isinstance(analysis_id, str) or not re.fullmatch(r'[a-zA-Z0-9_\-=]{4,500}', analysis_id):
            raise ValueError('bad analysis id')
    except (ValueError, TypeError, KeyError):
        return _provider('error', 'Файл был отправлен, но VirusTotal не вернул корректный номер анализа.')

    token = secrets.token_urlsafe(32)
    async with _LOCK:
        _cleanup(time.monotonic())
        _SESSIONS[token] = {'id': analysis_id, 'time': time.monotonic()}
    return _provider('pending', 'Файл отправлен в VirusTotal по вашему разрешению. Проверка ещё выполняется. Нажмите «Узнать результат» через минуту.',
                     analysis_token=token)


async def check_analysis(token: str) -> dict[str, Any]:
    if not uploads_enabled() or not os.getenv('VIRUSTOTAL_API_KEY', '').strip():
        return _provider('error', 'Проверка новых файлов отключена владельцем сайта.')
    async with _LOCK:
        _cleanup(time.monotonic())
        info = _SESSIONS.get(token)
    if not info:
        return _provider('error', 'Время ожидания отчёта истекло или сервер перезапускался. Загрузите файл снова для проверки SHA-256.')
    if not await take_virustotal_slot():
        return _provider('pending', 'Лимит VirusTotal: попробуйте снова через минуту.', analysis_token=token)
    try:
        async with httpx.AsyncClient(timeout=12, trust_env=False, follow_redirects=False) as client:
            resp = await client.get(f'https://www.virustotal.com/api/v3/analyses/{info["id"]}',
                                    headers={'x-apikey': os.environ['VIRUSTOTAL_API_KEY'].strip(), 'accept': 'application/json'})
    except httpx.HTTPError:
        return _provider('pending', 'Связь с VirusTotal временно недоступна. Повторите попытку позже.', analysis_token=token)
    if resp.status_code == 429:
        return _provider('pending', 'Достигнут лимит запросов VirusTotal. Повторите попытку через минуту.', analysis_token=token)
    if resp.status_code != 200:
        return _provider('error', f'Не удалось получить отчёт VirusTotal (HTTP {resp.status_code}).')
    try:
        attributes = resp.json()['data']['attributes']
        if attributes['status'] != 'completed':
            return _provider('pending', 'VirusTotal ещё анализирует файл. Повторите проверку позднее.', analysis_token=token)
        result = _normalize_stats(attributes)
    except (KeyError, ValueError, TypeError):
        return _provider('error', 'VirusTotal вернул некорректные данные анализа.')
    if result['status'] in {'checked', 'no_data'}:
        async with _LOCK:
            _SESSIONS.pop(token, None)
    return result
