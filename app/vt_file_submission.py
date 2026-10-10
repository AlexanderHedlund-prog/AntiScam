"""Public VirusTotal file scanning, opt-in only.

No user file is uploaded unless separately consented to. Status tokens are
HMAC signed and survive Render's process restarts (unlike in-memory sessions).
The token conveys only the VirusTotal analysis id for that user's submission.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections import deque
from typing import Any

import httpx

from app.reputation_quota import take_virustotal_slot

SUBMISSION_MAX_BYTES = 8 * 1024 * 1024
MAX_DAILY_SUBMISSIONS = 8  # a conservative per-process, not global quota
TOKEN_TTL = 24 * 60 * 60
_SESSIONS: dict[str, dict[str, Any]] = {}  # compatibility; not required for token recovery
_RECENT: dict[str, float] = {}
_RECENT_TOKEN: dict[str, str] = {}
_SUBMISSIONS: deque[float] = deque()
_LOCK = asyncio.Lock()
_ANALYSIS_ID = re.compile(r'^[a-zA-Z0-9_\-=]{4,500}$')


def uploads_enabled() -> bool:
    return os.getenv('VT_FILE_UPLOAD_ENABLED', '').strip().lower() == 'true'


def _provider(status: str, message: str, **kwargs: Any) -> dict[str, Any]:
    return {'name': 'VirusTotal (новое сканирование)', 'status': status, 'message': message, **kwargs}


def _normalize_stats(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get('stats'), dict):
        return _provider('no_data', 'VirusTotal ещё не предоставил результаты антивирусных движков.')
    counts = payload['stats']
    try:
        values = {}
        for key in ('malicious', 'suspicious', 'harmless', 'undetected', 'failure', 'timeout', 'type-unsupported'):
            number = counts.get(key, 0)
            if type(number) is not int or number < 0:
                raise ValueError('invalid stats')
            values[key] = number
        analyzed = sum(values[k] for k in ('malicious', 'suspicious', 'harmless', 'undetected'))
    except (ValueError, TypeError, OverflowError):
        return _provider('error', 'VirusTotal вернул некорректные результаты проверки.')
    if analyzed == 0:
        return _provider('no_data', 'Анализ завершён, но ни один антивирус пока не предоставил проверяемый результат.')
    return _provider(
        'checked',
        f'Проверка завершена: {values["malicious"]} опасных, {values["suspicious"]} подозрительных из {analyzed} ответивших антивирусов. '
        'Отсутствие обнаружений не гарантирует безопасность.',
        detections=values['malicious'], suspicious=values['suspicious'], total=analyzed,
        unavailable=values['failure'] + values['timeout'] + values['type-unsupported'],
    )


def _hmac_key() -> bytes:
    # When no separate key has been installed on Render, use a purpose-derived
    # signing key. Tokens survive restarts as long as the VT API key is unchanged.
    secret = os.getenv('VT_STATUS_SIGNING_KEY', '').strip() or os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not secret:
        raise ValueError('no secret configured')
    return hashlib.sha256(b'antiscam-vt-status-v1\x00' + secret.encode()).digest()


def _make_token(analysis_id: str) -> str:
    if not _ANALYSIS_ID.fullmatch(analysis_id):
        raise ValueError('invalid analysis id')
    data = json.dumps({'id': analysis_id, 'iat': int(time.time()), 'nonce': secrets.token_hex(8)}, separators=(',', ':')).encode()
    body = base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    sig = hmac.new(_hmac_key(), body.encode(), hashlib.sha256).hexdigest()
    return 'v1.' + body + '.' + sig


def _read_token(token: str) -> str | None:
    try:
        version, body, sig = token.split('.')
        if version != 'v1' or len(body) > 850 or len(sig) != 64:
            return None
        expected = hmac.new(_hmac_key(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        content = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
        aid, iat = content['id'], content['iat']
        if not isinstance(aid, str) or not _ANALYSIS_ID.fullmatch(aid) or type(iat) is not int:
            return None
        if not 0 <= time.time() - iat <= TOKEN_TTL:
            return None
        return aid
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _cleanup(now: float) -> None:
    for digest, when in list(_RECENT.items()):
        if now - when > 3600:
            _RECENT.pop(digest, None)
            _RECENT_TOKEN.pop(digest, None)
    while _SUBMISSIONS and now - _SUBMISSIONS[0] > 86400:
        _SUBMISSIONS.popleft()
    if len(_SESSIONS) > 500:
        _SESSIONS.clear()


async def submit_unknown_file(data: bytes, digest: str, filename: str) -> dict[str, Any]:
    """Submit unknown file to VirusTotal, after separate explicit consent.

    Never called for an existing file hash report; incoming filename omitted.
    An HMAC token allows checking the result despite free Render restarts.
    """
    if not uploads_enabled():
        return _provider('error', 'Отправка новых файлов отключена владельцем сайта.')
    key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return _provider('error', 'Не настроен API-ключ VirusTotal.')
    if not data or len(data) > SUBMISSION_MAX_BYTES:
        return _provider('error', 'Разрешены только непустые файлы до 8 МБ.')
    if not re.fullmatch(r'[0-9a-f]{64}', digest) or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest):
        return _provider('error', 'Контрольная сумма загруженного файла не совпадает.')

    now = time.monotonic()
    async with _LOCK:
        _cleanup(now)
        if digest in _RECENT:
            old_token = _RECENT_TOKEN.get(digest)
            if old_token:
                return _provider('pending', 'Этот файл уже отправлен недавно. Используйте «Узнать результат», не загружая его повторно.', analysis_token=old_token)
            return _provider('pending', 'Такой файл уже отправлялся недавно. Повторите проверку позднее.')
        if len(_SUBMISSIONS) >= MAX_DAILY_SUBMISSIONS:
            return _provider('error', 'Лимит отправок на сегодня исчерпан. Проверка по хешу остаётся доступна.')
        _RECENT[digest] = now
        _SUBMISSIONS.append(now)

    if not await take_virustotal_slot():
        async with _LOCK:
            _RECENT.pop(digest, None)
            try: _SUBMISSIONS.remove(now)
            except ValueError: pass
        return _provider('error', 'Лимит запросов VirusTotal. Повторите примерно через минуту.')

    # Standard public upload endpoint for files <=32 MB; our bound is 8 MB.
    # The generic upload name avoids exposing filenames containing personal data.
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=7.0), trust_env=False, follow_redirects=False) as client:
            resp = await client.post('https://www.virustotal.com/api/v3/files',
                                     headers={'x-apikey': key, 'accept': 'application/json'},
                                     files={'file': ('sample.bin', data, 'application/octet-stream')})
    except httpx.HTTPError:
        # VT may have received the bytes before network failure. Avoid a blind
        # second upload; the hash lookup can find the sample eventually.
        return _provider('error', 'Не удалось подтвердить приём файла VirusTotal. Подождите и попробуйте поиск по SHA-256; не отправляйте его повторно сразу.')
    if resp.status_code == 429:
        return _provider('error', 'VirusTotal временно ограничил запросы (HTTP 429). Повторите позднее.')
    if resp.status_code in (401, 403):
        return _provider('error', 'VirusTotal отклонил загрузку. Проверьте права API-ключа и условия тарифа.')
    if resp.status_code != 200:
        return _provider('error', f'VirusTotal не принял новый файл (HTTP {resp.status_code}). Попробуйте позже.')
    try:
        analysis_id = resp.json()['data']['id']
        if not isinstance(analysis_id, str): raise ValueError('missing id')
        token = _make_token(analysis_id)
    except (ValueError, TypeError, KeyError):
        return _provider('error', 'Файл отправлен, но VirusTotal не выдал корректный идентификатор анализа. Попробуйте позднее поиск по SHA-256.')
    async with _LOCK:
        _RECENT_TOKEN[digest] = token
        _SESSIONS[token] = {'id': analysis_id, 'time': time.monotonic()}
    return _provider('pending', 'Файл принят VirusTotal. Проверка выполняется; нажмите «Узнать результат» через 45–60 секунд.', analysis_token=token)


async def check_analysis(token: str) -> dict[str, Any]:
    if not uploads_enabled() or not os.getenv('VIRUSTOTAL_API_KEY', '').strip():
        return _provider('error', 'Проверка новых файлов отключена владельцем сайта.')
    analysis_id = _read_token(token)
    if not analysis_id:
        return _provider('error', 'Не удалось подтвердить ссылку на анализ или истёк срок ожидания. Попробуйте снова проверить хеш.')
    if not await take_virustotal_slot():
        return _provider('pending', 'Лимит запросов VirusTotal. Повторите попытку через минуту.', analysis_token=token)
    try:
        async with httpx.AsyncClient(timeout=15.0, trust_env=False, follow_redirects=False) as client:
            resp = await client.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                                    headers={'x-apikey': os.environ['VIRUSTOTAL_API_KEY'].strip(), 'accept': 'application/json'})
    except httpx.HTTPError:
        return _provider('pending', 'Нет связи с VirusTotal. Попробуйте получить результат чуть позже.', analysis_token=token)
    if resp.status_code in (429, 503, 502, 500):
        return _provider('pending', f'VirusTotal временно недоступен (HTTP {resp.status_code}). Повторите позднее.', analysis_token=token)
    if resp.status_code in (401, 403):
        return _provider('error', 'VirusTotal отклонил ключ при получении отчёта (HTTP 401/403).')
    if resp.status_code == 404:
        return _provider('pending', 'Анализ пока не найден в VirusTotal. Повторите через минуту.', analysis_token=token)
    if resp.status_code != 200:
        return _provider('pending', f'Ошибка получения анализа (HTTP {resp.status_code}). Попробуйте позднее.', analysis_token=token)
    try:
        attributes = resp.json()['data']['attributes']
        if attributes['status'] != 'completed':
            return _provider('pending', 'VirusTotal ещё сканирует файл. Повторите проверку позднее.', analysis_token=token)
        result = _normalize_stats(attributes)
    except (KeyError, ValueError, TypeError):
        return _provider('pending', 'VirusTotal вернул неполный ответ. Повторите позднее.', analysis_token=token)
    if result['status'] == 'no_data':
        return _provider('pending', result['message'] + ' Попробуйте обновить результат позже.', analysis_token=token)
    if result['status'] == 'checked':
        async with _LOCK:
            _SESSIONS.pop(token, None)
    return result
