"""AntiScam API and multi-page frontend."""
from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.scanner import URLValidationError, analyse_url
from app.file_scanner import MAX_FILE_BYTES, MAX_MULTIPART_BYTES, analyse_file
from app.vt_file_submission import uploads_enabled, check_analysis

load_dotenv()
BASE = Path(__file__).resolve().parent
app = FastAPI(title='AntiScam API', version='1.3.1', docs_url=None, redoc_url=None, openapi_url=None)
app.mount('/assets', StaticFiles(directory=BASE / 'static'), name='assets')
_LIMIT = int(os.getenv('RATE_LIMIT_PER_MINUTE', '12'))
_TRAFFIC: dict[str, deque[float]] = defaultdict(deque)
_TRAFFIC_LOCK = asyncio.Lock()
_GLOBAL_TRAFFIC: deque[float] = deque()
_GLOBAL_PER_MINUTE = max(2, int(os.getenv('GLOBAL_RATE_LIMIT_PER_MINUTE', '80')))
_FILE_SCAN_SEMAPHORE = asyncio.Semaphore(max(1, min(4, int(os.getenv('MAX_ACTIVE_FILE_SCANS', '2')))))


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    share_with_services: bool = False
    inspect_headers: bool = False
    inspect_page: bool = False
    inspect_download: bool = False


class VTStatusRequest(BaseModel):
    token: str = Field(min_length=20, max_length=1100, pattern=r'^[a-zA-Z0-9_.\-]+$')


@app.middleware('http')
async def security_headers(request: Request, call_next):
    # Require a bounded multipart Content-Length BEFORE Starlette spools a file.
    if request.url.path == '/api/scan-file' and request.method == 'POST':
        length = request.headers.get('content-length', '')
        if not length.isdecimal():
            response = JSONResponse(status_code=411, content={'detail': 'Для загрузки файла требуется Content-Length.'})
        elif int(length) > MAX_MULTIPART_BYTES:
            response = JSONResponse(status_code=413, content={'detail': 'Максимальный размер файла — 8 МБ.'})
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


async def check_rate_limit(client: str) -> bool:
    now = time.monotonic()
    async with _TRAFFIC_LOCK:
        # Cap global traffic and the number of tracked source addresses.
        # In-memory limits apply only to this one process, not a cluster.
        while _GLOBAL_TRAFFIC and now - _GLOBAL_TRAFFIC[0] > 60:
            _GLOBAL_TRAFFIC.popleft()
        if len(_GLOBAL_TRAFFIC) >= _GLOBAL_PER_MINUTE:
            return False
        if client not in _TRAFFIC and len(_TRAFFIC) >= 2048:
            for host, moments in list(_TRAFFIC.items()):
                if not moments or now - moments[-1] > 61:
                    del _TRAFFIC[host]
            if len(_TRAFFIC) >= 2048:
                return False
        moments = _TRAFFIC[client]
        while moments and now - moments[0] > 60:
            moments.popleft()
        if len(moments) >= _LIMIT:
            return False
        moments.append(now)
        _GLOBAL_TRAFFIC.append(now)
        return True


@app.get('/')
@app.get('/file')
@app.get('/about')
@app.get('/agreement')
async def index():
    return FileResponse(BASE / 'static' / 'index.html')


@app.get('/health')
async def health():
    return {'status': 'ok', 'service': 'AntiScam', 'version': '1.3.1'}


@app.get('/api/providers')
async def providers_status():
    """Status of integrations, not proof that external providers are reachable."""
    return {
        'google_safe_browsing': {'configured': bool(os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '').strip()), 'version': 'v5'},
        'virustotal': {'configured': bool(os.getenv('VIRUSTOTAL_API_KEY', '').strip()), 'new_file_upload_enabled': uploads_enabled()},
        'note': 'configured означает только наличие ключа; действительность ключа подтверждается при проверке ссылки.',
    }


@app.post('/api/scan')
async def scan(payload: ScanRequest, request: Request):
    # Deliberately never log URLs: query strings may contain access tokens.
    ip = request.client.host if request.client else 'unknown'
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail='Слишком много проверок. Повторите попытку через минуту.')
    try:
        return await analyse_url(payload.url, payload.share_with_services, payload.inspect_headers, payload.inspect_page, payload.inspect_download)
    except URLValidationError as exc:
        return JSONResponse(status_code=422, content={'detail': str(exc)})


@app.post('/api/scan-file')
async def scan_file(request: Request, file: UploadFile = File(...), check_hash: bool = Form(False), submit_to_vt: bool = Form(False), vt_public_consent: bool = Form(False)):
    ip = request.client.host if request.client else 'unknown'
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail='Слишком много проверок. Повторите попытку через минуту.')
    if submit_to_vt and not vt_public_consent:
        raise HTTPException(status_code=422, detail='Для публичной отправки файла в VirusTotal требуется отдельное подтверждение соглашения о передаче файла.')
    if submit_to_vt and not check_hash:
        raise HTTPException(status_code=422, detail='Для отправки нового файла необходимо согласие на проверку VirusTotal по SHA-256.')
    if submit_to_vt and not uploads_enabled():
        raise HTTPException(status_code=403, detail='Отправка новых файлов в VirusTotal отключена владельцем сайта.')
    # Refuse concurrent expensive scans on the small public Render instance.
    try:
        await asyncio.wait_for(_FILE_SCAN_SEMAPHORE.acquire(), timeout=0.15)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail='Сервер занят проверками файлов. Повторите попытку через минуту.')
    # Small bounded reads; never execute, persist or forward bytes unless separately permitted.
    data = bytearray()
    try:
        while chunk := await file.read(65536):
            if len(data) + len(chunk) > MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail='Максимальный размер файла — 8 МБ.')
            data.extend(chunk)
        if not data:
            raise HTTPException(status_code=422, detail='Нельзя проверить пустой файл.')
        return await analyse_file(bytes(data), file.filename or 'без_названия', check_hash, submit_to_vt=submit_to_vt)
    finally:
        try:
            await file.close()
        finally:
            data.clear()
            _FILE_SCAN_SEMAPHORE.release()


@app.post('/api/vt-file-status')
async def vt_file_status(payload: VTStatusRequest, request: Request):
    ip = request.client.host if request.client else 'unknown'
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail='Слишком много проверок. Повторите через минуту.')
    return await check_analysis(payload.token)
