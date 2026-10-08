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

load_dotenv()
BASE = Path(__file__).resolve().parent
app = FastAPI(title='AntiScam API', version='0.3.0', docs_url=None, redoc_url=None, openapi_url=None)
app.mount('/assets', StaticFiles(directory=BASE / 'static'), name='assets')
_LIMIT = int(os.getenv('RATE_LIMIT_PER_MINUTE', '12'))
_TRAFFIC: dict[str, deque[float]] = defaultdict(deque)
_TRAFFIC_LOCK = asyncio.Lock()


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    share_with_services: bool = False
    inspect_headers: bool = False


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
        if len(_TRAFFIC) > 3000:
            for host, moments in list(_TRAFFIC.items()):
                if not moments or now - moments[-1] > 61:
                    del _TRAFFIC[host]
        moments = _TRAFFIC[client]
        while moments and now - moments[0] > 60:
            moments.popleft()
        if len(moments) >= _LIMIT:
            return False
        moments.append(now)
        return True


@app.get('/')
@app.get('/file')
@app.get('/about')
async def index():
    return FileResponse(BASE / 'static' / 'index.html')


@app.get('/health')
async def health():
    return {'status': 'ok', 'service': 'AntiScam', 'version': '0.3.0'}


@app.get('/api/providers')
async def providers_status():
    """Status of integrations, not proof that external providers are reachable."""
    return {
        'google_safe_browsing': {'configured': bool(os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '').strip()), 'version': 'v5'},
        'virustotal': {'configured': bool(os.getenv('VIRUSTOTAL_API_KEY', '').strip())},
        'note': 'configured означает только наличие ключа; действительность ключа подтверждается при проверке ссылки.',
    }


@app.post('/api/scan')
async def scan(payload: ScanRequest, request: Request):
    # Deliberately never log URLs: query strings may contain access tokens.
    ip = request.client.host if request.client else 'unknown'
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail='Слишком много проверок. Повторите попытку через минуту.')
    try:
        return await analyse_url(payload.url, payload.share_with_services, payload.inspect_headers)
    except URLValidationError as exc:
        return JSONResponse(status_code=422, content={'detail': str(exc)})


@app.post('/api/scan-file')
async def scan_file(request: Request, file: UploadFile = File(...), check_hash: bool = Form(False)):
    ip = request.client.host if request.client else 'unknown'
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail='Слишком много проверок. Повторите попытку через минуту.')
    # Small bounded reads; never execute, unpack, persist, or forward file bytes.
    data = bytearray()
    try:
        while chunk := await file.read(65536):
            if len(data) + len(chunk) > MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail='Максимальный размер файла — 8 МБ.')
            data.extend(chunk)
        if not data:
            raise HTTPException(status_code=422, detail='Нельзя проверить пустой файл.')
        return await analyse_file(bytes(data), file.filename or 'без_названия', check_hash)
    finally:
        await file.close()
        data.clear()
