"""Optional, local-only ClamAV `clamd` INSTREAM client.

A ClamAV daemon must be provisioned separately on the *same trusted machine*
with a private Unix socket. No remote address or unauthenticated TCP listener
is accepted. File bytes are not sent to a third-party cloud provider.
"""
from __future__ import annotations

import asyncio
import os
import re
import struct
from typing import Any

MAX_REPLY = 512
_MAX_PARALLEL = asyncio.Semaphore(2)


def configured() -> bool:
    return bool(os.getenv('CLAMD_SOCKET_PATH', '').strip())


async def scan_clamav(data: bytes) -> dict[str, Any]:
    name = 'ClamAV (антивирусные сигнатуры)'
    path = os.getenv('CLAMD_SOCKET_PATH', '').strip()
    if not path:
        return {'name': name, 'status': 'skipped', 'message': 'Антивирус ClamAV не подключён. На бесплатном Render доступен только собственный ограниченный анализ.'}
    if not path.startswith('/') or '\x00' in path or len(path) > 100:
        return {'name': name, 'status': 'error', 'message': 'Некорректная настройка локального сокета ClamAV.'}

    async def _run():
        writer = None
        try:
            reader, writer = await asyncio.open_unix_connection(path)
            writer.write(b'zINSTREAM\x00')
            for pos in range(0, len(data), 65536):
                chunk = data[pos:pos + 65536]
                writer.write(struct.pack('>I', len(chunk)) + chunk)
                await writer.drain()
            writer.write(struct.pack('>I', 0))
            await writer.drain()
            reply = await reader.readuntil(b'\x00')
            if len(reply) > MAX_REPLY:
                raise ValueError('Unexpectedly long clamd reply')
            text = reply[:-1].decode('utf-8', 'replace')
            if text == 'stream: OK':
                return {'name': name, 'status': 'checked', 'detections': 0, 'message': 'ClamAV проверил байты файла: известных сигнатур не найдено. Это не гарантия безопасности.'}
            match = re.fullmatch(r'stream: (.{1,150}) FOUND', text)
            if match:
                signature = ''.join(c for c in match.group(1) if c.isprintable())[:120]
                if signature.lower().startswith('eicar'):
                    return {'name': name, 'status': 'checked', 'detections': 0, 'test_signatures': 1,
                            'message': 'ClamAV обнаружил безвредный тестовый образец EICAR (это не настоящий вирус).'}
                return {'name': name, 'status': 'checked', 'detections': 1, 'signature': signature,
                        'message': 'ClamAV обнаружил сигнатуру «' + signature + '». Не открывайте файл.'}
            return {'name': name, 'status': 'error', 'message': 'ClamAV вернул ошибку или непонятный результат. Проверка не выполнена.'}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionError):
                    pass

    try:
        async with _MAX_PARALLEL:
            return await asyncio.wait_for(_run(), timeout=14)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            OSError, ConnectionError, ValueError, RuntimeError):
        return {'name': name, 'status': 'error', 'message': 'Локальный антивирус недоступен или не завершил проверку. Файл нельзя считать проверенным ClamAV.'}
