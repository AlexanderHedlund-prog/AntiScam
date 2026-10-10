"""Offline, explainable URL-only anti-phishing heuristics for AntiScam.

No network traffic, DNS resolution or URL execution. These indicators are
not virus detection and do not establish the trustworthiness of a page.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, unquote, urlsplit

# Known official roots are examples, NOT an assertion that every other domain
# carrying these names is malicious. Flag only brand-like domains ALSO using
# security/login/verification lures or obvious reversed host impersonation.
OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    'google': ('google.com', 'google.ru', 'google.de', 'google.co.uk', 'google.fr', 'google.co.jp', 'google.com.au', 'google.co.in', 'google.com.br', 'google.ca', 'google.es', 'google.it', 'google.nl', 'google.pl', 'googleapis.com', 'googleusercontent.com', 'youtube.com'),
    'paypal': ('paypal.com', 'paypal.me'),
    'microsoft': ('microsoft.com', 'microsoftonline.com', 'live.com', 'office.com'),
    'apple': ('apple.com', 'icloud.com'),
    'telegram': ('telegram.org', 't.me'),
    'steam': ('steampowered.com', 'steamcommunity.com'),
    'discord': ('discord.com', 'discord.gg'),
    'gosuslugi': ('gosuslugi.ru',),
    'sberbank': ('sberbank.ru', 'sber.ru'),
}
AUTH_WORDS = frozenset({
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
    'auth', 'account', 'password', 'support', 'update', 'confirm', 'wallet',
    'payment', 'billing', 'reset', 'restore', 'access', 'block', 'blocked',
    'vhod', 'podtverdi', 'proverka', 'akkaunt', 'kod',
})
SUSPICIOUS_SUFFIXES = frozenset({'.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.msi', '.apk', '.jar', '.js', '.hta', '.lnk', '.com'})
DOCUMENT_SUFFIXES = frozenset({'.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.jpg', '.png', '.zip'})
REDIRECT_KEYS = frozenset({'next', 'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_to', 'returnurl', 'url', 'target', 'dest', 'destination', 'continue'})
SENSITIVE_KEYS = frozenset({'access_token', 'auth_token', 'api_key', 'apikey', 'secret', 'password', 'pass', 'session_token'})
COMMON_SHORTENERS = frozenset({'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'clck.ru', 'goo.su', 'shorturl.at'})


def _is_official(host: str, brand: str) -> bool:
    return any(host == root or host.endswith('.' + root) for root in OFFICIAL_DOMAINS[brand])


def _words(text: str) -> set[str]:
    return set(filter(None, re.split(r'[^a-z0-9]+', text.lower())))


def _label_looks_like_brand(word: str, brand: str) -> bool:
    """Exact or common glyph substitutions, not a broad fuzzy-match accusation."""
    if word == brand:
        return True
    if len(word) != len(brand):
        return False
    swaps = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '5': 's'})
    return word.translate(swaps) == brand


def analyse_locally(link) -> dict:
    """Analyze already validated ValidURL; no network, no untrusted execution."""
    host = link.host.lower().rstrip('.')
    parts = urlsplit(link.original)
    path = unquote(link.path or '')[:2048]
    query = parts.query[:2048]
    signals: list[dict[str, str]] = []
    categories: set[str] = set()

    def add(category: str, severity: str, text: str):
        if category not in categories:
            categories.add(category)
            signals.append({'severity': severity, 'text': text, 'source': 'local', 'category': category})

    if link.scheme == 'http':
        add('unencrypted', 'medium', 'Ссылка использует HTTP без шифрования. Не вводите на таком сайте пароли и платёжные данные.')

    try:
        ipaddress.ip_address(host)
        add('ip_host', 'medium', 'Вместо обычного домена используется IP-адрес. Проверьте, кому он принадлежит.')
    except ValueError:
        pass

    if host in COMMON_SHORTENERS or any(host.endswith('.' + d) for d in COMMON_SHORTENERS):
        add('shortener', 'medium', 'Сервис коротких ссылок скрывает конечный адрес. Переходы не выполнялись.')

    if 'xn--' in host.split('.') or any(label.startswith('xn--') for label in host.split('.')):
        add('punycode', 'medium', 'Домен записан через Punycode. Проверьте, не имитирует ли он знакомый сайт.')
    try:
        decoded_host = host.encode('ascii').decode('idna') if 'xn--' in host else host
    except (UnicodeError, ValueError):
        decoded_host = host
    if re.search(r'[а-яё]', decoded_host) and re.search(r'[a-z]', decoded_host):
        add('mixed_script', 'high', 'В домене смешаны кириллические и латинские буквы: возможна подмена похожих символов.')

    # Approximate typos in brand labels only alongside an auth/payment lure.
    # This is a warning of resemblance, not a claim of confirmed phishing.
    def near_brand(label: str, brand: str) -> bool:
        if len(brand) < 5 or abs(len(label) - len(brand)) > 1 or label == brand:
            return False
        if len(label) == len(brand):
            return sum(a != b for a, b in zip(label, brand)) == 1
        short, long = (label, brand) if len(label) < len(brand) else (brand, label)
        return any(short == long[:i] + long[i+1:] for i in range(len(long)))

    # Only alert on common brands when there is also a login/payment lure;
    # ordinary unrelated words or subdomains must not be called fraudulent.
    labels = host.split('.')
    flat_tokens = _words(host)
    lure = bool(flat_tokens & AUTH_WORDS)
    for brand in OFFICIAL_DOMAINS:
        if _is_official(host, brand):
            continue
        spoof_root = any(label == brand for label in labels[1:-1])
        branded_word = any(_label_looks_like_brand(word, brand) for word in flat_tokens)
        typo_lure = lure and any(near_brand(label, brand) for label in labels[:-1])
        if spoof_root or (branded_word and lure) or typo_lure:
            add('brand_spoof', 'high', 'Домен напоминает адрес известного сервиса, но не совпадает с его официальным адресом. Возможен фишинг.')
            break

    if host.count('.') >= 4:
        add('deep_subdomain', 'low', 'Много уровней поддомена: обратите внимание, какая часть адреса является настоящим доменом.')

    last_filename = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(last_filename).suffix
    if suffix in SUSPICIOUS_SUFFIXES:
        add('executable', 'high', 'Ссылка выглядит как загрузка исполняемой программы или скрипта. Не запускайте неизвестный файл.')
    if suffix in {'.docm', '.xlsm', '.pptm'}:
        add('macro', 'medium', 'Расширение файла допускает макросы, которые могут выполнять действия при открытии.')
    if any(last_filename.endswith(doc + exe) for doc in DOCUMENT_SUFFIXES for exe in SUSPICIOUS_SUFFIXES):
        add('double_suffix', 'high', 'Двойное расширение может маскировать программу под изображение или документ.')

    # Parse query locally only. Never issue GET to the redirect target.
    pairs = parse_qsl(query, keep_blank_values=False, max_num_fields=35, errors='replace') if query.count('&') <= 34 else []
    if query.count('&') > 34:
        add('query_many', 'low', 'В ссылке необычно много параметров. Точный смысл без открытия страницы неизвестен.')
    for key, value in pairs:
        key = key.lower().strip()
        if key in SENSITIVE_KEYS:
            add('credentials_in_url', 'medium', 'Параметры ссылки похожи на секретный токен или пароль. Не отправляйте такие URL посторонним.')
        if key in REDIRECT_KEYS:
            target = unquote(value[:512]).strip()
            if target.startswith('//'):
                target = 'https:' + target
            target_info = urlsplit(target)
            if target_info.scheme in {'http', 'https'} and target_info.hostname:
                dst_host = target_info.hostname.lower().rstrip('.')
                if dst_host != host and not dst_host.endswith('.' + host):
                    add('redirect', 'medium', 'В параметрах указан переход на другой домен. Конечный адрес не открывался и не проверялся.')
        # An extension in a query string is not evidence of an actual download.
        if key in {'file', 'filename', 'download', 'attachment'}:
            filename = PurePosixPath(unquote(value[:240])).name.lower()
            if any(filename.endswith(doc + exe) for doc in DOCUMENT_SUFFIXES for exe in SUSPICIOUS_SUFFIXES):
                add('query_double_suffix', 'high', 'В имени файла из параметров найдено двойное расширение (например, .pdf.exe).')

    if len(query) > 360:
        add('very_long_query', 'low', 'Очень длинный адрес с параметрами: внимательно проверьте источник ссылки.')
    if len(signals) > 12:
        signals = signals[:12]

    high = sum(s['severity'] == 'high' for s in signals)
    medium = sum(s['severity'] == 'medium' for s in signals)
    level = 'high' if high else 'medium' if medium else 'low' if signals else 'none'
    descriptions = {
        'high': 'Найдены заметные признаки возможного обмана или опасной загрузки.',
        'medium': 'Найдены признаки, требующие осторожности, но сами по себе они не доказывают угрозу.',
        'low': 'Найдены слабые признаки, которые встречаются и у обычных сайтов.',
        'none': 'По самому адресу явных признаков не найдено. Содержимое страницы и наличие вирусов не проверялись.',
    }
    return {
        'status': 'completed', 'method': 'Локальный анализ адреса без открытия страницы',
        'level': level, 'summary': descriptions[level], 'signals': signals,
        'checks': [
            'Домен и признаки подмены известных сервисов',
            'Символы, кодировка и скрытие конечного адреса',
            'Названия файлов, расширения и параметры переходов',
            'Тип соединения HTTP/HTTPS',
        ],
        'limitations': 'Только признаки в URL. Мы не загружали сайт, не запускали JavaScript и не проверяли вирусы внутри файлов.',
    }
