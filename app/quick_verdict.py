"""Human-readable summaries with explicit limits of malware detection.

Risk here is an evidence-based triage value, *not* a proof of safety.
"""
from __future__ import annotations

from typing import Literal


def build_quick_verdict(risk: str, *, kind: Literal['url', 'file']) -> dict[str, str]:
    """Return a concise answer to the question 'Есть ли вирус?'.

    A phishing URL can be harmful without containing a virus; accordingly the
    verdict uses 'угроза' for URLs. Only a positive malware reputation report
    can justify saying a threat was found; heuristics alone never do.
    """
    if kind not in ('url', 'file'):
        raise ValueError('Unknown inspection kind')

    if risk == 'danger':
        return {
            'state': 'danger',
            'label': 'Есть ли вирус или угроза?',
            'answer': 'Да, обнаружена известная угроза' if kind == 'url' else 'Есть обнаружения вредоносности',
            'note': ('Сервис репутации отметил этот адрес как опасный. Это может быть фишинг или вредоносное ПО.'
                     if kind == 'url' else
                     'Антивирусы в отчёте VirusTotal обнаружили угрозу. Не открывайте файл.'),
        }
    if risk == 'caution':
        return {
            'state': 'caution',
            'label': 'Есть ли вирус или угроза?',
            'answer': 'Возможно опасно — вирус не подтверждён',
            'note': 'Найдены подозрительные признаки. Это повод отказаться от открытия, но не доказательство вируса.',
        }
    if risk == 'low':
        return {
            'state': 'low',
            'label': 'Есть ли вирус или угроза?',
            'answer': 'Известных угроз не обнаружено',
            'note': ('Доступные базы не нашли угроз. Это НЕ означает, что по ссылке точно нет вируса: полное динамическое сканирование не выполнялось.'
                     if kind == 'url' else
                     'Доступные проверки не нашли известных угроз. Новый или изменённый вирус может остаться незамеченным.'),
        }
    return {
        'state': 'unknown',
        'label': 'Есть ли вирус или угроза?',
        'answer': 'Пока невозможно определить',
        'note': 'Данных недостаточно, чтобы подтвердить наличие или отсутствие вредоносного содержимого.',
    }
