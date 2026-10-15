"""Conservative, actionable file guidance based on *reported evidence*.

No heuristics are presented as verified malware detections. Never call a file
'safe': a zero-detection report is only a record of engines that responded.
"""
from __future__ import annotations
from typing import Any


def assess_file(reputation: dict[str, Any], signals: list[dict[str, str]],
                partial: bool, *, eicar_only: bool = False) -> dict[str, Any]:
    status = reputation.get('status')
    detections = int(reputation.get('detections') or 0) if status == 'checked' else 0
    suspicious = int(reputation.get('suspicious') or 0) if status == 'checked' else 0
    total = int(reputation.get('total') or 0) if status == 'checked' else 0
    # The official EICAR 68-byte test string is not malware, even though AV
    # scanners are expressly designed to flag it.
    if eicar_only:
        risk = 'caution'
        answer = 'Это тест EICAR, а не настоящий вирус'
        title = 'Обнаружен тестовый образец EICAR'
        detail = 'Антивирусы специально распознают эту безвредную тестовую строку.'
        note = ('Результат демонстрирует обнаружение тестовой сигнатуры, но не означает, '
                'что в файле есть реальная вредоносная программа.')
        action = 'Тест выполнен. Для проверки реального файла выберите именно его; не используйте EICAR как доказательство полной защиты.'
    elif detections >= 2:
        risk, title = 'danger', 'Есть обнаружения вредоносности'
        answer = 'Обнаружена вредоносная активность по данным антивирусов'
        detail = f'VirusTotal: {detections} обнаружений вредоносности из {total} ответивших систем.'
        note = 'Несколько движков отметили этот файл как вредоносный. Возможны ложные срабатывания, но открывать файл опасно.'
        action = 'Не открывайте и не запускайте файл. Удалите его, если он получен из неизвестного источника, и проверьте устройство установленным антивирусом.'
    elif detections or suspicious or signals:
        risk, title = 'caution', 'Найдены подозрительные признаки'
        answer = 'Есть риск — открывать не рекомендуется'
        detail = ('Найдены признаки риска в структуре файла или срабатывания защитных систем. '
                  'Это ещё не доказывает наличие вируса.')
        note = (f'VirusTotal: {detections} вредоносных, {suspicious} подозрительных из {total} ответивших систем. '
                if status == 'checked' else 'Антивирусный отчёт отсутствует или ещё не готов. ')
        note += 'Опасный формат, маскировка или подозрительный код требуют дополнительной проверки.'
        action = 'Не запускайте файл и не включайте макросы. Уточните источник и проверьте файл локальным антивирусом.'
    elif status == 'pending':
        risk, title = 'unknown', 'Антивирусная проверка ещё идёт'
        answer = 'Проверка VirusTotal ещё идёт'
        detail = 'Файл принят на новый анализ. Результат появится после завершения проверки.'
        note = 'AntiScam уже проверил структуру. Пока нет отчёта антивирусных движков.'
        action = 'Не открывайте файл до получения результата. Нажмите «Узнать результат» примерно через минуту.'
    elif status == 'checked' and partial:
        risk, title = 'unknown', 'Часть содержимого не проверена'
        answer = 'Антивирусы не сообщили об угрозе, но проверка неполная'
        detail = f'Из {total} ответивших систем обнаружений нет; часть структуры файла недоступна для AntiScam.'
        note = 'Даже при нулевых обнаружениях скрытые или зашифрованные вложения могут оставаться непроверенными.'
        action = 'Не открывайте неожиданный файл. Уточните отправителя; проверьте вложения и файл на устройстве антивирусом.'
    elif status == 'checked':
        risk, title = 'low', 'Известных угроз не обнаружено'
        answer = 'По проверке VirusTotal угроз не обнаружено'
        detail = f'0 опасных и 0 подозрительных из {total} ответивших систем VirusTotal.'
        note = 'Это результат известных проверок, а не гарантия отсутствия новых вирусов или вредоносного поведения.'
        action = 'Если файл получен неожиданно, подтвердите отправителя. Не включайте макросы и не запускайте неизвестные программы.'
    else:
        risk, title = 'unknown', 'Нет антивирусного заключения'
        answer = 'Антивирусной проверки не было — безопасность не подтверждена'
        detail = 'Файл изучен статически, но готового антивирусного отчёта нет.'
        note = 'Отсутствие локальных признаков риска не подтверждает безопасность. Нужен отчёт антивируса.'
        action = ('Не открывайте неизвестный файл. Для более точной проверки запустите антивирус на устройстве '
                  'или явно разрешите новое сканирование VirusTotal, если оно доступно и файл не конфиденциальный.')
    return {
        'risk': risk, 'title': title, 'detail': detail,
        'quick_verdict': {'state': risk, 'label': 'Результат проверки файла', 'answer': answer, 'note': note},
        'recommendation': action,
    }
