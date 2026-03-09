# Отчёт по тестированию Orchesis

Дата: 2026-03-09 22:15:24 MSK  
Версия: `98c2fa1 fix(ci): YAML syntax in fuzz workflow + fix backoff test timing`  
OS: macOS 26.3 (25D125)  
Python: 3.12.6

## Установка
Существенных проблем при установке не было. Рабочее окружение: `.venv`, запуск через локальный source (`src/orchesis`).

## Баги

### Баг #1: `proxy.port` из `orchesis.yaml` игнорировался
- **Шаг ТЗ:** Базовый запуск proxy / конфигурирование порта
- **Серьёзность:** 🟡 Важно
- **Что делал:** `orchesis proxy` при `orchesis.yaml` с `proxy.port: 8080`
- **Ожидалось:** proxy слушает порт из policy (`8080`)
- **Фактически:** запускался на дефолтном `8100`
- **Скриншот/лог:** `Listening: http://127.0.0.1:8100`
- **Фикс (если делал):** исправлено в `src/orchesis/cli.py` (чтение `proxy.*` из policy + приоритет CLI-флагов); коммит не делался

### Баг #2: Dashboard JS падал + `favicon.ico` 404
- **Шаг ТЗ:** Dashboard доступность и корректный рендер
- **Серьёзность:** 🟡 Важно
- **Что делал:** открытие `/dashboard`
- **Ожидалось:** корректная отрисовка вкладок без ошибок в консоли
- **Фактически:** `Identifier 'ratio' has already been declared`, `GET /favicon.ico 404`
- **Скриншот/лог:** ошибки в DevTools
- **Фикс (если делал):** исправлено в `src/orchesis/dashboard.py` (переименование переменной), `src/orchesis/proxy.py` и `src/orchesis/api.py` (обработка `/favicon.ico`), добавлен no-cache для `/dashboard`; коммит не делался

### Баг #3: Cache Hit Rate показывал `0.0%` при реальных cache-hit
- **Шаг ТЗ:** Cache tab / observability cache
- **Серьёзность:** 🟡 Важно
- **Что делал:** запуск live cache-теста и проверка Dashboard Cache
- **Ожидалось:** hit rate отражает фактические cache-hit
- **Фактически:** `X-Orchesis-Cache: hit`, но в табе `0.0%`
- **Скриншот/лог:** `/stats`: `cache_hit_rate_percent > 0`, `semantic_cache.hit_rate_percent = 0`
- **Фикс (если делал):** дашборд обновлён: Cache Hit Rate учитывает cascade cache, добавлены cascade-метрики в Cache tab, затем упрощён вид `Entries`; коммит не делался

### Баг #4: Loop warning не попадал в Shield Events
- **Шаг ТЗ:** Loop detection observability
- **Серьёзность:** 🟡 Важно
- **Что делал:** `python tests_live/test_05_loops.py` при `action: warn`
- **Ожидалось:** предупреждения видны в `Shield -> Events`
- **Фактически:** событий не было
- **Скриншот/лог:** при warn только header, без dashboard event
- **Фикс (если делал):** добавлены `loop_warning`/`loop_detected` events в `src/orchesis/proxy.py`, плюс фикc: loop detection выполняется даже при cascade cache-hit; коммит не делался

### Баг #5: `tests_live/test_06_flow.py` нестабилен (400/TypeError)
- **Шаг ТЗ:** Flow X-Ray live test
- **Серьёзность:** 🟢 Мелочь (тестовый скрипт)
- **Что делал:** `python tests_live/test_06_flow.py`
- **Ожидалось:** стабильный сценарий 2-х ходов с tool-calls
- **Фактически:**
  - 400 `tool_call_id` mismatch на 2-м ходе
  - `TypeError` при `message.content is None`
- **Скриншот/лог:** traceback из консоли
- **Фикс (если делал):** стабилизирован скрипт: корректная сборка сообщений, безопасный вывод ответа, отдельный `X-Session-Id` на каждый прогон; коммит не делался

## Что НЕ работает вообще
Критически неработающих частей не обнаружено. Были проблемы с корректностью отображения и сценарными edge-cases, все воспроизводимые кейсы выше локально исправлены в рабочем дереве.
