# AI SAST Agent

Go-проект: AI-агент для статического анализа безопасности (SAST) Go-кода с автоматическим triage через LLM.

## Как это работает

1. **Scanner** запускает три уровня анализа последовательно, результаты дедуплицируются:
   - **CodeQL** (если доступен) — межпроцедурный taint-анализ
   - **Builtin** — `go/packages + ast/inspector`, taint-lite, 20 декларативных правил (`rule.go`); если `go.mod` отсутствует, создаётся временный
   - **gosec / govulncheck** (если доступны в `$PATH`) — внешние Go security scanners
2. **Rule engine** формирует findings (severity, evidence, remediation).
3. **AI triage** присваивает каждому finding verdict: `true_positive | false_positive | needs_review`.
4. **Calibration** — при успешном AI triage дополнительно калибрует спорные вердикты для HIGH/CRITICAL.
5. **Policy engine** вычисляет итоговый security gate (`should_fail: true|false`).

Поддерживаемые провайдеры: `ollama`, `ollama-agentic` (Analyst → Skeptic → Judge), `openai`, `openai-agentic`, `gigachat`, `gigachat-agentic`, `noop`.

Подробнее об архитектуре: [docs/architecture.md](docs/architecture.md)

---

## Быстрый старт (локально)

```bash
cp .env.example .env          # настрой переменные
docker compose up -d          # запускает ollama + sast-agent-api + web UI
curl -s http://localhost:10000/healthz
```

Web UI доступен на `http://localhost:10001`.

Для сборки с CodeQL (глубокий анализ):
```bash
docker compose up -d
```

---

## API

### `GET /healthz`
```json
{"status": "ok"}
```

### `POST /scan`

Принимает multipart/form-data. Возвращает JSON.

```bash
# 1. Архивируй код
tar -czf source.tar.gz --exclude='.git' /path/to/project

# 2. Отправь на сервер
curl -sS -X POST http://localhost:10000/scan \
  -F "archive=@source.tar.gz" \
  -F "provider=ollama-agentic" \
  -F "ai_budget=10" \
  -F "fail_on_severity=HIGH" \
  -F "fail_on_verdict=true_positive" \
  -F "correlation_id=build-123" \
  | jq '{should_fail, stats: .report.stats}'
```

Параметры формы:

| Поле | Описание | По умолчанию |
|---|---|---|
| `archive` | Архив `.tar.gz` или `.zip` с исходным кодом | обязательный |
| `provider` | AI-провайдер | `SAST_AI_PROVIDER` из env |
| `ai_budget` | Макс. количество AI-triaged findings (0 = без лимита) | `SAST_AI_BUDGET` |
| `fail_on_severity` | Минимальный severity для провала (`LOW/MEDIUM/HIGH/CRITICAL`) | `SAST_FAIL_ON_SEVERITY` |
| `fail_on_verdict` | Вердикт для провала (`true_positive/needs_review/any`) | `SAST_FAIL_ON_VERDICT` |
| `openai_key` | API-ключ (для cloud-провайдеров) | `SAST_OPENAI_KEY` |
| `gigachat_key` | Authorization key для GigaChat | `SAST_GIGACHAT_KEY` *(fallback: `SAST_OPENAI_KEY`)* |
| `openai_model` | Модель | `SAST_OPENAI_MODEL` |
| `openai_url` | Base URL (для OpenAI-совместимых провайдеров) | `SAST_OPENAI_URL` |
| `gigachat_scope` | Scope GigaChat | `SAST_GIGACHAT_SCOPE` |

Ответ:
```json
{
  "should_fail": true,
  "correlation_id": "build-123",
  "report": {
    "findings": [
      {
        "finding": { "rule_id": "...", "title": "...", "severity": "HIGH", "file": "...", "line": 42, "evidence": "..." },
        "verdict": { "label": "true_positive", "confidence": 0.92, "rationale": "...", "remediation": "...", "provider": "ollama-agentic:qwen2.5:7b-instruct" },
        "snippet": "..."
      }
    ],
    "stats": { "total_findings": 5, "ai_triaged_findings": 5, "true_positive_count": 3, "needs_review_count": 1, "false_positive_count": 1 },
    "scan_metrics": { "files_scanned": 12, "files_discovered": 12 },
    "agent_duration": 14500000000
  }
}
```

Если `should_fail: true` — pipeline должен завершаться с ошибкой.

### `POST /scan/stream`

Те же параметры, что и `/scan`. Возвращает SSE-поток с событиями прогресса. Используется Web UI.

### `GET /history` / `GET /history/{id}`

История сканирований (требует `SAST_HISTORY_DIR`).

### `POST /provider/test`

Проверка подключения к AI-провайдеру.

---

## Интеграция в CI/CD

### Требования

1. Задеплоенный SAST-сервер (см. [docker-compose.yml](docker-compose.yml)).
2. Переменная `SAST_SERVER_URL` с адресом сервера.

### GitHub Actions

Готовый workflow с комментарием к PR: [examples/github-actions.yml](examples/github-actions.yml)

Что делает workflow:
1. Архивирует код.
2. Отправляет архив на SAST-сервер.
3. Постит/обновляет комментарий к PR с результатами (finding-таблица с AI-вердиктами).
4. Завершает pipeline с `exit 1` при срабатывании security gate.

Secrets для репозитория:
```
SAST_SERVER_URL = http://your-sast-server:10000
```

Пример комментария к PR:

```
## 🔒 AI SAST Report

| | |
|---|---|
| Статус | 🔴 FAIL |
| Файлов просканировано | 12 |
| Всего находок | 3 |
| AI triage | 3 |
| Реальные | 2 |
| На проверку | 1 |
| Ложные | 0 |

### Находки

🔴 HIGH · true_positive · Hardcoded Secret (main.go:42)
...
```

### GitLab CI

Готовый пример: [examples/gitlab-ci.yml](examples/gitlab-ci.yml)

CI/CD variables:
```
SAST_SERVER_URL  = http://your-sast-server:10000   (masked)
SAST_BOT_TOKEN   = <gitlab-token-with-api-scope>  (masked)
```

Для форматирования комментария используется скрипт [`scripts/format-mr-comment.sh`](scripts/format-mr-comment.sh) (требует `jq`).

---

## Конфигурация сервера

Через переменные окружения (пример: [.env.example](.env.example)):

| Переменная | По умолчанию | Описание |
|---|---|---|
| `SAST_AI_PROVIDER` | `ollama-agentic` | AI-провайдер |
| `SAST_OLLAMA_URL` | `http://127.0.0.1:11434` | Адрес Ollama |
| `SAST_OLLAMA_MODEL` | `qwen2.5:7b-instruct` | Модель Ollama |
| `SAST_OPENAI_KEY` | — | API-ключ для cloud-провайдеров |
| `SAST_GIGACHAT_KEY` | — | Authorization key для GigaChat (приоритетнее `SAST_OPENAI_KEY`) |
| `SAST_OPENAI_MODEL` | `gpt-4o-mini` | Модель OpenAI |
| `SAST_OPENAI_URL` | `https://api.openai.com/v1` | Base URL OpenAI-совместимого API |
| `SAST_AI_BUDGET` | `0` | Макс. находок для AI triage (0 = без лимита) |
| `SAST_AI_PARALLEL` | `1` | Параллельных triage-вызовов |
| `SAST_FAIL_ON_SEVERITY` | `MEDIUM` | Порог severity для `should_fail` |
| `SAST_FAIL_ON_VERDICT` | `true_positive` | Вердикт для `should_fail` |
| `SAST_SNIPPET_RADIUS` | `8` | Строк контекста вокруг finding |
| `SAST_HISTORY_DIR` | — | Директория для хранения истории |
| `SAST_WORKERS` | `NumCPU` | Worker-потоков для сканирования |
| `SAST_SERVER_ADDR` | `:8080` | Адрес HTTP-сервера |
| `SAST_API_PORT` | `10000` | Внешний host-port API |
| `SAST_UI_PORT` | `10001` | Внешний host-port Web UI |

---

## Prod-деплой

```bash
export SAST_TARGET_PATH=./scan-target
export SAST_API_PORT=10000
export SAST_UI_PORT=10001
docker compose up -d
```

`ollama-init` автоматически скачивает модель из `SAST_OLLAMA_MODEL` перед стартом API. Вручную выполнять `ollama pull` не нужно.

Для workflow [.github/workflows/deploy.yml](.github/workflows/deploy.yml) добавьте в GitHub:

Secrets:
```
DEPLOY_SSH_KEY = private SSH key для входа на сервер
DEPLOY_HOST    = IP или DNS сервера
DEPLOY_USER    = SSH-пользователь на сервере
```

Variables:
```
DEPLOY_PATH        = /opt/sast-agent              # optional
SAST_OLLAMA_MODEL  = qwen2.5:7b-instruct          # optional
SAST_AI_PROVIDER   = ollama-agentic               # optional
SAST_API_PORT      = 10000                         # optional
SAST_UI_PORT       = 10001                         # optional
```

Особенности prod-контура:
- CodeQL (Go/Python/C/C++) через `Dockerfile`
- `read_only: true` для API-контейнера + tmpfs
- CPU/RAM limits для ollama и API

macOS: путь в `SAST_TARGET_PATH` должен быть в Docker Desktop File Sharing.

---

## Проверка

```bash
go test ./...
docker compose config --quiet
```
