# Архитектура AI SAST Agent

## Pipeline

```
Archive upload (multipart)
  → extract to tmpdir
  → scanner.ScanWithOptions()
       → ensureGoMod()              (создаёт go.mod если нет)
       → CodeQL (если доступен)     go/packages → codeql database create/analyze
       → go/packages + ast/inspector  (builtin rules + taint-lite)
       → gosec (если доступен)      external binary, stdout/stderr разделены
       → govulncheck (если доступен) external binary, stdout/stderr разделены
       → mergeFindings() → deduplicate
  → agent.Run()
       → TriageProvider.Triage() per finding  (parallel)
            → ollama / ollama-agentic / openai / openai-agentic / gigachat / ...
       → calibrateVerdict()        (только при успешном AI triage)
       → ApplyFeedback()
  → policy engine (ShouldFail)
  → Report { Findings, Stats, ScanMetrics, AgentDuration }
```

## Компоненты

| Пакет | Назначение |
|---|---|
| `internal/scanner` | Сбор Go-файлов, параллельный скан, rule engine, taint-lite, внешние сканеры |
| `internal/agent` | Оркестратор triage, интерфейс `TriageProvider`, провайдеры, калибровка |
| `internal/report` | Форматы вывода: text, JSON, SARIF, CI-бандл (+ MR-summary) |
| `internal/history` | Персистентность результатов на диске |
| `internal/jobs` | Менеджер фоновых задач для SSE-стриминга Web UI |
| `cmd/server` | HTTP-сервер: `/scan`, `/scan/stream`, `/history`, `/healthz`, `/provider/test` |

## Сканеры

Три уровня запускаются последовательно, результаты дедуплицируются:

### 1. CodeQL

Запускается если бинарь `codeql` доступен и файлов ≤ `SAST_CODEQL_MAX_FILES` (default 10 000).

- `codeql database create --language=go --threads=0 --ram=2048`
- `codeql database analyze codeql/go-queries:codeql-suites/go-code-scanning.qls`
- Результат: SARIF → `[]Finding`

### 2. Builtin (go/packages)

- `ensureGoMod`: если в папке нет `go.mod`, создаёт временный `module scan-target` и удаляет после скана
- `packages.Load` с `GOPROXY=off` — не скачивает зависимости; пакеты с ошибками обрабатываются частично
- `ast/inspector` обходит AST по типам узлов: `CallExpr`, `CompositeLit`, `ValueSpec`, `AssignStmt`
- `checkTaintLite` — taint per-function: источник (`os.Getenv`, `r.FormValue`, …) → sink (`exec.Command`, `http.Get`, `os.Open`)

Правила builtin:

| Правило | Что проверяет |
|---|---|
| `GO-HARDCODED-SECRET` | `const`/`var` с именем-секретом + значение ≥ 16 chars или PEM-блок; имена с суффиксами Controller/Handler/Manager и др. исключены |
| `GO-CMD-SHELL` | `exec.Command("sh"/"bash", "-c", …)` |
| `GO-CMD-INJECTION-TAINT` | taint: ввод пользователя → exec |
| `GO-SSRF-TAINT` | taint: ввод → `http.Get/Post` |
| `GO-PATH-TRAVERSAL-TAINT` | taint: ввод → `os.Open/ReadFile` |
| `GO-TLS-SKIP-VERIFY` | `InsecureSkipVerify: true` |
| `GO-CRYPTO-WEAK` | `crypto/md5`, `crypto/sha1` |
| `GO-RAND-INSECURE` | `math/rand` |
| `GO-HTTP-NO-TLS` | `http.ListenAndServe` |
| `GO-FILE-PERMISSIVE` | `os.Chmod` с `0777`/`0666` |
| `GO-DESERIALIZE-UNTRUSTED` | `gob.Decode`, `yaml.Unmarshal` |
| `GO-TEMPFILE-REVIEW` | `os.CreateTemp`, `ioutil.TempFile` |

### 3. gosec / govulncheck

Внешние бинарные инструменты, запускаются если присутствуют в `$PATH`.

- `gosec -fmt=json -no-fail ./...` — stdout (JSON) и stderr разделены, stderr игнорируется
- `govulncheck -json ./...` — аналогично; требует `go.mod`

## Провайдеры AI

| Провайдер | Тип | Описание |
|---|---|---|
| `ollama` | локальный | Одношаговый triage через Ollama `/api/generate` |
| `ollama-agentic` | локальный | Многошаговый: Analyst → Skeptic → Judge |
| `openai` | облачный | Одношаговый через OpenAI-совместимый API |
| `openai-agentic` | облачный | Многошаговый через OpenAI-совместимый API |
| `gigachat` | облачный | Одношаговый через GigaChat API |
| `gigachat-agentic` | облачный | Многошаговый через GigaChat API |
| `noop` | — | Без AI: все finding получают `needs_review` |

## Agentic triage (многошаговый)

```
Finding + snippet + CWE-контекст
  → Analyst prompt   → analysis (markdown)
  → Skeptic prompt   → critique (markdown)
  → Judge prompt     → JSON: {label, confidence, rationale, remediation}
```

Judge возвращает: `true_positive | false_positive | needs_review`.

## Калибровка вердиктов

`calibrateVerdict` вызывается **только при успешном AI triage** (`r.err == nil`).

- `false_positive` без признаков mitigation в сниппете + HIGH/CRITICAL → переводится в `true_positive`
- `needs_review` + HIGH/CRITICAL + сильный сигнал риска → `true_positive`
- При ошибке AI verdict остаётся `needs_review`, калибровка не применяется

## Безопасность

- В промпт передаются только данные finding + snippet; полный исходник не отправляется
- AI verdict хранится отдельно от scanner finding; finding не модифицируется
- `remediation` из AI не применяется автоматически — только отображается
- `feedback.json` позволяет переопределить вердикт вручную без перезапуска AI
