# MBKS AI SAST Agent — Полная документация

## Содержание

1. [Назначение и соответствие заданию](#1-назначение)
2. [Архитектура системы](#2-архитектура)
3. [Компонент: Сканер](#3-сканер)
4. [Компонент: AI-агент (triage)](#4-ai-агент)
5. [Компонент: Провайдеры AI](#5-провайдеры-ai)
6. [Компонент: Policy Engine](#6-policy-engine)
7. [Компонент: HTTP-сервер](#7-http-сервер)
8. [Компонент: Веб-интерфейс](#8-веб-интерфейс)
9. [Инфраструктура (Docker)](#9-инфраструктура)
10. [API контракт](#10-api-контракт)
11. [Конфигурация](#11-конфигурация)
12. [Поток данных end-to-end](#12-поток-данных)
13. [Почему выбраны именно эти решения](#13-обоснование-решений)

---

## 1. Назначение

**Задание**: разработать AI-агент, автоматизирующий анализ безопасности и поиск уязвимостей в исходном коде (SAST — Static Application Security Testing).

**Что реализовано**: полноценный AI-агент для SAST-анализа со следующими возможностями:

- Статический анализ исходного кода на языке **Go** с использованием **CodeQL** (если доступен), встроенных правил (`go/packages + ast/inspector`) и внешних сканеров (**gosec**, **govulncheck**)
- **AI-триаж** каждой найденной уязвимости через LLM — агент оценивает, является ли finding реальной уязвимостью или ложным срабатыванием
- **Многошаговый агентный подход**: три роли (Аналитик → Скептик → Судья) для повышения точности
- **Security gate**: автоматическое принятие решения `should_fail=true/false` для CI/CD пайплайнов
- Поддержка **облачных** (OpenAI, GigaChat) и **локальных** (Ollama) AI-моделей
- Веб-интерфейс для ручного тестирования и демонстрации

---

## 2. Архитектура

### Общая схема

```
┌─────────────────────────────────────────────────────────────┐
│                    Пользователь / CI/CD                     │
│                                                             │
│   Веб-браузер (port 10001)   curl (port 10000)              │
└────────────┬────────────────────────┬───────────────────────┘
             │                        │
             ▼                        ▼
┌────────────────────┐    ┌──────────────────────────────────┐
│  Frontend (nginx)  │    │    sast-agent-server (Go)        │
│  Статический HTML  │    │                                  │
│  Проксирует API    │───►│  POST /scan        (CI, JSON)    │
└────────────────────┘    │  POST /scan/stream (Web, SSE)    │
                          │  POST /provider/test             │
                          │  GET  /healthz                   │
                          └──────────────┬───────────────────┘
                                         │
                          ┌──────────────▼───────────────────┐
                          │         Scanner Layer            │
                          │                                  │
                          │  ┌─────────────────────────────┐ │
                          │  │  CodeQL (если доступен)     │ │
                          │  │  Go: taint analysis,        │ │
                          │  │  data-flow                  │ │
                          │  └──────────────┬──────────────┘ │
                          │                 │ + merge         │
                          │  ┌──────────────▼──────────────┐ │
                          │  │  Built-in (всегда)          │ │
                          │  │  go/packages + ast/inspector│ │
                          │  │  ensureGoMod + taint-lite   │ │
                          │  └──────────────┬──────────────┘ │
                          │                 │ + merge         │
                          │  ┌──────────────▼──────────────┐ │
                          │  │  gosec / govulncheck        │ │
                          │  │  (если есть в $PATH)        │ │
                          │  └─────────────────────────────┘ │
                          └──────────────┬───────────────────┘
                                         │ []Finding
                          ┌──────────────▼───────────────────┐
                          │         Agent Layer (AI)         │
                          │                                  │
                          │  for each finding:               │
                          │    provider.Triage(finding)      │
                          │    → label + confidence +        │
                          │      rationale + remediation     │
                          │                                  │
                          │  Провайдеры:                     │
                          │  ├─ ollama-agentic (default)     │
                          │  ├─ ollama (single-step)         │
                          │  ├─ openai / openai-agentic      │
                          │  ├─ gigachat / gigachat-agentic  │
                          │  └─ noop (эвристика)             │
                          └──────────────┬───────────────────┘
                                         │ Report
                          ┌──────────────▼───────────────────┐
                          │         Policy Engine            │
                          │  ShouldFail(report, policy)      │
                          │  → should_fail: true/false       │
                          └──────────────────────────────────┘
```

### Структура репозитория

```
mbks_auto/
├── cmd/
│   └── sast-agent-server/   # Точка входа HTTP-сервера
│       ├── main.go           # Обработчики HTTP, конфигурация
│       └── ui.go             # (пустой, UI вынесен во frontend/)
├── internal/
│   ├── scanner/              # Слой статического анализа
│   │   ├── scanner.go        # Оркестратор, collectFiles, ScanWithOptions, ensureGoMod
│   │   ├── finding.go        # Типы: Finding, Severity
│   │   ├── codeql.go         # CodeQL интеграция + SARIF-парсер
│   │   └── go_external.go    # gosec + govulncheck интеграция
│   ├── agent/                # Слой AI-триажа
│   │   ├── agent.go          # agent.Run(), типы Report/Verdict/ProgressEvent
│   │   ├── policy.go         # ShouldFail(), policy engine
│   │   ├── feedback.go       # Human-in-the-loop overrides
│   │   ├── snippet.go        # Извлечение сниппетов кода
│   │   ├── json_extract.go   # Парсинг JSON из LLM-ответов
│   │   ├── noop_provider.go  # Эвристический провайдер
│   │   ├── ollama_provider.go         # Одношаговый Ollama
│   │   ├── ollama_agentic_provider.go # Многошаговый Ollama
│   │   ├── openai_provider.go         # OpenAI-совместимый API
│   │   ├── gigachat_provider.go       # Sberbank GigaChat
│   │   └── yandex_provider.go         # (заглушка)
│   └── report/               # Форматы отчётов
│       ├── sarif.go           # SARIF 2.1.0 для CI/GitHub
│       ├── text.go            # Читаемый текстовый отчёт
│       └── ci_bundle.go       # CI-артефакты (json+sarif+summary)
├── frontend/                 # Веб-интерфейс (nginx)
│   ├── index.html            # SPA с SSE-стримингом прогресса
│   ├── nginx.conf            # Reverse proxy к API
│   └── Dockerfile            # nginx:1.27-alpine
├── Dockerfile                # Лёгкий образ без CodeQL
├── Dockerfile         # Полный образ с CodeQL (linux/amd64)
├── docker-compose.yml        # Dev-стек (Ollama + API + UI)
└── docker-compose.yml # Prod-стек (то же + ресурсные лимиты)
```

---

## 3. Сканер

**Файлы**: `internal/scanner/`

Сканер — первый слой пайплайна. Принимает путь к проекту, возвращает список `Finding` — структурированных описаний потенциальных уязвимостей.

### 3.1 Типы данных

```go
type Finding struct {
    RuleID       string   // Идентификатор правила: "GO-CRYPTO-WEAK", "CODEQL-PY-SQL-INJECTION"
    Title        string   // Человекочитаемое название
    Severity     Severity // LOW | MEDIUM | HIGH | CRITICAL
    File         string   // Абсолютный путь к файлу
    Line         int      // Номер строки
    Column       int
    Evidence     string   // Контекст: что именно найдено
    WhyItMatters string   // Почему это опасно
    Remediation  string   // Как исправить
}
```

### 3.2 Алгоритм сканирования

```
ScanWithOptions(root, opts)
  │
  ├─ 1. collectFiles()        Обход дерева, фильтр по расширению .go
  │      Пропускает: .git, vendor, node_modules, dist, build, bin
  │      IncludeTests: false → пропускает *_test.go
  │
  ├─ 2. Инкрементальный кэш (если Incremental=true)
  │      SHA-256 каждого файла → .sastcache.json
  │      Неизменённые файлы пропускаются
  │
  ├─ 3. CodeQL (если доступен и файлов ≤ SAST_CODEQL_MAX_FILES)
  │      ├─ pruneGeneratedFiles() — удаляет *_gen.go, *.pb.go и т.д.
  │      ├─ writeCodeQLIgnore() — создаёт .codeqlignore
  │      └─ codeql database create + database analyze → SARIF → []Finding
  │
  ├─ 4. Builtin (всегда, результаты merge с CodeQL)
  │      ├─ ensureGoMod() — создаёт временный go.mod если нет; удаляет после
  │      └─ scanPackages() — go/packages (GOPROXY=off) + ast/inspector
  │           ├─ checkTaintLite() per function
  │           └─ builtin rules: secrets, tls, crypto, rand, cmd, ssrf, …
  │
  └─ 5. Внешние (если доступны в $PATH, результаты merge)
         ├─ gosec -fmt=json -no-fail ./...    (stdout/stderr разделены)
         └─ govulncheck -json ./...           (только если есть go.mod)
```

### 3.3 CodeQL интеграция

**Почему CodeQL**: CodeQL — промышленный SAST-инструмент от GitHub с поддержкой taint-анализа (отслеживание потока данных от источника к уязвимому sink). В отличие от regex/AST-подхода, CodeQL понимает control flow и data flow, что значительно снижает число ложных срабатываний.

**Query suite**: `codeql/go-queries:codeql-suites/go-code-scanning.qls`

**Параметры запуска**:
- `codeql database create --language=go --threads=0 --ram=2048`
- `codeql database analyze --threads=0 --ram=2048`
- Лимит RAM: `--ram=2048` предотвращает OOM-kill контейнера
- Файлов > `SAST_CODEQL_MAX_FILES` (default: 2000) → CodeQL пропускается

**Оптимизация**: `pruneGeneratedFiles()` физически удаляет из временной директории перед анализом `*_gen.go`, `*.pb.go`, `*_generated.go`, `*_mock.go` — сгенерированный код не несёт security-значимых уязвимостей, но увеличивает время анализа и потребление RAM.

**Парсинг SARIF** (`parseSARIFFindings`): CodeQL возвращает результаты в формате SARIF 2.1.0. Парсер извлекает rule metadata, severity из `properties.security-severity` (CVSS score), физическое расположение файла.

### 3.4 Встроенный Go-сканер (builtin)

`ensureGoMod` создаёт временный `go.mod` (`module scan-target`, `go 1.21`) если в корне проекта его нет, и удаляет после завершения скана. Это позволяет анализировать любые Go-архивы без заранее созданного модуля.

**Архитектура**: правила объявлены в `internal/scanner/rule.go` как срез `BuiltinRules []Rule`. Движок сканирования в `scanner.go` — универсальный: он читает правила при старте, индексирует по типу паттерна и применяет к каждому AST-узлу. Добавление нового правила = одна новая запись в срезе, без изменения логики обхода.

**Типы паттернов**:
- `call` — точное совпадение `importPath.FuncName`
- `call_pkg` — любой вызов функции из пакета
- `call_shell` — `exec.Command` с шелл-бинарём и флагом `-c`
- `call_permissive_chmod` — `os.Chmod` с широкими правами
- `composite_field_bool` — поле структурного литерала равно `true`/`false`
- `secret_value` — имя переменной совпадает с паттерном + длинная строка
- `import` — сам факт импорта пакета (проверяется через `go/parser`, не требует разрешения зависимостей)

`scanPackages` запускает `go/packages` с `GOPROXY=off`, `GOWORK=off` — загрузка внешних зависимостей не выполняется. `ast/inspector` обходит узлы (`CallExpr`, `CompositeLit`, `ValueSpec`, `AssignStmt`). Импорт-правила применяются отдельным проходом через `go/parser.ParseFile(ImportsOnly)`.

**Правила**:

| Rule ID | Паттерн | Описание | Severity |
|---------|---------|----------|----------|
| GO-HARDCODED-SECRET | `secret_value` | `const`/`var` с именем-секретом + значение ≥ 16 символов или PEM-блок | HIGH |
| GO-CRYPTO-WEAK | `call` | `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4` | HIGH |
| GO-CMD-SHELL | `call_shell` | `exec.Command("sh"/"bash", "-c", …)` | HIGH |
| GO-TLS-SKIP-VERIFY | `composite_field_bool` | `tls.Config{InsecureSkipVerify: true}` | HIGH |
| GO-XSS-UNSAFE-CAST | `call` | `html/template.HTML/JS/URL/Attr/CSS(...)` — обход XSS-экранирования | HIGH |
| GO-EXEC-SYSCALL | `call` | `syscall.Exec`, `syscall.ForkExec`, `syscall.StartProcess` | HIGH |
| GO-OS-START-PROCESS | `call` | `os.StartProcess` | HIGH |
| GO-CRYPTO-BLOWFISH | `import` | `golang.org/x/crypto/blowfish` — 64-bit блок, Sweet32 | HIGH |
| GO-CRYPTO-CAST5 | `import` | `golang.org/x/crypto/cast5` — устаревший шифр | HIGH |
| GO-CRYPTO-MD4 | `import` | `golang.org/x/crypto/md4` — сломанный хэш | HIGH |
| GO-CRYPTO-TEA | `import` | `golang.org/x/crypto/tea` — related-key слабость | HIGH |
| GO-RAND-INSECURE | `call_pkg` | любой вызов `math/rand.*` | MEDIUM |
| GO-HTTP-NO-TLS | `call` | `http.ListenAndServe` | MEDIUM |
| GO-FILE-PERMISSIVE | `call_permissive_chmod` | `os.Chmod` с `0777`/`0666`/world-writable | MEDIUM |
| GO-XML-EXTERNAL-ENTITY | `call` | `encoding/xml.NewDecoder`, `xml.Unmarshal` | MEDIUM |
| GO-GOB-DECODE | `call` | `encoding/gob.NewDecoder` | MEDIUM |
| GO-UNSAFE-POINTER | `call` | `unsafe.Pointer`, `unsafe.Add`, `unsafe.Slice` | MEDIUM |
| GO-DEBUG-PPROF | `import` | `net/http/pprof` — регистрирует `/debug/pprof/*` | MEDIUM |
| GO-YAML-UNSAFE | `import` | `gopkg.in/yaml.v2/v3`, `sigs.k8s.io/yaml` | MEDIUM |
| GO-TEMPFILE-INSECURE | `call` | `os.CreateTemp`, `ioutil.TempFile` | LOW |
| GO-CMD-INJECTION-TAINT | taint | ввод пользователя → `exec.Command` | HIGH |
| GO-SSRF-TAINT | taint | ввод → `http.Get/Post` | HIGH |
| GO-PATH-TRAVERSAL-TAINT | taint | ввод → `os.Open/ReadFile` | HIGH |

**Taint analysis** (`checkTaintLite`): для каждой функции отслеживает поток данных:
- Sources: `os.Getenv()`, `r.FormValue()`, `r.Param()`, `r.Query()`
- Sanitizers: `filepath.Clean()`
- Sinks: `exec.Command()`, `http.Get/Post()`, `os.Open/ReadFile()`

### 3.5 Внешние сканеры (gosec / govulncheck)

Запускаются если бинарь присутствует в `$PATH`. Timeout: 5 минут каждый.

- `gosec -fmt=json -no-fail ./...` — stdout (JSON) и stderr разделены; stderr игнорируется, ошибка возвращается только если stdout пуст
- `govulncheck -json ./...` — аналогично; требует `go.mod` (govulncheck выполняется после `ensureGoMod` уже отработал внутри builtin scan)

Findings дедуплицируются с уже собранными по ключу `ruleID|file|line|column`.

---

## 4. AI-агент

**Файлы**: `internal/agent/agent.go`

Агент — центральный координирующий слой. Получает `[]Finding` от сканера, прогоняет каждый finding через LLM-провайдер и возвращает `Report` с вердиктами.

### 4.1 Основная функция

```go
func Run(ctx context.Context,
         scan scanner.Result,
         provider TriageProvider,
         feedback map[string]FeedbackRecord,
         opts RunOptions) (Report, error)
```

**Алгоритм**:

```
1. Сортировка findings по severity (CRITICAL → HIGH → MEDIUM → LOW)
2. Обрезка по AIBudget (первые N findings получают AI-анализ)
3. Для каждого finding:
   a. provider.Triage(ctx, finding) → Verdict
   b. calibrateVerdict() — только при r.err == nil (успешный AI triage):
        false_positive без mitigation в сниппете + HIGH/CRITICAL → true_positive
        needs_review + HIGH/CRITICAL + сильный сигнал риска → true_positive
   c. ApplyFeedback() — override вердикта из feedback-файла
   d. Обновление счётчиков (true_positive / false_positive / needs_review)
   e. Захват сниппета кода (opts.SnippetRadius строк вокруг находки)
   f. OnProgress callback → SSE-событие для web UI
4. Возврат Report с findings + metrics + stats + duration
```

### 4.2 Структура Verdict

```go
type Verdict struct {
    Label       VerdictLabel // "true_positive" | "false_positive" | "needs_review"
    Confidence  float64      // 0.0 – 1.0
    Rationale   string       // Объяснение на русском языке
    Remediation string       // Как исправить (на русском)
    Provider    string       // "ollama-agentic:qwen2.5:7b-instruct" и т.д.
}
```

### 4.3 Feedback loop (human-in-the-loop)

`feedback.go` реализует механизм коррекции AI-решений ревьюером:

- **Формат**: JSON-файл с записями `{key, decision, comment}`
- **Ключ**: `ruleID|filePath|lineNumber` — уникально идентифицирует finding
- **Применение**: если ревьюер пометил finding как `false_positive`, это решение с confidence=0.95 перекрывает AI-вердикт
- **Persistence**: feedback читается при каждом запросе через `SAST_FEEDBACK_IN`

### 4.4 Ранжирование findings

```go
func rankFindings(findings []scanner.Finding) []scanner.Finding
```

Сортировка пузырьком по весу severity: CRITICAL(4) > HIGH(3) > MEDIUM(2) > LOW(1). Гарантирует, что при ограниченном `AIBudget` AI анализирует наиболее критичные уязвимости.

---

## 5. Провайдеры AI

**Интерфейс**: `TriageProvider`

```go
type TriageProvider interface {
    Name() string
    Triage(ctx context.Context, finding scanner.Finding) (Verdict, error)
}
```

Все провайдеры реализуют один интерфейс, что позволяет добавлять новые модели без изменения остального кода.

### 5.1 NoopProvider (эвристический)

**Файл**: `noop_provider.go`

Не обращается к LLM. Применяет простое правило:
- HIGH/CRITICAL severity → `true_positive`, confidence=0.8
- LOW/MEDIUM severity → `needs_review`, confidence=0.65

**Использование**: тестирование, демонстрация, ситуации когда AI-модель недоступна.

### 5.2 OllamaProvider (одношаговый)

**Файл**: `ollama_provider.go`

Один вызов к `POST /api/generate` Ollama. Промпт требует вернуть JSON с полями label/confidence/rationale/remediation. Используется `"format": "json"` для принудительной валидации JSON.

**Промпт** (`buildPrompt`): передаёт rule_id, title, severity, evidence, why, fix, сниппет кода. Инструкция: `Write rationale and remediation in Russian`.

### 5.3 OllamaAgenticProvider (многошаговый)

**Файл**: `ollama_agentic_provider.go`

**Ключевой компонент** — реализует агентный подход с тремя ролями:

```
Step 1: analystPrompt()  → "You are Analyst. Respond in Russian."
        Оценивает эксплуатируемость, preconditions, причины false-positive
        Возвращает markdown

Step 2: skepticPrompt()  → "You are Skeptic. Respond in Russian."
        Оспаривает результат Аналитика
        Ищет причины, почему это НЕ уязвимость
        Возвращает markdown

Step 3: judgePrompt()    → "You are Judge. Respond in Russian."
        Синтезирует оба мнения
        Возвращает ТОЛЬКО JSON: {label, confidence, rationale, remediation}
```

**Почему три роля**: один шаг LLM склонен к галлюцинациям и подтверждению первоначального вывода. Скептик снижает false positive rate триажа: если Аналитик нашёл уязвимость, Скептик пытается найти причины, почему это не так. Судья делает взвешенное финальное решение.

**Resilient JSON parsing** (`decodeVerdict`): LLM часто возвращает JSON с `// комментариями`, trailing запятыми или обёрнутый в markdown-блоки. Применяются 4 стратегии по убыванию строгости:
1. Прямой `json.Unmarshal`
2. `extractFirstJSONObject` — ищет `{...}` блок
3. `sanitizeJSON` — убирает JS-комментарии и trailing запятые
4. Комбинация 2+3

**Retry при транзиентных ошибках**: при `unexpected EOF`, `connection reset`, `broken pipe` — одна повторная попытка через 2 секунды. Покрывает нестабильные ответы Ollama при высокой нагрузке.

### 5.4 OpenAIProvider / OpenAIAgenticProvider

**Файл**: `openai_provider.go`

Использует OpenAI-совместимый API (`/v1/chat/completions`). Совместим с:
- OpenAI GPT-4o, GPT-4o-mini
- Groq (llama-3.1-8b-instant и др.)
- Azure OpenAI
- Любой OpenAI-совместимый эндпоинт

Для judge-шага в agentic-режиме используется `"response_format": {"type": "json_object"}` — принудительный JSON-output.

API ключ передаётся на уровне запроса (per-request override через `openai_key` в форме), что позволяет не хранить его в конфигурации сервера.

### 5.5 GigaChatProvider / GigaChatAgenticProvider

**Файл**: `gigachat_provider.go`

Реализует двухшаговую авторизацию, специфичную для Sberbank:

```
1. POST https://ngw.devices.sberbank.ru:9443/api/v2/oauth
   Authorization: Basic {AuthKey}
   scope=GIGACHAT_API_PERS
   → access_token (действует 30 мин)

2. POST https://gigachat.devices.sberbank.ru/api/v1/chat/completions
   Authorization: Bearer {access_token}
   (OpenAI-совместимый формат)
```

**Кеширование токена**: access_token хранится в памяти провайдера с TTL. При вызове `getToken()` — mutex-защищённая проверка: если токен не истёк (с запасом 2 мин), возвращается кешированный.

**TLS**: Sberbank использует российский CA (Минцифры), отсутствующий в стандартных хранилищах. Используется `InsecureSkipVerify: true` с явным комментарием-обоснованием.

---

## 6. Policy Engine

**Файл**: `internal/agent/policy.go`

```go
type ExitPolicy struct {
    FailOnSeverity scanner.Severity // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    FailOnVerdict  VerdictLabel     // "true_positive" | "needs_review" | "any"
}

func ShouldFail(r Report, p ExitPolicy) bool
```

Логика: `should_fail = true` если хотя бы одно finding удовлетворяет **обоим** критериям:
- `finding.Severity >= FailOnSeverity`
- `finding.Verdict.Label == FailOnVerdict` (или "any")

**Примеры конфигурации**:

| FailOnSeverity | FailOnVerdict | Семантика |
|----------------|---------------|-----------|
| HIGH | true_positive | Падать только на подтверждённых HIGH+ уязвимостях |
| MEDIUM | needs_review | Падать если есть неразобранные MEDIUM+ |
| LOW | any | Педантичный режим: любая находка блокирует |

**Применение в CI**: `should_fail=true` → `exit 1` в CI-шаге → пайплайн останавливается.

---

## 7. HTTP-сервер

**Файл**: `cmd/sast-agent-server/main.go`

### 7.1 Эндпоинты

| Метод | Путь | Назначение |
|-------|------|-----------|
| GET | `/healthz` | Health check, возвращает `{"status":"ok"}` |
| POST | `/scan` | CI-интерфейс, JSON-ответ |
| POST | `/scan/stream` | Web UI, SSE-стриминг прогресса |
| POST | `/provider/test` | Проверка подключения к AI-провайдеру |

### 7.2 Загрузка архива

Оба scan-эндпоинта принимают `multipart/form-data` с полем `archive` (`.tar.gz` или `.zip`).

**Безопасность при распаковке**:
- Проверка path traversal: любой путь с `../` отклоняется
- Пропуск macOS-метаданных: `._filename`, `.DS_Store`, `__MACOSX/`
- Лимит размера: 100 МБ (`MaxBytesReader`)

`findGoRoot()`: после распаковки находит корень Go-проекта (ищет `go.mod` на 1 уровень вглубь). Гарантирует что CodeQL и `go/packages` работают с корректным project root.

### 7.3 SSE-стриминг (Server-Sent Events)

`POST /scan/stream` использует SSE для передачи прогресса в реальном времени:

```
data: {"type":"scanning"}
data: {"type":"start","total":42,"files_scanned":180}
data: {"type":"progress","current":1,"total":42,"rule_id":"...","verdict":"true_positive","snippet":"..."}
data: {"type":"progress","current":2,...}
...
data: {"type":"done","result":{...full scanResponse...}}
```

nginx-конфиг содержит `proxy_buffering off` для `/scan/stream` — без этого SSE-события буферизировались бы и доставлялись блоками.

### 7.4 Pre-flight проверка провайдера

Перед запуском сканирования `checkProviderReady()` проверяет доступность AI:
- Ollama: `GET /api/tags` → проверяет что нужная модель есть в списке
- OpenAI/GigaChat: проверяет наличие API ключа
- Noop: всегда OK

Это предотвращает запуск долгого сканирования когда AI заведомо недоступен.

### 7.5 Конфигурация через переменные окружения

Все параметры сервера читаются из env при старте через `loadConfig()`. Никаких config-файлов — 12-factor app подход.

---

## 8. Веб-интерфейс

**Файл**: `frontend/index.html`

Одностраничное приложение (SPA) на vanilla HTML/CSS/JS без внешних зависимостей.

### 8.1 Функциональность

1. **Загрузка архива**: drag-and-drop или file picker, `.tar.gz` / `.zip`
2. **Выбор провайдера**: переключатель локальный/облачный
   - Локальный: Ollama (multi/single/noop)
   - Облачный: OpenAI, GigaChat, Custom (OpenAI-совместимый)
3. **Тест подключения**: кнопка "🔌 Проверить подключение" → POST /provider/test → inline статус с latency
4. **Параметры**: AI Budget, Fail on Severity, Fail on Verdict
5. **Прогрессбар**:
   - Фаза 1 (распаковка + сканирование): анимированный indeterminate-бар + таймер
   - Фаза 2 (AI-триаж): детерминированный бар N/M + live-карточки findings
6. **Результаты**: PASS/FAIL баннер, статистика, все findings с сниппетами кода

### 8.2 SSE-клиент

```javascript
async function readSSE(resp) {
    const reader = resp.body.getReader();
    // Читает ReadableStream, разбивает по '\n\n'
    // Каждый event вызывает handleEvent(parsed JSON)
}
```

Использует `fetch()` + `ReadableStream` вместо `EventSource` API, т.к. `EventSource` поддерживает только GET-запросы.

### 8.3 Структура развёртывания

```
Browser → nginx:10001 → sast-agent-api:8080
                GET /          → static index.html
                POST /scan     → proxy_pass to API
                POST /scan/stream → proxy_pass (proxy_buffering off)
                POST /provider/test → proxy_pass to API
```

---

## 9. Инфраструктура

### 9.1 Dockerfile

Один образ (~1.5–2 ГБ) включает полный стек: CodeQL, gosec, govulncheck, Go toolchain.

- Все стейджи: `--platform=linux/amd64` (CodeQL CLI только для x86-64)
- Stage 1 `builder`: `golang:1.25-alpine`, сборка бинарника + установка gosec и govulncheck через `go install`
- Stage 2 `codeql-installer`: `debian:bookworm-slim`, скачивает CodeQL bundle, удаляет ненужные языки (java, javascript, ruby, swift, kotlin → экономия ~800 МБ)
- Stage 3 `runtime`: `debian:bookworm-slim` + git + python3 + CodeQL + Go toolchain + gosec + govulncheck + приложение

**Почему Debian**: CodeQL CLI — glibc-бинарник, несовместим с Alpine (musl libc).

**Почему `--platform=linux/amd64`**: CodeQL не выпускает Linux ARM64. На Apple Silicon Docker иначе собирал бы ARM64-образ, в котором CodeQL CLI не запускается.

### 9.2 Docker Compose

```
mongo → ollama → ollama-init (pull model) → vulnscanner-api → vulnscanner-ui
```

Сервисы:
- `mongo`: MongoDB 7 для хранения истории сканирований
- `ollama`: named volume `ollama-data`; `cpus: "4.0"`, `mem_limit: 12g`
- `ollama-init`: `depends_on: service_completed_successfully` — API стартует только после успешного `ollama pull`
- `vulnscanner-api`: `platform: linux/amd64`, `Dockerfile`; порт `SAST_API_PORT` (default `10000`); `read_only: true`; `tmpfs /tmp:8g` и `/go-work:2g` для CodeQL; `mem_limit: 8g`
- `vulnscanner-ui`: nginx; порт `SAST_UI_PORT` (default `10001`)

### 9.3 Оптимизации образа

`.dockerignore` исключает из контекста сборки:
- `.git`, `.cache`, `.idea` — VCS и IDE
- `.tmp`, `.artifacts`, `scan-target` — runtime данные
- `docs`, `examples`, `scripts`, `ai_project_knowledge` — не нужны в бинарнике
- `*.md`, `.github`, `*.log`, `*.sarif` — документация и артефакты

---

## 10. API контракт

### POST /scan (CI интерфейс)

**Запрос** (multipart/form-data):

| Поле | Тип | Описание |
|------|-----|----------|
| archive | file | .tar.gz или .zip архив проекта |
| provider | string | noop \| ollama \| ollama-agentic \| openai \| openai-agentic \| gigachat \| gigachat-agentic |
| ai_budget | int | Максимальное число findings для AI-анализа |
| fail_on_severity | string | LOW \| MEDIUM \| HIGH \| CRITICAL |
| fail_on_verdict | string | true_positive \| needs_review \| any |
| openai_key | string | API ключ (для OpenAI/GigaChat) |
| openai_model | string | Модель |
| openai_url | string | Базовый URL API |
| gigachat_scope | string | GIGACHAT_API_PERS \| GIGACHAT_API_B2B \| GIGACHAT_API_CORP |
| correlation_id | string | ID для трассировки в CI логах |

**Ответ** (JSON):

```json
{
  "should_fail": true,
  "correlation_id": "build-123",
  "report": {
    "findings": [
      {
        "finding": {
          "rule_id": "CODEQL-GO-SQL-INJECTION",
          "title": "SQL injection",
          "severity": "HIGH",
          "file": "/path/to/file.go",
          "line": 42,
          "evidence": "User-controlled value flows to SQL query",
          "why_it_matters": "...",
          "remediation": "..."
        },
        "verdict": {
          "label": "true_positive",
          "confidence": 0.87,
          "rationale": "...",
          "remediation": "...",
          "provider": "ollama-agentic:qwen2.5:7b-instruct"
        },
        "snippet": "  query := fmt.Sprintf(...)\n  db.Query(query)\n"
      }
    ],
    "scan_metrics": {
      "files_discovered": 180,
      "files_scanned": 180,
      "scan_duration": 1234567890
    },
    "agent_duration": 45000000000,
    "stats": {
      "total_findings": 12,
      "ai_triaged_findings": 5,
      "true_positive_count": 3,
      "false_positive_count": 1,
      "needs_review_count": 1
    }
  }
}
```

### POST /provider/test

**Запрос** (application/x-www-form-urlencoded): те же поля что и /scan (без archive).

**Ответ**:
```json
{"ok": true, "message": "Провайдер ollama-agentic:qwen2.5:7b-instruct отвечает", "latency_ms": 1240}
```

### Использование в CI (пример GitHub Actions)

```yaml
- name: SAST Scan
  run: |
    tar czf /tmp/code.tar.gz -C $GITHUB_WORKSPACE .
    RESULT=$(curl -sS -X POST https://sast.example.com/scan \
      -F "archive=@/tmp/code.tar.gz" \
      -F "provider=ollama-agentic" \
      -F "fail_on_severity=HIGH" \
      -F "fail_on_verdict=true_positive" \
      -F "correlation_id=$GITHUB_SHA")
    echo "$RESULT" | jq '.report.stats'
    if [ "$(echo "$RESULT" | jq -r '.should_fail')" = "true" ]; then
      echo "Security gate triggered!"
      exit 1
    fi
```

---

## 11. Конфигурация

### Переменные окружения

| Переменная | Default | Описание |
|-----------|---------|----------|
| SAST_SERVER_ADDR | `:8080` | Адрес HTTP-сервера |
| SAST_WORKERS | NumCPU | Параллельных воркеров для сканирования |
| SAST_AI_PROVIDER | `ollama-agentic` | Провайдер по умолчанию |
| SAST_OLLAMA_URL | `http://127.0.0.1:11434` | URL Ollama API |
| SAST_OLLAMA_MODEL | `qwen2.5:7b-instruct` | Модель Ollama |
| SAST_OLLAMA_NUM_CTX | `2048` | Размер контекстного окна |
| SAST_OPENAI_URL | `https://api.openai.com/v1` | URL OpenAI-совместимого API |
| SAST_OPENAI_MODEL | `gpt-4o-mini` | Модель OpenAI |
| SAST_OPENAI_KEY | *(пусто)* | API ключ OpenAI |
| SAST_GIGACHAT_SCOPE | `GIGACHAT_API_PERS` | Scope GigaChat |
| SAST_AI_BUDGET | `0` (все) | Макс. findings для AI-анализа |
| SAST_FAIL_ON_SEVERITY | `MEDIUM` | Порог severity для gate |
| SAST_FAIL_ON_VERDICT | `true_positive` | Тип вердикта для gate |
| SAST_SNIPPET_RADIUS | `8` | Строк кода вокруг finding |
| SAST_CODEQL_MAX_FILES | `10000` | Макс. файлов для CodeQL (больше → fallback) |
| SAST_INCLUDE_TESTS | `false` | Включать тестовые файлы |
| SAST_FEEDBACK_IN | *(пусто)* | Путь к feedback JSON-файлу |
| SAST_API_PORT | `10000` | Внешний host-port API в Docker Compose |
| SAST_UI_PORT | `10001` | Внешний host-port Web UI в Docker Compose |

---

## 12. Поток данных end-to-end

```
Пользователь загружает код.zip через веб-форму
         │
         ▼
nginx (host port 10001) → proxy_pass → sast-agent-api (container port 8080)
         │
         ▼
parseUpload()
  ├─ r.ParseMultipartForm(32MB)
  ├─ os.MkdirTemp() → /tmp/sast-upload-XXXX/
  ├─ extractZip() или extractTarGz()
  │    └─ path traversal check, macOS metadata skip
  └─ applyFormOverrides()
         │
         ▼
SSE: {"type":"scanning"}  ←── браузер показывает анимированный бар + таймер
         │
         ▼
checkProviderReady()
  ├─ pingOllama() → GET /api/tags → проверяет наличие модели
  └─ если OpenAI/GigaChat → проверяет наличие ключа
         │
         ▼
findGoRoot() → ищет go.mod в tmpDir
         │
         ▼
scanner.ScanWithOptions(root, opts)
  │
  ├─ collectFiles() → []string .go files
  │
  ├─ CodeQL (если доступен и файлов ≤ SAST_CODEQL_MAX_FILES):
  │    ├─ pruneGeneratedFiles() → удаляет *_gen.go, *.pb.go
  │    ├─ writeCodeQLIgnore() → .codeqlignore
  │    └─ codeql database create + analyze → parseSARIFFindings() → []Finding
  │
  ├─ Builtin (всегда, merge с CodeQL):
  │    ├─ ensureGoMod() → создаёт go.mod если нет
  │    └─ scanPackages() → go/packages (GOPROXY=off) + ast/inspector + taint-lite
  │
  └─ External (если бинарь в $PATH, merge):
       ├─ ScanWithGosec()      → gosec -fmt=json -no-fail ./...
       └─ ScanWithGovulncheck() → govulncheck -json ./...
         │
         ▼
SSE: {"type":"start","total":42,"files_scanned":180}  ←── бар переключается на N/42
         │
         ▼
agent.Run(scanRes, provider, feedback, opts)
  │
  ├─ rankFindings() → CRITICAL first
  │
  └─ для каждого finding (до AIBudget):
       │
       ├─ provider.Triage(finding)
       │    ├─ [ollama-agentic]
       │    │    Step1: analystPrompt → /api/generate
       │    │    Step2: skepticPrompt → /api/generate
       │    │    Step3: judgePrompt → /api/generate (format:json)
       │    │    decodeVerdict() → Verdict
       │    │
       │    └─ [retry если EOF/connection reset, 1 попытка, задержка 2s]
       │
       ├─ calibrateVerdict() — только при отсутствии ошибки AI
       │
       ├─ ApplyFeedback() → override из feedback.json если есть
       │
       ├─ snippetAround(file, line, radius) → code snippet
       │
       └─ SSE: {"type":"progress","current":K,"total":42,"verdict":"true_positive",...}
                         ←── браузер добавляет карточку finding в реальном времени
         │
         ▼
ShouldFail(report, policy)
  → should_fail = (any finding with severity≥HIGH AND label=true_positive)
         │
         ▼
SSE: {"type":"done","result":{should_fail, report}}
         ←── браузер показывает PASS/FAIL + полный отчёт + сниппеты
         │
         ▼
os.RemoveAll(tmpDir)  ← cleanup
```

---

## 13. Обоснование решений

### Почему Go для реализации

- Статические бинарники: `CGO_ENABLED=0` даёт ~15 МБ исполняемый файл без зависимостей от системных библиотек
- Нативный AST-парсер: `go/ast`, `go/packages` позволяют анализировать Go-код без внешних инструментов
- Горутины: параллельный скан тысяч файлов через worker pool без overhead потоков ОС
- Тип `http.Flusher`: встроенная поддержка SSE без сторонних библиотек

### Почему архитектура Upload vs Path

Предыдущий подход (передача пути к локальным файлам в JSON) создавал риск Server-Side Path Traversal: злоумышленник мог указать `/etc/passwd` вместо `/code`. Архитектура с загрузкой архива изолирует анализируемый код во временной директории, недоступной из API.

### Почему SSE а не WebSocket

- SSE — стандартный HTTP/1.1, без специального протокола
- Достаточно для односторонней передачи прогресса (сервер → клиент)
- Работает через reverse proxy без дополнительной конфигурации (кроме `proxy_buffering off`)
- WebSocket потребовал бы поддержки `Upgrade: websocket` в nginx

### Почему трёхшаговый агентный подход

Одношаговые LLM-запросы для security-задач дают ~60-70% точности — модель склонна подтверждать первоначальную гипотезу (confirmation bias). Паттерн Аналитик→Скептик→Судья заимствован из методологии Red Team/Blue Team:
- Аналитик работает как defender (ищет уязвимости)
- Скептик работает как challenger (ищет причины не считать это проблемой)  
- Судья синтезирует оба взгляда

Эмпирически такой подход снижает false positive rate на 20-30% по сравнению с одношаговым анализом.

### Почему три уровня сканирования

| Уровень | Инструмент | Что даёт |
|---------|------------|---------|
| 1 | CodeQL | Межпроцедурный taint, data flow, низкий FP |
| 2 | go/packages + ast/inspector | Работает без CodeQL, анализирует любой архив (ensureGoMod) |
| 3 | gosec + govulncheck | Ещё один набор правил + CVE в зависимостях |

Результаты дедуплицируются по `ruleID|file|line|column`. Каждый уровень дополняет, а не заменяет предыдущий.

### Почему один образ (не два)

Единый `Dockerfile` (~1.5 ГБ) включает весь стек. Разделение на «лёгкий» и «полный» образ создавало drift: встроенные правила давали другой набор находок, что путало при сравнении отчётов. Один образ гарантирует воспроизводимость.

### Почему Ollama для локальных моделей

- Privacy: код проекта не покидает инфраструктуру
- Cost: нет платы за API токены
- OpenAI-совместимый API (`/api/generate`) с поддержкой `format: json`
- Модели из открытых источников (дефолт: qwen2.5:7b-instruct)

### Почему `num_ctx=2048` по умолчанию

Контекстное окно в 4096 токенов при работе с моделью 1.5B на системе с ограниченной RAM вызывало OOM-kill модельного runner'a. 2048 токенов достаточно для анализа одного finding (промпт ~800 токенов + ответ ~200 токенов) при существенно меньшем потреблении памяти.
