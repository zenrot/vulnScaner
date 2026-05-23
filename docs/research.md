# Исследование: AI-агенты для SAST

Дата исследования: 2026-05-20.

## Ключевой вывод

Для самостоятельной реализации разумнее строить не "LLM вместо SAST", а гибридный AI-SAST агент:

1. Детерминированный анализатор находит воспроизводимые кандидаты в уязвимости.
2. Агент собирает контекст вокруг finding: AST-узел, импорт, функция, соседние строки, возможный source/sink путь.
3. LLM или локальная модель выполняет triage: true positive / false positive / needs review.
4. Агент формирует объяснение, remediation и приоритет.
5. Подтвержденные паттерны превращаются в новые правила или тест-кейсы.

Такой дизайн снижает риск галлюцинаций: AI не "выдумывает" уязвимости с нуля, а работает поверх проверяемых фактов.

## Что делают существующие решения

### Semgrep и Semgrep Assistant

Semgrep описывает SAST как запуск правил по коду: правила матчят фрагменты и создают findings. В документации отдельно указана возможность писать custom rules и использовать registry rules. Semgrep Assistant добавляет AI-assisted triage/remediation поверх результатов SAST.

Полезные идеи для нашего проекта:

- правила должны быть человекочитаемыми;
- findings должны содержать минимальный контекст для review;
- AI-этап должен быть отключаемым и воспроизводимым;
- важно явно отделить rule finding от AI verdict.

Источники:

- https://semgrep.dev/docs/running-rules/
- https://semgrep.dev/docs/writing-rules/overview
- https://semgrep.dev/

### CodeQL

CodeQL трактует код как данные и особенно силен в data flow / path queries: можно моделировать путь от source к sink. Это полезно для SQL injection, command injection, path traversal, SSRF и утечек секретов.

Полезные идеи:

- отдельная модель sources/sinks/sanitizers;
- path-based evidence важнее простого "строка подозрительная";
- для niche frameworks нужны custom models.

Источники:

- https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql
- https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/
- https://codeql.github.com/docs/codeql-overview/about-codeql/

### gosec

gosec - зрелый Go security checker. Его README описывает анализ Go AST и SSA, JSON/SARIF вывод и наборы правил по hardcoded credentials, injection risks, file/path handling, crypto и HTTP hardening.

Полезные идеи:

- Go-сканер должен использовать AST, а позднее SSA;
- JSON/SARIF пригодны для CI;
- правила удобно группировать по CWE/категориям.

Источник:

- https://github.com/securego/gosec

### Go analysis API

Официальный пакет `golang.org/x/tools/go/analysis` задает модель Analyzer: имя, документация, зависимости и функция `Run`. Это хороший следующий шаг после MVP на стандартном `go/ast`, если нужно подключаться к `go vet`, `singlechecker`, `multichecker`, SSA и type information.

Источники:

- https://pkg.go.dev/golang.org/x/tools/go/analysis
- https://go.dev/pkg/go/ast/

## Свежие исследовательские направления

### Multi-agent false-positive reduction

QASecClaw описывает схему, где SAST сначала создает candidates, а LLM-based filter agent проверяет findings с контекстом кода и классифицирует true/false positive.

Источник:

- https://arxiv.org/abs/2605.01885

### Ensemble/static-analysis orchestration

Argus рассматривает multi-agent ensemble поверх статического анализа для full-chain vulnerability detection. Это подтверждает идею, что агент должен оркестрировать инструменты и контекст, а не быть единственным механизмом анализа.

Источник:

- https://arxiv.org/abs/2604.06633

### LLM-supported SAST

LSAST предлагает интегрировать LLM со SAST-сканерами, чтобы усилить поиск уязвимостей и компенсировать ограничения отдельных подходов. Важные риски: privacy, устаревшие знания модели и нестабильность результата.

Источник:

- https://arxiv.org/abs/2409.15735

### Сравнение агентов для фильтрации шума

Исследование "Sifting the Noise" сравнивает агентные фреймворки для false-positive filtering и показывает, что агентный слой может резко снижать шум SAST, но требует строгой постановки задачи и ground truth.

Источник:

- https://arxiv.org/abs/2601.22952

## Предлагаемая тема реализации

Название: "Локальный AI-агент для SAST-анализа Go-кода с детерминированным ядром и LLM-триажом".

Минимальный продукт:

- CLI: `sast-agent -path ./project -format json`.
- AST rules для Go.
- Findings с severity, file, line, evidence, why, remediation.
- JSON output.
- Набор тестовых уязвимых примеров.
- Документированная архитектура AI-этапа.

Расширенный продукт:

- SARIF output для GitHub code scanning.
- Поддержка `go/analysis` и SSA.
- Taint analysis: sources/sinks/sanitizers.
- LLM triage provider interface.
- Offline mode без отправки кода во внешние API.
- Prompt templates, где модель получает только минимальный необходимый контекст.
- Автогенерация patch suggestions без автоматического применения.

## Правила безопасности для AI-слоя

- Не отправлять секреты и полные файлы в LLM без явного разрешения.
- Передавать только минимальный snippet вокруг finding.
- Хранить AI verdict отдельно от scanner finding.
- В отчете показывать confidence и причину.
- Не применять remediation автоматически.
- Логировать версию правил, модель, prompt template и hash snippet, но не секретное содержимое.
