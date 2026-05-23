# Go Библиотеки Для Усиления SAST

Дата: 2026-05-20

## Что лучше стандартной библиотеки для SAST

1. `golang.org/x/tools/go/analysis`
- Промышленный каркас Analyzer-пайплайнов.
- Позволяет строить набор проверок с зависимостями, facts и переиспользуемыми passes.
- Источник: https://pkg.go.dev/golang.org/x/tools/go/analysis

2. `golang.org/x/tools/go/packages`
- Корректная загрузка модулей/пакетов с учетом build tags и workspace-контекста.
- Лучше простого `filepath+parser` для реальных монореп.
- Источник: https://pkg.go.dev/golang.org/x/tools/go/packages

3. `golang.org/x/tools/go/ast/inspector`
- Быстрый индексированный обход AST (эффективнее многократных `ast.Inspect`).
- Полезно для производительности rule engine.
- Источник: https://pkg.go.dev/golang.org/x/tools/go/ast/inspector

4. `golang.org/x/tools/go/ssa` + `golang.org/x/tools/go/pointer`
- База для межпроцедурного и path-sensitive анализа.
- Критично для глубокой проверки source/sink/sanitizer.
- Источники:
  - https://pkg.go.dev/golang.org/x/tools/go/ssa
  - https://pkg.go.dev/golang.org/x/tools/go/pointer

5. `honnef.co/go/tools` (Staticcheck framework)
- Набор зрелых анализаторов и практик построения checks.
- Можно адаптировать подходы к диагностикам и качеству сигналов.
- Источник: https://github.com/dominikh/go-tools

6. `github.com/quasilyte/go-ruleguard/dsl`
- DSL для декларативных Go-правил; полезно как слой быстрой разработки сигнатур.
- Источник: https://github.com/quasilyte/go-ruleguard

7. `github.com/securego/gosec`
- Эталонный Go security scanner с практическими rule-паттернами.
- Полезен как референс для rule coverage и тестовых кейсов.
- Источник: https://github.com/securego/gosec

## Рекомендуемая эволюция нашего ядра

1. Перейти с `parser+ast` на `go/packages + go/analysis`.
2. Заменить ручные AST-проходы на `ast/inspector`.
3. Добавить `ssa`-этап для taint анализа между функциями.
4. Добавить rule layer на базе ruleguard-подобного DSL.
5. Сохранить AI-слой поверх детерминированных findings (не вместо них).
