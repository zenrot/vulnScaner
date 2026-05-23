# Лог задачи: локальный SAST AI-agent репозиторий

- 2026-05-20 19:28 MSK: старт задачи в `/Users/alexey/CLionProjects/mbks_auto`.
- Попытка открыть `ai_project_knowledge/README.md` завершилась ошибкой: файла и папки `ai_project_knowledge/` не было.
- Тематические файлы проектной AI-документации не открывались, потому что они отсутствовали.
- Создана структура `ai_project_knowledge/current_task/` для append-only лога текущей задачи.
- Проведено веб-исследование по AI+SAST: Semgrep/Semgrep Assistant, CodeQL, gosec, Go analysis API, QASecClaw, Argus, LSAST, false-positive filtering agents.
- Создается локальный Go-репозиторий с MVP CLI SAST-сканера и документацией исследования.
- Добавлены `go.mod`, CLI `cmd/sast-agent`, AST-сканер в `internal/scanner`, текстовый/JSON отчет, тесты, demo vulnerable project и документация `docs/research.md`, `docs/architecture.md`.
- `go test ./...` в sandbox сначала не прошел из-за запрета записи в `~/Library/Caches/go-build`; повторный запуск с локальным `GOCACHE=/Users/alexey/CLionProjects/mbks_auto/.cache/go-build` прошел успешно.
- Демо `go run ./cmd/sast-agent -path ./examples/vulnerable` нашло 7 findings и вернуло exit code 1, потому что уязвимости найдены.
- Инициализирован локальный git-репозиторий в `/Users/alexey/CLionProjects/mbks_auto`; ветка переименована в `main`. Коммит не создавался.

Кандидат на перенос в постоянную документацию: в проекте отсутствовал обязательный `ai_project_knowledge/README.md`; если эта папка должна существовать всегда, ее нужно создать отдельной явной задачей.
