# AI Project Knowledge

## Формулировка Задания

Использование AI-агентов в задачах обеспечения безопасности.  
Разработать AI-агент, реализующий автоматизацию анализа безопасности и поиска уязвимостей одного из следующих типов объектов анализа: исходный код (SAST).

## Быстрая Навигация По Задачам

| Тип задачи | Файл |
| --- | --- |
| Лог всех задач и изменений (основной) | `current_task/2026-05-20-sast-agent-upgrade.md` |
| История первого MVP и стартового исследования | `current_task/2026-05-20-sast-agent-repo.md` |
| Исследование библиотек Go для усиления SAST-ядра | `services/go_sast_libraries.md` |

## Ключевые Решения

| Компонент | Решение | Файл |
| --- | --- | --- |
| AI-калибровка вердиктов | `false_positive` → max `needs_review`; `true_positive` ставит только модель | `internal/agent/calibration.go` |
| Промпт триажа | Default=true_positive для HIGH/CRITICAL; русский язык; явный запрет FP без кода защиты | `internal/agent/provider/prompt.go` |
| Провайдеры AI | `ollama`, `ollama-agentic` (analyst→skeptic→judge), `gigachat`, `openai` | `internal/agent/provider/` |
| Серверный режим | `POST /scan` multipart; `/healthz`; CI-артефакты в `-ci-output-dir` | `cmd/sast-agent-server/` |
| Сканеры | Собственные правила Go + gosec + govulncheck + CodeQL | `internal/scanner/`, `Dockerfile.codeql` |
| CI-интеграция | GitHub Actions (PR-комментарий), GitLab CI (MR-комментарий) | `examples/` |

## Правила

- Этот файл читается перед каждой задачей.
- Открываются только тематические файлы, относящиеся к текущей задаче.
- Постоянная документация проекта хранится в корне репозитория (`README.md`, `docs/*.md`), task-log хранит только факты выполнения.
