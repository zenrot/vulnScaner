# Лог задачи: варианты SAST для C-кода с реализацией на Go

- 2026-05-22: запрос пользователя — подобрать решения для SAST анализа C-кода в контуре на Go.
- Прочитаны: `ai_project_knowledge/README.md` (обязательно), `ai_project_knowledge/services/go_sast_libraries.md` (релевантно архитектуре Go SAST).
- Проведен внешний ресерч по инструментам: CodeQL, Semgrep, CodeChecker/Clang, Infer, Tree-sitter Go bindings.
- Подготовлен список практических вариантов: готовые движки + orchestration через Go и вариант собственного rule-engine на tree-sitter.

Кандидат на перенос в постоянную документацию: для C-кода в Go-контуре оптимальна гибридная стратегия (CodeChecker/Clang + Semgrep + единый Go-нормализатор SARIF/JSON).
