# 2026-05-23 github deploy key

- Прочитан `ai_project_knowledge/README.md`.
- Тематические файлы не открывались: вопрос только про SSH secret для GitHub Actions deploy.
- Проверен `.github/workflows/deploy.yml`: workflow ожидает secret `DEPLOY_SSH_KEY` как приватный SSH-ключ для подключения к `DEPLOY_USER@DEPLOY_HOST`.
- Уточнено: для хоста имя secret должно быть ровно `DEPLOY_HOST`, а IP/DNS сервера вводится в поле value, не в name.
