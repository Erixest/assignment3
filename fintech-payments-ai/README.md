# FinPay AI Edition

Веб-приложение для управления цифровыми платежами и мониторинга мошенничества, разработанное с применением AI-инструментов (GitHub Copilot, ChatGPT GPT-4). Функционально эквивалентно Go-версии из задания 1.

## Стек технологий

- Python 3.11
- FastAPI (ASGI-фреймворк)
- SQLAlchemy 2.0 (ORM)
- SQLite
- Jinja2 (шаблонизатор)
- python-jose (JWT, HS256)
- passlib[bcrypt] (хеширование паролей)
- SlowAPI (ограничение частоты запросов)
- itsdangerous (CSRF-токены)

## Быстрый старт

```bash
# 1. Скопировать конфигурацию
cp .env.example .env

# 2. Установить SECRET_KEY (минимум 32 символа)
# Отредактировать .env и задать SECRET_KEY

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Инициализировать и заполнить БД
python3 -c "from database import init_db, seed_db; init_db(); seed_db()"

# 5. Запустить сервер
uvicorn main:app --reload
```

Приложение будет доступно по адресу http://localhost:8000

## Учётные данные по умолчанию

| Пользователь | Пароль        | Роль     |
|--------------|---------------|----------|
| admin        | AdminPass1!   | analyst  |
| analyst1     | AnalystPass1! | analyst  |
| user1        | UserPass1!    | user     |
| user2        | UserPass2!    | user     |
| user3        | UserPass3!    | user     |

## Docker

```bash
cp .env.example .env
# Отредактировать .env

docker compose up --build
```

Приложение будет доступно по адресу http://localhost:8001

## Функциональность

- Регистрация и аутентификация пользователей (JWT в httponly cookie)
- Две роли: user (создание и просмотр своих платежей), analyst (все платежи + управление)
- Уникальные идентификаторы квитанций TXN-YYYYMMDD-XXXXXX
- Автоматическая оценка риска транзакций
- Панель аналитика: статистика, фильтрация, отметка/отклонение платежей
- Журнал аудита всех критичных событий
- Экспорт платежей в CSV

## Механизмы безопасности

- JWT HS256, httponly + samesite=lax cookie
- bcrypt с проверкой сложности пароля
- Блокировка аккаунта после 5 неверных попыток (15 минут)
- Rate limiting на /login (5 запросов в минуту с одного IP)
- CSRF-защита через itsdangerous на всех state-changing POST запросах
- Обязательный SECRET_KEY (min 32 символа), RuntimeError при отсутствии
- Разграничение доступа: пользователь видит только свои платежи
- Глобальный exception handler без раскрытия stack trace
- Структурированный аудит-лог без PII (паролей)
