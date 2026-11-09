# Защищённое REST API

Учебный REST API на Flask для аутентификации пользователей и работы с заметками. Данные хранятся в SQLite. У каждого пользователя доступ только к его заметкам.

## Стек

- Python 3.12, Flask
- SQLite с параметризованными SQL-запросами
- PyJWT для токенов, Argon2 для хэширования паролей
- Bandit для SAST, pip-audit для SCA
- GitHub Actions для CI/CD

## Запуск

```bash
cd lab1
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
export JWT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/flask --app app:create_app create-user rmb
.venv/bin/flask --app app:create_app run
```

При создании пользователя введите пароль длиной от 12 до 128 символов. Создание учётной записи выполняется командой CLI; REST-маршрута `/auth/register` в этом варианте API нет.
Если пользователь уже создан в локальной базе, шаг `create-user` можно пропустить.

## Описание API

Все запросы и ответы используют JSON. Для защищённых маршрутов передавайте JWT в заголовке `Authorization: Bearer <токен>`.

### `POST /auth/login`

Аутентифицирует пользователя и возвращает JWT. Поля запроса — `username` и `password`.

```json
{
  "username": "rmb",
  "password": "ваш-пароль-длиной-от-12-символов"
}
```

Успешный ответ содержит `access_token`, тип токена `Bearer` и `expires_in: 36000` (10 часов).

### `GET /api/data`

Возвращает заметки текущего пользователя. Требуется действующий JWT.

```bash
curl -sS http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer $TOKEN"
```

### `POST /api/data`

Создаёт заметку для текущего пользователя. Требуется действующий JWT.

```json
{
  "title": "Заголовок",
  "content": "Текст заметки"
}
```

## Реализованные меры защиты

- **SQL-инъекции:** запросы к SQLite используют параметры (`?`) и передают значения отдельно от SQL-кода. Пользовательский ввод не конкатенируется в SQL-запросы.
- **XSS:** заголовок и текст заметки экранируются через `html.escape` перед возвратом в JSON. Кириллица в JSON-ответах выводится напрямую.
- **Аутентификация:** пароли хэшируются Argon2. После успешного входа сервер выдаёт подписанный JWT со сроком действия 10 часов. Middleware проверяет подпись, срок, издателя и аудиторию токена на защищённых маршрутах.
- **Доступ к данным:** запросы заметок ограничены идентификатором пользователя из проверенного JWT; пользователь не может читать или изменять чужие заметки.
- **HTTP-защита:** ответы включают заголовки `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` и `Cache-Control`.

## Отчёты из pipeline

Pipeline запускает тесты API, Bandit и pip-audit. HTML-отчёт `dependency-check-report.html` загружается как артефакт с именем `dependency-check-report`. Откройте [запуски GitHub Actions](https://github.com/romboooo/iblab1/actions/workflows/ci.yml), выберите последний успешный запуск и скачайте этот артефакт. В последнем проверенном запуске тесты прошли, а pip-audit сообщил, что известных уязвимостей не найдено.

Pipeline запускает тесты API, Bandit и pip-audit. В запуске #9 тесты прошли, Bandit завершился без находок заданных уровней, а pip-audit сообщил, что известных уязвимостей в зависимостях не найдено.
