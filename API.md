# Документация Aspia REST API

Этот API предоставляет доступ к информации о Aspia Router и Host, включая детальную конфигурацию системы.

## Базовый URL
`http://localhost:8080` (по умолчанию)

## Аутентификация
API использует комбинацию настроек по умолчанию из `config.ini` и HTTP-заголовков для аутентификации.

### Заголовки (Headers)
Вы можете переопределить учетные данные из `config.ini`, передав следующие заголовки в запросе:

| Заголовок | Описание |
| :--- | :--- |
| `X-Aspia-Router-User` | Имя пользователя для подключения к Aspia Router (доступ администратора). |
| `X-Aspia-Router-Password` | Пароль для Aspia Router. |
| `X-Aspia-Host-User` | Имя пользователя для аутентификации на целевом Хосте (System Info). |
| `X-Aspia-Host-Password` | Пароль для целевого Хоста. |

---

## Эндпоинты (Endpoints)

### 1. Получить список хостов
Возвращает список всех хостов, подключенных к Aspia Router.

**Запрос:**
`GET /hosts`

**Ответ:**
```json
[
  {
    "host_id": 43,
    "session_id": 12345,
    "computer_name": "WORKSTATION-01",
    "ip_address": "192.168.1.100",
    "os_name": "Windows 10 Pro",
    "architecture": "x64",
    "version": "2.5.2.0"
  }
]
```

### 2. Получить конфигурацию хоста (System Info)
Возвращает детальную системную информацию для конкретного хоста.

**Запрос:**
`GET /hosts/{hostId}/config`

**Параметры запроса (Query Parameters):**

| Параметр | Тип | По умолчанию | Описание |
| :--- | :--- | :--- | :--- |
| `category` | string | `summary` | Указывает, какую категорию данных получить. |

**Поддерживаемые категории:**
*   `summary` (По умолчанию): Базовая информация (Компьютер, ОС, CPU, RAM и т.д.)
*   `all`: **Все доступные категории** (тяжелый запрос)
*   `video_adapters`: Видеокарты и драйверы
*   `monitors`: Подключенные мониторы
*   `printers`: Установленные принтеры
*   `applications`: Установленные программы
*   `drivers`: Системные драйверы
*   `services`: Службы Windows
*   `users`: Локальные пользователи
*   `processes`: Запущенные процессы
*   ... и другие (см. `handlers/aspia_service.go` для полного списка)

**Пример запроса:**
```bash
curl -H "X-Aspia-Host-User: admin" \
     -H "X-Aspia-Host-Password: secret" \
     "http://localhost:8080/hosts/43/config?category=video_adapters"
```

**Ответ:**
```json
{
  "host_id": 43,
  "system_info": {
    "video_adapters": [
      {
        "name": "NVIDIA GeForce RTX 3060",
        "memory": "12288 MB"
      }
    ]
  }
}
```

## Коды ошибок

Ошибки возвращаются в формате JSON:
```json
{
  "error": "Router authentication failed: access denied",
  "code": "router_auth_failed"
}
```

### Распространенные коды ошибок

| Код (code) | HTTP Статус | Описание |
| :--- | :--- | :--- |
| `router_auth_failed` | 401 | Неверные учетные данные Роутера. |
| `host_auth_failed` | 401 | Неверные учетные данные Хоста. |
| `router_connection_failed` | 500 | Не удалось подключиться к Роутеру. |
| `router_operation_failed` | 500 | Не удалось получить список хостов. |
| `host_operation_failed` | 500 | Не удалось получить системную информацию с Хоста. |
| `bad_request` | 400 | Неверные параметры (например, ID хоста). |
| `internal_error` | 500 | Внутренняя ошибка сервера (например, ошибка JSON). |
