# Aspia REST API

REST API для работы с Aspia Router - получение списка хостов и конфигурации отдельных хостов.

## Эндпоинты

### GET /hosts
Получить список всех доступных хостов на Aspia Router.

**Ответ:**
```json
[
  {
    "host_id": 48,
    "session_id": 1,
    "computer_name": "DESKTOP-ABC",
    "ip_address": "192.168.1.100",
    "os_name": "Windows 10 Pro",
    "architecture": "x86_64",
    "version": "2.7.0.4866"
  }
]
```

### GET /hosts/{hostId}/config
Получить конфигурацию конкретного хоста, подключившись к нему через Aspia Relay.

**Параметры:**
- `hostId` - ID хоста (из списка хостов)

**Ответ:**
```json
{
  "host_id": 48,
  "system_info": "OS: Windows 10 Pro, Arch: x86_64, Version: 2.7.0.4866"
}
```

### GET /health
Проверка работоспособности API.

**Ответ:**
```json
{
  "status": "OK"
}
```

## Запуск

1. Убедитесь, что файл `config.ini` находится в родительской директории
2. Установите зависимости:
```bash
go mod tidy
```

3. Запустите сервер:
```bash
go run main.go
```

Сервер будет доступен на `http://localhost:8080`

## Примеры использования

```bash
# Получить список хостов
curl http://localhost:8080/hosts

# Получить конфигурацию хоста с ID 48
curl http://localhost:8080/hosts/48/config

# Проверить здоровье API
curl http://localhost:8080/health
```
