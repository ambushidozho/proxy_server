# Белокопытов Даниил
Вариант 3
# Описание
Прокси сервер задеплоен на порту 8080

Веб-апи задеплоено на порту 8000
## Использование
Чтобы сгенерировать сертификаты и запустить docker

Предварительно нужно добавить в ОС корневой сертификат:
```sh
$ sudo apt-get install -y ca-certificates
$ sudo cp certs/ca.crt /usr/local/share/ca-certificates
$ sudo update-ca-certificates
```

Запустите проект с помощью команды:
```sh
./start.sh
```

## API
- GET /api/v1/requests – Список запросов;
- GET /api/v1/requests/{id} – Получить 1 запрос;
- GET /api/v1/repeat/{id} – Переотправить запрос;
- GET /api/v1/scan/{id} – Проверить запрос на XXE уязвимости;

## XXE Scaner
В случае присутствия в запросе XML (строчка <?xml ...), заменяет его на 
```
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```
Ищет в ответе строчку "root:", если нашлась то запрос уязвим