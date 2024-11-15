
# Реализация JWT аутентификации с кастомными ролями в Spring Boot

## Описание проекта
Проект представляет собой Spring Boot приложение с реализованной JWT аутентификацией и кастомными ролями для контроля доступа к определённым эндпоинтам. В дополнение, реализованы:
- Блокировка аккаунта после нескольких неудачных попыток входа.
- Логирование событий аутентификации.
- Обеспечение безопасности передачи данных через HTTPS.
- Возможность обновления JWT через Refresh Token (опционально).

## Технологии и библиотеки
- **Spring Boot** — основной фреймворк для создания приложения
- **Spring Security** — настройка безопасности и доступов
- **JWT (JSON Web Token)** — для аутентификации
- **Hibernate и JPA** — для работы с базой данных
- **HTTPS** — для безопасности передачи данных
- **Lombok** — для упрощения кода
- **Maven** — для управления зависимостями

## Функционал
- **Аутентификация и авторизация через JWT**
- **Блокировка аккаунта** после нескольких неудачных попыток входа
- **Логирование** событий аутентификации
- **Поддержка HTTPS** для безопасной передачи данных
- **Обновление токенов** с использованием Refresh Token (опционально)

## Структура проекта
- `controller` — контроллеры для обработки HTTP запросов
- `service` — сервисы для выполнения бизнес-логики
- `repository` — репозитории для работы с базой данных
- `security` — настройки безопасности, включая JWT фильтры и конфигурацию
- `dto` — объекты для передачи данных (Data Transfer Objects)
- `config` — конфигурационные классы приложения

## Начало работы

### Предварительные условия
Для запуска проекта вам понадобятся:
- **JDK 17+**
- **Maven** (при использовании Maven)
- **База данных** (например, H2 для тестов или PostgreSQL для продакшн)

### Установка и настройка

1. **Склонируйте репозиторий**:
   ```bash
   git clone https://github.com/your-repository/jwt-authentication-example.git
   cd jwt-authentication-example
   ```

2. **Настройте базу данных**. В `application.properties` или `application.yml` укажите параметры для подключения к базе данных.

3. **Запустите миграции базы данных** (если используется Liquibase или Flyway).

4. **Соберите и запустите приложение**:
   ```bash
   mvn clean install
   mvn spring-boot:run
   ```

## Использование

### Регистрация и вход
- Для создания пользователя или входа отправьте `POST` запросы на эндпоинты `/auth/sign-up` и `/auth/sign-in`.
- При успешной аутентификации сервер ответит JWT токеном.

### Блокировка аккаунтов
- Аккаунт пользователя будет заблокирован после нескольких (например, 3) неудачных попыток входа.
- Администратор может разблокировать аккаунт вручную (дополнительно можно реализовать автоматическое снятие блокировки через определённое время).

### Обновление токена
- Для обновления токена отправьте `POST` запрос на эндпоинт `/auth/refresh-token` с действительным Refresh Token.

### Пример эндпоинтов и прав доступа
- **/auth/** — общедоступные эндпоинты для регистрации и аутентификации
- **/admin/** — эндпоинты, доступные только пользователям с ролью `ADMIN`
- **/user/** — эндпоинты, доступные пользователям с ролью `USER`

## Безопасность данных
Для обеспечения безопасности передаваемых данных рекомендуется настроить HTTPS на сервере. В `application.properties` добавьте настройки для использования SSL.

### Пример конфигурации для HTTPS:
```properties
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=your-password
server.ssl.keyStoreType=PKCS12
server.ssl.keyAlias=your-alias
```

## Логирование
- Все попытки входа и выхода, успешные и неудачные, логируются для обеспечения дополнительной безопасности.
- Логирование можно настроить через файл `application.properties` для различных уровней, например:
  ```properties
  logging.level.org.springframework.security=DEBUG
  logging.level.com.example=INFO
  ```

## Тестирование
Для проверки работоспособности JWT аутентификации и ролей:
- Реализуйте unit и интеграционные тесты с использованием JUnit и Mockito.

## Дополнительные ресурсы
- [Документация Spring Security](https://spring.io/projects/spring-security)
- [Документация JWT](https://jwt.io/)
- [Руководство по настройке HTTPS](https://www.baeldung.com/spring-boot-https-self-signed-certificate)