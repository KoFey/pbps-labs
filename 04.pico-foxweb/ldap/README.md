# Настройка LDAP для pico-foxweb

Этот проект предназначен для развёртывания локального OpenLDAP-сервера с пользователями, подготовленными для Digest-аутентификации (через HA1-хэш).

---

##  Требования

- Debian (или совместимая система)
- `slapd` и `ldap-utils`
- `make`, `md5sum`, `echo`

---

## Установка и настройка OpenLDAP

### 1. Установка OpenLDAP и утилит

```bash
sudo apt update
sudo apt install slapd ldap-utils
```

### 2. Выполните команду:

```
make apply LDAP_PASS=<указать пароль от LDAP>
```
Makefile выполнит пошаговую загрузку:

- базовой записи `dc=nodomain`
- `ou=users`
- пользователей ( `admin`, `newuser`)
