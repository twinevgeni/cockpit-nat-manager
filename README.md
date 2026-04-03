# Cockpit NAT Manager Plugin

Плагин для управления правилами NAT (DNAT и SNAT) через веб-интерфейс Cockpit на AlmaLinux / RHEL / Rocky Linux.

## Возможности

- **DNAT** — проброс портов через `firewalld` rich rules (поддержка TCP/UDP, выбор зоны)
- **SNAT** — маскарадинг источника через `firewalld` direct rules
- Динамическое добавление и удаление правил без перезапуска сервисов
- Список всех активных правил с кнопкой удаления
- Валидация полей ввода (IP-адреса, порты, CIDR)
- Уведомления об успехе и ошибках
- Автоматический `firewall-cmd --reload` после каждого изменения

## Требования

- AlmaLinux 8/9 (или RHEL/Rocky Linux)
- `cockpit` установлен и запущен
- `firewalld` установлен и запущен
- Пользователь должен иметь права `sudo` / `wheel` (Cockpit запросит повышение прав)

## Установка

### Для текущего пользователя

```bash
mkdir -p ~/.local/share/cockpit/nat-manager
cp index.html app.js manifest.json ~/.local/share/cockpit/nat-manager/
```

### Системная установка (для всех пользователей)

```bash
sudo mkdir -p /usr/share/cockpit/nat-manager
sudo cp index.html app.js manifest.json /usr/share/cockpit/nat-manager/
```

После установки плагин появится в боковом меню Cockpit под именем **"NAT Manager"**.

> Перезапуск Cockpit не требуется — плагины подхватываются автоматически.

## Использование

### Добавить DNAT правило

Заполните поля:
| Поле | Описание | Пример |
|------|----------|--------|
| Внешний IP (Destination) | Публичный IP сервера | `188.127.226.59` |
| Протокол | TCP или UDP | `tcp` |
| Внешний порт | Порт, на который приходит трафик | `80` |
| Внутренний IP (To Address) | Локальный IP назначения | `192.168.122.237` |
| Внутренний порт (To Port) | Порт на локальном хосте | `80` |
| Зона | Зона firewalld | `public` |

Эквивалентная команда:
```bash
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" destination address="188.127.226.59" \
  forward-port port="80" protocol="tcp" to-addr="192.168.122.237" to-port="80"'
sudo firewall-cmd --reload
```

### Добавить SNAT правило

Заполните поля:
| Поле | Описание | Пример |
|------|----------|--------|
| Источник (Source CIDR) | Подсеть или IP источника | `192.168.122.3/32` |
| Исходящий интерфейс | Внешний сетевой интерфейс | `eno1np0` |
| Внешний IP (To Source) | Публичный IP для подмены | `152.89.219.98` |

Эквивалентная команда:
```bash
sudo firewall-cmd --permanent --direct \
  --add-rule ipv4 nat POSTROUTING 0 \
  -s 192.168.122.3/32 -o eno1np0 -j SNAT --to-source 152.89.219.98
sudo firewall-cmd --reload
```

## Структура файлов

```
nat-manager/
├── index.html      # Интерфейс плагина
├── app.js        # Логика: добавление, удаление, отображение правил
└── manifest.json   # Метаданные плагина для Cockpit
```
