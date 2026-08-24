# netcheck

Одноразовая диагностика Linux-сервера в один заход: **канал** (скорость/задержки), **IPv6** (стек, исходящий/входящий), и **доступность из РФ и из-за рубежа** (узлы check-host.net).

Только читает и шлёт запросы — ничего не устанавливает и не меняет на машине.

## Запуск

Прямо на проверяемой машине (по SSH):

```bash
curl -sL https://raw.githubusercontent.com/hordes22/netcheck/main/netcheck.sh | bash
```

Проверить чужой хост / указать TCP-порт для проверки «из мира»:

```bash
curl -sL https://raw.githubusercontent.com/hordes22/netcheck/main/netcheck.sh -o netcheck.sh
bash netcheck.sh 1.2.3.4      # цель — другой IP
PORT=443 bash netcheck.sh     # порт для TCP-проверки из мира
```

## Требуется

`bash`, `curl`, `ping` (+`ping6` для IPv6), `python3` (разбор JSON).
Единственная внешняя зависимость — публичный API `check-host.net` (ключ не нужен).

## Что показывает

1. **Кто это** — публичный IPv4/IPv6, провайдер, гео.
2. **Канал** — задержки до якорей (CF/Google/Yandex/Hetzner), скорость (Ookla `speedtest` при наличии, иначе curl-бенч Cloudflare).
3. **IPv6** — глобальный адрес, маршрут, исходящая связность.
4. **Из РФ и из-за рубежа** — ICMP-ping + TCP до сервера с ~30 узлов, разбито на «из России» и «из-за рубежа», с итоговым вердиктом.
