# py_proxy

TCP SNI proxy — routeert HTTPS-verkeer op basis van de SNI-hostnaam zonder TLS te termineren.

## Bestanden

- `proxy.py` — de volledige proxy, één bestand, geen externe dependencies
- `config.json` — runtime configuratie (wordt live bijgehouden door de admin UI)
- `backup.sh` — sync naar Google Drive via rclone (`google:backup/py_proxy`)

## Starten

```bash
python3 proxy.py            # gebruikt config.json in de huidige map
python3 proxy.py pad/naar/config.json
```

Vereist root (of `cap_net_bind_service`) alleen als je luistert op poort < 1024.

## Poorten

| Poort | Functie |
|-------|---------|
| 8444  | TLS SNI proxy (inkomend HTTPS-verkeer) |
| 8888  | Admin web UI (`http://<host>:8888/`) |

## Config (config.json)

```json
{
  "listen_host": "0.0.0.0",
  "listen_ports": [8444],
  "tls_routes": {
    "voorbeeld.nl": {"host": "192.168.1.10", "port": 443, "name": "label", "enabled": true}
  },
  "connect_timeout": 10,
  "read_timeout": 5,
  "admin_host": "0.0.0.0",
  "admin_port": 8888
}
```

Routes kunnen live aan/uit worden gezet via de admin UI of met een SIGHUP na handmatige aanpassing.

## Signalen

```bash
kill -HUP <pid>    # herlaad config.json zonder herstart
kill -TERM <pid>   # netjes stoppen
```

## Admin UI

Bereikbaar op `http://<host>:8888/`. Toont alle routes met een toggle om ze in/uit te schakelen. Wijzigingen worden direct actief en opgeslagen in `config.json`.

## Bekende valkuilen

- `onchange`-attribuut in de admin UI gebruikt enkele aanhalingstekens — `JSON.stringify` geeft dubbele aanhalingstekens terug die het HTML-attribuut anders zouden breken.
- Admin poort was oorspronkelijk 8080, maar dat was al in gebruik op deze machine; nu 8888.
