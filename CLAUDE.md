# py_proxy

TCP SNI proxy — routeert HTTPS-verkeer op basis van SNI-hostnaam (passthrough) of hostnaam + pad (met TLS-terminatie).

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

## Routering

Er zijn twee soorten routes:

### Passthrough (hostnaam alleen)
TLS wordt **niet** getermineerd. De proxy leest alleen de SNI uit de ClientHello en stuurt de verbinding transparant door. Het backend-certificaat blijft intact.

```json
"home.budie.eu": {"host": "192.168.2.76", "port": 300, "name": "home", "enabled": true, "backend_ssl": false, "strip_path": true}
```

### Pad-routing (hostnaam + pad)
TLS wordt **wel** getermineerd met het geconfigureerde wildcard-certificaat. De proxy leest het HTTP-verzoek, matcht op langste padprefix en stuurt door naar de backend.

```json
"home.budie.eu/pfsense": {"host": "192.168.2.76", "port": 443, "name": "pfsense", "enabled": true, "backend_ssl": true, "strip_path": true}
```

- `backend_ssl: true` → proxy maakt HTTPS-verbinding met backend (certificaatcontrole uitgeschakeld voor interne hosts)
- `strip_path: true` → padprefix wordt gestript voor forwarding (`/pfsense/foo` → `/foo`)
- Als een hostnaam minstens één pad-route heeft, wordt TLS altijd getermineerd voor die hostnaam

## Config (config.json)

```json
{
  "listen_host": "0.0.0.0",
  "listen_ports": [8444],
  "tls_routes": {
    "voorbeeld.nl":          {"host": "192.168.1.10", "port": 8443, "name": "label",   "enabled": true, "backend_ssl": false, "strip_path": true},
    "voorbeeld.nl/subapp":   {"host": "192.168.1.20", "port": 443,  "name": "subapp",  "enabled": true, "backend_ssl": true,  "strip_path": true}
  },
  "connect_timeout": 10,
  "read_timeout": 5,
  "admin_host": "0.0.0.0",
  "admin_port": 8888,
  "tls_cert": "/pad/naar/cert.crt",
  "tls_key": "/pad/naar/cert.key"
}
```

`tls_cert` en `tls_key` zijn alleen nodig als er pad-routes zijn. Het certificaat op deze machine staat in `/home/admin/ClouDNS/MarcBudie.crt` (wildcard `*.budie.eu`, geldig t/m 25 okt 2026).

## Signalen

```bash
kill -HUP <pid>    # herlaad config.json zonder herstart
kill -TERM <pid>   # netjes stoppen
```

## Admin UI

Bereikbaar op `http://<host>:8888/`. Toont alle routes met een toggle om ze in/uit te schakelen. Pad-routes worden gemarkeerd met een "pad"-badge, HTTPS-backends met "HTTPS". Wijzigingen worden direct actief en opgeslagen in `config.json`.

## Bekende valkuilen

- `onchange`-attribuut in de admin UI gebruikt enkele aanhalingstekens — `JSON.stringify` geeft dubbele aanhalingstekens terug die het HTML-attribuut anders zouden breken.
- Admin poort is 8888 (8080 was al in gebruik op deze machine).
- TLS-terminatie via `ssl.MemoryBIO` — hierdoor kan de proxy de ClientHello lezen voor SNI-detectie én daarna alsnog de TLS-handshake uitvoeren.
