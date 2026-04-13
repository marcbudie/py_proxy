# py_proxy

Pure TCP SNI proxy — routeert HTTPS-verkeer op basis van de SNI-hostnaam zonder TLS te termineren. Verbindingen zonder geldig SNI worden direct verbroken.

## Bestanden

- `proxy.py` — de volledige proxy, één bestand, geen externe dependencies
- `config.json` — runtime configuratie (wordt live bijgehouden door de admin UI)
- `backup.sh` — sync naar Google Drive via rclone (`google:backup/py_proxy`)

## Starten

```bash
python3 proxy.py            # gebruikt config.json in de huidige map
python3 proxy.py pad/naar/config.json
```

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
    "voorbeeld.nl": {"host": "192.168.1.10", "port": 443, "name": "label", "enabled": true},
    "andere.nl": {
      "host": "192.168.1.11", "port": 443, "name": "label", "enabled": true,
      "tls_cert": "/pad/naar/andere.nl.crt",
      "tls_key": "/pad/naar/andere.nl.key"
    }
  },
  "connect_timeout": 10,
  "read_timeout": 5,
  "admin_host": "0.0.0.0",
  "admin_port": 8888,
  "tls_cert": "/pad/naar/wildcard.crt",
  "tls_key": "/pad/naar/wildcard.key"
}
```

Elke route stuurt verkeer voor dat hostname transparant door naar de opgegeven backend. TLS wordt niet getermineerd — het backend-certificaat blijft intact.

### Foutpagina bij uitgeschakelde routes

Als een route is uitgeschakeld, stuurt de proxy een HTML 503-pagina terug via TLS. Hiervoor moet een certificaat beschikbaar zijn dat de hostname dekt:

- **Globaal cert** (`tls_cert` / `tls_key` op topniveau) — geldt als fallback voor alle routes zonder eigen cert. Typisch een wildcard-certificaat.
- **Per-route cert** (`tls_cert` / `tls_key` op route-niveau) — overschrijft het globale cert voor die specifieke route. Gebruik dit voor domeinen die niet door het wildcard-cert gedekt worden.

Is er geen geldig cert beschikbaar voor een uitgeschakelde route, dan wordt de verbinding stilletjes gesloten.

## Signalen

```bash
kill -HUP <pid>    # herlaad config.json zonder herstart
kill -TERM <pid>   # netjes stoppen
```

## Admin UI

Bereikbaar op `http://<host>:8888/`. Functionaliteit:

- **Aan/uit toggle** per route — direct actief, opgeslagen in `config.json`
- **Verwijderen** per route — met bevestigingsdialoog
- **Toevoegen** via formulier onderaan — velden: hostname, backend host, poort, label

Wijzigingen worden direct actief en opgeslagen in `config.json` zonder herstart.

### API-endpoints

| Methode | Pad | Omschrijving |
|---------|-----|--------------|
| GET | `/api/routes` | Lijst van alle routes |
| POST | `/api/routes` | Nieuwe route toevoegen (JSON body: `hostname`, `host`, `port`, `name`) |
| POST | `/api/routes/<hostname>/toggle` | Route aan/uit schakelen |
| DELETE | `/api/routes/<hostname>` | Route verwijderen |

## Bekende valkuilen

- Admin poort is 8888 (8080 was al in gebruik op deze machine).
- `onchange`-attribuut in de admin UI gebruikt enkele aanhalingstekens — `JSON.stringify` geeft dubbele aanhalingstekens terug die het HTML-attribuut anders zouden breken.
- Pad-gebaseerde routing (hostname + pad) is geprobeerd maar werkt niet betrouwbaar voor applicaties zoals pfSense die URLs dynamisch opbouwen in JavaScript. Gebruik altijd een eigen subdomein per applicatie.
