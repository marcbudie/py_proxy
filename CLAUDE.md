# py_proxy

Pure TCP SNI proxy — routeert HTTPS-verkeer op basis van de SNI-hostnaam zonder TLS te termineren. Verbindingen zonder geldig SNI worden direct verbroken.

## Bestanden

- `proxy.py` — de volledige proxy, één bestand, geen externe dependencies
- `config.json` — runtime configuratie (wordt live bijgehouden door de admin UI, **niet in git** vanwege Gmail app-wachtwoord)
- `Containerfile` — Podman/Docker container definitie
- `proxy.service` — systemd service unit
- `install.sh` — bouwt container en installeert/herstart de systemd service
- `backup.sh` — sync naar Google Drive via rclone (`google:backup/py_proxy`)

## Installeren en starten

### Via systemd + Podman (aanbevolen)

```bash
sudo bash install.sh   # bouwt container, installeert en start systemd service
```

De service heet `py-proxy`. Handige commando's:

```bash
systemctl status  py-proxy        # status bekijken
journalctl -u py-proxy -f         # logs volgen
systemctl reload  py-proxy        # config herladen (SIGHUP)
systemctl restart py-proxy        # herstarten na nieuwe versie
```

Voer `sudo bash install.sh` opnieuw uit na elke wijziging van `proxy.py`.

### Direct (ontwikkeling)

```bash
python3 proxy.py            # gebruikt config.json in de huidige map
python3 proxy.py pad/naar/config.json
```

## Poorten

| Poort | Functie |
|-------|---------|
| 8444  | TLS SNI proxy (inkomend HTTPS-verkeer) |
| 9443  | Admin web UI (`https://<host>:9443/`) — HTTPS met OTP-authenticatie |

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
  "admin_port": 9443,
  "tls_cert": "/pad/naar/wildcard.crt",
  "tls_key": "/pad/naar/wildcard.key",
  "email": {
    "gmail_user": "jouw@gmail.com",
    "gmail_app_password": "app-wachtwoord",
    "to": "jouw@gmail.com"
  }
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

Bereikbaar op `https://<host>:9443/`. Vereist inloggen via OTP-code (zie Authenticatie).

Functionaliteit:

- **Aan/uit toggle** per route — direct actief, opgeslagen in `config.json`
- **Verwijderen** per route — met bevestigingsdialoog
- **Toevoegen** via formulier onderaan — velden: hostname, backend host, poort, label

Wijzigingen worden direct actief en opgeslagen in `config.json` zonder herstart.

### Authenticatie

De admin UI gebruikt OTP-authenticatie via e-mail:

1. Bezoek `/login` — klik op "Stuur inlogcode"
2. Een eenmalige 6-cijferige code wordt gemaild naar het geconfigureerde `to`-adres
3. Vul de code in — bij succes wordt een sessiecookie gezet (geldig 30 minuten)
4. Uitloggen via de knop rechtsboven in de UI

**Limieten:** code is 5 minuten geldig en eenmalig bruikbaar; minimaal 60 seconden tussen aanvragen; na 10 foutieve pogingen wordt de code ongeldig gemaakt.

E-mail wordt verstuurd via Gmail SMTP met een app-wachtwoord (`gmail_user` + `gmail_app_password` in config.json).

### API-endpoints

| Methode | Pad | Omschrijving |
|---------|-----|--------------|
| GET | `/login` | Inlogpagina (HTML) |
| POST | `/api/auth/request-code` | Vraag OTP-code aan (verstuurt e-mail) |
| POST | `/api/auth/verify` | Verifieer OTP-code, ontvangt sessiecookie |
| POST | `/api/auth/logout` | Sessie beëindigen |
| GET | `/api/routes` | Lijst van alle routes |
| POST | `/api/routes` | Nieuwe route toevoegen (JSON body: `hostname`, `host`, `port`, `name`) |
| POST | `/api/routes/<hostname>/toggle` | Route aan/uit schakelen |
| DELETE | `/api/routes/<hostname>` | Route verwijderen |

## Bekende valkuilen

- Admin poort is 9443 — HTTPS verplicht, proxy weigert te starten zonder geldig `tls_cert`/`tls_key`.
- `config.json` staat niet in git vanwege het Gmail app-wachtwoord — na een verse checkout handmatig aanmaken.
- In de Podman container moet `config.json` **beschrijfbaar** gemount zijn (geen `:ro`), anders mislukt `save_config()` bij elke toggle/toevoeging en valt de verbinding weg.
- De admin UI gebruikt `Connection: keep-alive` met een `while True` loop zodat de TLS-verbinding open blijft na een response. Zonder keep-alive stuurt asyncio's SSL-transport een TCP RST als de browser's `close_notify` nog in de buffer zit.
- `onchange`-attribuut in de admin UI gebruikt enkele aanhalingstekens — `JSON.stringify` geeft dubbele aanhalingstekens terug die het HTML-attribuut anders zouden breken.
- Pad-gebaseerde routing (hostname + pad) is geprobeerd maar werkt niet betrouwbaar voor applicaties zoals pfSense die URLs dynamisch opbouwen in JavaScript. Gebruik altijd een eigen subdomein per applicatie.
- HTTP/2 connection coalescing: als twee domeinen hetzelfde wildcard-cert en IP-adres delen, hergebruikt de browser de TLS-verbinding. Geef zulke domeinen een eigen cert om dit te voorkomen.
