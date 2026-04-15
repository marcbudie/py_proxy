# py_proxy

Pure TCP SNI proxy — routeert HTTPS-verkeer op basis van de SNI-hostnaam zonder TLS te termineren. Verbindingen zonder geldig SNI worden direct verbroken.

## Bestanden

- `proxy.py` — de volledige proxy, één bestand, geen externe dependencies
- `config.json` — runtime configuratie (wordt live bijgehouden door de admin UI, **niet in git** vanwege Gmail app-wachtwoord)
- `requirements.txt` — leeg (alles stdlib); aanwezig voor consistentie
- `run.sh` — start de proxy direct vanuit de venv (voor handmatig testen)
- `proxy.service` — systemd service unit
- `install.sh` — maakt venv aan en installeert/herstart de systemd service
- `backup.sh` — sync naar Google Drive via rclone (`google:backup/py_proxy`)

## Installeren en starten

### Via systemd + venv (aanbevolen)

```bash
sudo bash install.sh   # maakt venv aan, installeert en start systemd service
```

De service heet `py-proxy`. Handige commando's:

```bash
systemctl status  py-proxy        # status bekijken
journalctl -u py-proxy -f         # logs volgen
systemctl reload  py-proxy        # config herladen (SIGHUP)
systemctl restart py-proxy        # herstarten na nieuwe versie
```

Na een wijziging van `proxy.py` is alleen `systemctl restart py-proxy` nodig.  
`sudo bash install.sh` opnieuw uitvoeren is alleen nodig bij een nieuwe checkout of als `requirements.txt` verandert.

### Direct (ontwikkeling)

```bash
bash run.sh                        # via venv
python3 proxy.py                   # of direct, gebruikt config.json in huidige map
python3 proxy.py pad/naar/config.json
```

## Poorten

| Poort | Functie |
|-------|---------|
| 8444  | TLS SNI proxy (inkomend HTTPS-verkeer) |
| 9443  | Admin web UI (`https://<host>:9443/`) — HTTPS met OTP-authenticatie |
| variabel | TCP routes — willekeurige poorten gedefinieerd in `tcp_routes` |

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
  "tcp_routes": {
    "2222": {"host": "192.168.1.10", "port": 22, "name": "ssh", "enabled": true}
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
  },
  "telegram": {
    "bot_token": "123456:ABC...",
    "allowed_chat_ids": [123456789]
  }
}
```

Elke TLS route stuurt verkeer voor dat hostname transparant door naar de opgegeven backend. TLS wordt niet getermineerd — het backend-certificaat blijft intact.

### TCP routes

`tcp_routes` zijn voor plain TCP-verkeer zonder TLS (bijv. SSH, RDP). De sleutel is het poortnummer waarop de proxy luistert (als string); het verkeer wordt ongewijzigd doorgestuurd naar de backend. Er is geen SNI-inspectie — elke verbinding op die poort gaat naar de geconfigureerde backend.

Uitgeschakelde TCP routes laten de verbinding direct vallen (geen foutpagina mogelijk zonder TLS).

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

- **Aan/uit toggle** per TLS route en per TCP route — direct actief, opgeslagen in `config.json`
- **Verwijderen** per TLS route — met bevestigingsdialoog
- **Toevoegen** TLS route via formulier onderaan — velden: hostname, backend host, poort, label
- Aparte TCP routes sectie met toggle per route

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
| GET | `/api/routes` | Lijst van alle TLS routes |
| POST | `/api/routes` | Nieuwe TLS route toevoegen (JSON body: `hostname`, `host`, `port`, `name`) |
| POST | `/api/routes/<hostname>/toggle` | TLS route aan/uit schakelen |
| DELETE | `/api/routes/<hostname>` | TLS route verwijderen |
| GET | `/api/tcp-routes` | Lijst van alle TCP routes |
| POST | `/api/tcp-routes/<port>/toggle` | TCP route aan/uit schakelen |

## Telegram bot

De proxy bevat een ingebouwde Telegram bot die als asyncio-task naast de proxy draait — geen apart proces nodig.

### Configuratie

Voeg toe aan `config.json`:

```json
"telegram": {
  "bot_token": "123456:ABC...",
  "allowed_chat_ids": [123456789]
}
```

- `bot_token` — token van de BotFather
- `allowed_chat_ids` — lijst van toegestane chat-IDs (leeg = iedereen, niet aanbevolen)

Na het invullen: `systemctl reload py-proxy` (geen herstart nodig). Als het token wijzigt wordt de bot automatisch herstart bij reload.

### Commando's

| Commando | Omschrijving |
|---------|-------------|
| `/status` | Toont uptime, actieve verbindingen, alle routes met statistieken en toggle-knoppen |
| `/help` | Beschikbare commando's |

### Toggle-knoppen

Onder `/status` staat een inline-keyboard met één knop per route. Klikken togglet de route direct aan of uit — identiek aan de admin UI. Het bericht wordt daarna automatisch bijgewerkt met de nieuwe staat.

### Statistieken (runtime, gereset bij herstart)

Per TLS-route: aantal succesvolle verbindingen (`↗`) en geweigerd omdat de route uitgeschakeld was (`✗`).  
Per TCP-route: idem.  
Daarnaast: aantal verbindingen met onbekende SNI.

## Bekende valkuilen

- Admin poort is 9443 — HTTPS verplicht, proxy weigert te starten zonder geldig `tls_cert`/`tls_key`.
- `config.json` staat niet in git vanwege het Gmail app-wachtwoord en Telegram bot-token — na een verse checkout handmatig aanmaken.
- De admin UI gebruikt `Connection: keep-alive` met een `while True` loop zodat de TLS-verbinding open blijft na een response. Zonder keep-alive stuurt asyncio's SSL-transport een TCP RST als de browser's `close_notify` nog in de buffer zit.
- `onchange`-attribuut in de admin UI gebruikt enkele aanhalingstekens — `JSON.stringify` geeft dubbele aanhalingstekens terug die het HTML-attribuut anders zouden breken.
- Pad-gebaseerde routing (hostname + pad) is geprobeerd maar werkt niet betrouwbaar voor applicaties zoals pfSense die URLs dynamisch opbouwen in JavaScript. Gebruik altijd een eigen subdomein per applicatie.
- HTTP/2 connection coalescing: als twee domeinen hetzelfde wildcard-cert en IP-adres delen, hergebruikt de browser de TLS-verbinding. Geef zulke domeinen een eigen cert om dit te voorkomen.
