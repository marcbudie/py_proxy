# py_proxy

Pure TCP SNI proxy — routeert HTTPS-verkeer op basis van de SNI-hostnaam zonder TLS te termineren. Verbindingen zonder geldig SNI worden direct verbroken.

## Bestanden

- `proxy.py` — de volledige proxy, één bestand
- `config.json` — runtime configuratie (wordt live bijgehouden door de admin UI, **niet in git** vanwege Gmail app-wachtwoord)
- `requirements.txt` — één externe dependency: `segno` (QR-code generatie voor TOTP setup pagina)
- `Dockerfile` — container image op basis van `python:3.11-slim`
- `compose.yml` — handmatig starten van de container (ontwikkeling/testen); productie loopt via systemd
- `proxy-container.service` — systemd service unit voor de Podman container (draait als root)
- `run.sh` — start de proxy direct met `/usr/bin/python3` (voor handmatig testen, vanuit de checkout)
- `proxy.service` — systemd service unit (draait als `pyproxy` vanuit `/opt/py_proxy`)
- `install.sh` — interactief installatiescript voor systemd of Podman container
- `backup.sh` — sync naar Google Drive via rclone (`google:backup/py_proxy`)

## Installeren en updaten

Beide deploymethoden gebruiken hetzelfde script. Elke keer opnieuw uitvoeren installeert de nieuwste `proxy.py` en herstart de service — `config.json` wordt nooit overschreven.

```bash
sudo bash install.sh              # interactief: kies systemd of container
sudo bash install.sh --systemd   # altijd systemd
sudo bash install.sh --container # altijd Podman container
```

### Via Podman (container, beheerd door systemd)

`install.sh --container` doet:
1. `proxy.py`, `Dockerfile` en `requirements.txt` kopiëren naar `/opt/py_proxy/`
2. `/opt/py_proxy/config.json` klaarzetten (alleen als die nog niet bestaat)
3. Container image bouwen als root: `podman build -t py-proxy:latest /opt/py_proxy/`
4. `proxy-container.service` installeren als `py-proxy.service`
5. Service inschakelen en (her)starten

Systemd start de container via `podman run` als root. De container deelt het host-netwerk (`--network host`) — geen poortmapping nodig. Beheer loopt volledig via de bekende systemd-commando's:

```bash
systemctl status  py-proxy        # status bekijken
journalctl -u py-proxy -f         # logs volgen
systemctl reload  py-proxy        # config herladen (SIGHUP naar container)
systemctl restart py-proxy        # herstarten
systemctl stop    py-proxy        # stoppen
```

`proxy-container.service` montet `/opt/py_proxy/config.json` en `/home/admin/ssl` read-only in de container. Pas de volume-paden in het service-bestand aan als je certs ergens anders staan.

Het Telegram `/restart`-commando (`sudo systemctl restart py-proxy`) werkt in beide modi identiek.

### Via systemd

`install.sh --systemd` doet:
1. Systeemgebruiker `pyproxy` aanmaken (als die nog niet bestaat)
2. Python-dependencies installeren via `pip3 install --break-system-packages -r requirements.txt`
3. `proxy.py` kopiëren naar `/opt/py_proxy/`
4. `config.json` kopiëren naar `/opt/py_proxy/` (alleen als die er nog niet staat)
5. Eigenaar instellen op `pyproxy`, SELinux context herstellen via `restorecon`
6. Controleren of cert-bestanden leesbaar zijn voor `pyproxy`
7. Systemd service installeren en (her)starten

De service heet `py-proxy` en draait als `pyproxy` vanuit `/opt/py_proxy`. Handige commando's:

```bash
systemctl status  py-proxy        # status bekijken
journalctl -u py-proxy -f         # logs volgen
systemctl reload  py-proxy        # config herladen (SIGHUP)
systemctl restart py-proxy        # herstarten
```

#### Cert-bestanden toegankelijk maken voor pyproxy

De certs staan in `/home/admin/ssl/` en zijn world-readable, maar `/home/admin` zelf heeft geen traverse-rechten voor anderen. `install.sh` zet dit automatisch:

```bash
setfacl -m u:pyproxy:x /home/admin
```

`install.sh` controleert daarna of alle cert-bestanden leesbaar zijn en waarschuwt bij problemen.

#### Sudoers-regel voor Telegram /restart

De Telegram bot kan de service herstarten via `sudo systemctl restart py-proxy`. `install.sh` maakt hiervoor automatisch `/etc/sudoers.d/pyproxy-restart` aan:

```
pyproxy ALL=(root) NOPASSWD: /usr/bin/systemctl restart py-proxy
```

### Direct (ontwikkeling)

Vanuit de checkout in `/home/admin/py_proxy` — gebruikt de lokale `config.json`:

```bash
bash run.sh                        # met /usr/bin/python3
python3 proxy.py                   # of direct, gebruikt config.json in huidige map
python3 proxy.py pad/naar/config.json
```

## Netwerkarchitectuur

Alle inkomende verbindingen lopen via de firewall naar de proxy. De proxy beslist op basis van SNI (TLS) of poortnummer (TCP) waar het verkeer naartoe gaat.

```
Internet
  │
  ├─ :443  ──► proxy:8444  ──► SNI router ──► backend per hostname
  ├─ :2222 ──► proxy:2222  ──► tcp_route  ──► 192.168.2.76:22 (SSH)
  └─ :300  ──► proxy:3333  ──► tcp_route  ──► 192.168.2.76:300 (ThinLinc)
```

De admin UI (poort 9443) is niet direct open in de firewall — alleen bereikbaar via de TLS route `proxy.budie.eu` (SNI → poort 9443 op localhost).

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
    "2222": {"host": "192.168.1.10", "port": 22, "name": "ssh", "enabled": true,
             "auto_disable_minutes": 0}
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

Elke TLS route stuurt verkeer voor dat hostname transparant door naar de opgegeven backend. TLS wordt standaard niet getermineerd — het backend-certificaat blijft intact.

### TLS termineren voor HTTP backends

Voeg `"tls_terminate": true` toe aan een route als de backend plain HTTP draait (geen TLS):

```json
"mijnsite.nl": {
  "host": "192.168.1.10", "port": 80, "name": "mijnsite",
  "enabled": true, "tls_terminate": true
}
```

De proxy termineert dan TLS aan de client-kant (met het wildcard-cert of een per-route cert) en stuurt de gedecrypte HTTP bytes door naar de backend. De browser ziet gewoon HTTPS; de backend hoeft geen cert te hebben.

**Vereiste:** het hostname moet gedekt zijn door het globale wildcard-cert of een per-route `tls_cert`/`tls_key`.

**Host-header rewrite:** de proxy herschrijft automatisch de `Host`-header naar het backend-adres (bijv. `192.168.2.254` of `192.168.2.254:8080`). Dit is nodig omdat veel apparaten (routers, NAS, etc.) requests weigeren met een externe hostnaam in de Host-header.

**X-Forwarded-For:** de proxy voegt automatisch `X-Forwarded-For: <client-ip>` toe aan elk HTTP-request. Dit werkt ook bij HTTP/1.1 keep-alive verbindingen waarbij meerdere requests over dezelfde TLS-sessie lopen. De backend moet de header vertrouwen; bij uvicorn gaat dat via `--proxy-headers --forwarded-allow-ips 127.0.0.1`.

**Keep-alive / idle timeout:** verbindingen zonder activiteit worden na 30 seconden gesloten. Dit voorkomt dat trage of idle HTTP/1.1 keep-alive verbindingen de event loop belasten. Pagina's die veel resources laden (zoals Flutter web apps) openen tientallen gelijktijdige verbindingen — dit wordt correct afgehandeld.

In de admin UI staat bij "Route toevoegen" een checkbox "HTTP backend (TLS termineren)". Bestaande routes aanpassen: handmatig `"tls_terminate": true/false` in `config.json` zetten en daarna `systemctl reload py-proxy`.

### Auto-uitschakelen

Voeg `"auto_disable_minutes": N` toe aan een route om hem automatisch uit te schakelen N minuten nadat hij is ingeschakeld. `0` (standaard) betekent nooit automatisch uitschakelen.

```json
"tijdelijke.nl": {
  "host": "192.168.1.10", "port": 443, "name": "tijdelijk",
  "enabled": true, "auto_disable_minutes": 10
}
```

Werkt voor zowel TLS- als TCP-routes. De timer start op het moment van inschakelen (via toggle in de UI, Telegram of direct in config). De background task controleert elke 15 seconden; bij auto-uitschakelen wordt een Telegram-melding verstuurd (⏱ Auto-uitgeschakeld). De admin UI toont een oranje afteltimer per route en ververst de tabellen elke 15 seconden automatisch.

### Naam-gebaseerde groepering

Routes met dezelfde `name` worden als groep behandeld: als één route wordt aan- of uitgeschakeld, volgen alle andere routes (TLS én TCP) met dezelfde naam automatisch. Dit werkt via de admin UI, Telegram-toggles en de auto-disable timer.

```json
"thinlinc.budie.eu": {"host": "192.168.2.76", "port": 300, "name": "thinlinc-web", ...},
"tcp_routes": {
  "3333": {"host": "192.168.2.76", "port": 300, "name": "thinlinc-web", ...}
}
```

Elke route berekent zijn eigen `enabled_until` op basis van zijn eigen `auto_disable_minutes` — de timer-instellingen per route blijven onafhankelijk.

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

- **Aan/uit toggle** per TLS route en per TCP route — direct actief, opgeslagen in `config.json`; routes met dezelfde `name` volgen automatisch mee (zie [Naam-gebaseerde groepering](#naam-gebaseerde-groepering))
- **Verwijderen** per TLS route — met bevestigingsdialoog
- **Toevoegen** TLS route via formulier onderaan — velden: hostname, backend host, poort, label, checkbox "HTTP backend (TLS termineren)"
- Aparte TCP routes sectie met toggle per route

Wijzigingen worden direct actief en opgeslagen in `config.json` zonder herstart.

### Authenticatie

De admin UI ondersteunt twee methoden:

#### TOTP (aanbevolen — Google Authenticator, Authy, Bitwarden)

1. Ga naar `/totp-setup` (vereist een actieve sessie — stel dus eerst in via legacy OTP)
2. Kopieer het geheim en voeg het toe aan je authenticator-app
3. Verifieer met een code uit de app — bij succes wordt `totp_secret` opgeslagen in `config.json`
4. Daarna toont `/login` direct een invoerveld voor de TOTP-code (geen e-mail/Telegram meer)

Bij succesvolle TOTP-inlog wordt een Telegram-melding verstuurd. Het geheim is 20 bytes (160 bits), base32 gecodeerd. Replay-aanvallen worden geblokkeerd via een set van gebruikte time-steps.

TOTP uitschakelen: dashboard → "Authenticatie: Uitschakelen" — valt terug op e-mail/Telegram OTP.

#### Legacy OTP (fallback als TOTP niet actief is)

1. Bezoek `/login` — klik op "Stuur inlogcode"
2. Een eenmalige 8-cijferige code wordt verstuurd via e-mail en/of Telegram
3. Vul de code in — bij succes wordt een sessiecookie gezet (geldig 30 minuten)

**Limieten:** code is 5 minuten geldig en eenmalig bruikbaar; minimaal 60 seconden tussen aanvragen per IP-adres; na 10 foutieve pogingen wordt de code ongeldig gemaakt.

#### Sessiecookie

`proxy_session`; `HttpOnly; Secure; SameSite=Strict`; sliding expiry van 30 minuten (elke geauthenticeerde request verlengt de TTL — na 30 minuten inactiviteit wordt de sessie ongeldig).

### API-endpoints

| Methode | Pad | Omschrijving |
|---------|-----|--------------|
| GET | `/login` | Inlogpagina (HTML) — toont TOTP- of legacy OTP-formulier |
| POST | `/api/auth/request-code` | Vraag legacy OTP-code aan (e-mail en/of Telegram) |
| POST | `/api/auth/verify` | Verifieer legacy OTP-code, ontvangt sessiecookie |
| POST | `/api/auth/verify-totp` | Verifieer TOTP-code, ontvangt sessiecookie |
| POST | `/api/auth/logout` | Sessie beëindigen |
| GET | `/totp-setup` | TOTP setup pagina (sessie vereist) |
| GET | `/api/totp/new-secret` | Genereer nieuw TOTP-geheim (sessie vereist) |
| POST | `/api/totp/enable` | Activeer TOTP na verificatie (body: `secret`, `code`) |
| POST | `/api/totp/disable` | Deactiveer TOTP, valt terug op legacy OTP |
| GET | `/api/totp/status` | Geeft `{"enabled": bool}` |
| GET | `/api/routes` | Lijst van alle TLS routes |
| POST | `/api/routes` | Nieuwe TLS route toevoegen (JSON body: `hostname`, `host`, `port`, `name`, optioneel `tls_terminate`) |
| POST | `/api/routes/<hostname>/toggle` | TLS route aan/uit schakelen |
| POST | `/api/routes/<hostname>/auto-disable` | Auto-uitschakelen instellen (body: `{"minutes": N}`) |
| DELETE | `/api/routes/<hostname>` | TLS route verwijderen |
| GET | `/api/tcp-routes` | Lijst van alle TCP routes |
| POST | `/api/tcp-routes/<port>/toggle` | TCP route aan/uit schakelen |
| POST | `/api/tcp-routes/<port>/auto-disable` | Auto-uitschakelen instellen (body: `{"minutes": N}`) |

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
- `allowed_chat_ids` — lijst van toegestane chat-IDs (**leeg = niemand toegestaan** voor de Mini App; voor de bot zelf geen effect)

Na het invullen: `systemctl reload py-proxy` (geen herstart nodig). Als het token wijzigt wordt de bot automatisch herstart bij reload.

### Commando's

| Commando | Omschrijving |
|---------|-------------|
| `/status`    | Uptime, actieve verbindingen, statistieken per route + toggle-knoppen |
| `/cert`      | Vervaldatums van alle geconfigureerde certificaten (🟢/🟡/🔴) |
| `/logs`      | Laatste 30 logregels uit journald |
| `/reload`    | Config herladen zonder herstart (zelfde als `systemctl reload`) |
| `/restart`   | Service herstarten (`systemctl restart py-proxy`) |
| `/clear`     | Verbindingstellers resetten (runtime statistieken, gereset bij herstart) |
| `/proxyaan`  | Route `proxy.budie.eu` inschakelen — bruikbaar als de TLS route uit staat en de admin UI onbereikbaar is |
| `/proxyuit`  | Route `proxy.budie.eu` uitschakelen |
| `/help`      | Beschikbare commando's |

### Toggle-knoppen

Onder `/status` staat een inline-keyboard met één knop per route. Klikken togglet de route direct aan of uit — identiek aan de admin UI. Het bericht wordt daarna automatisch bijgewerkt.

### Proactieve meldingen

| Melding | Wanneer |
|---------|---------|
| 🟢 Proxy gestart | Bij elke (her)start van de service |
| ⚠️ Backend onbereikbaar | Bij connect timeout of OS-fout (max 1× per 5 min per backend) |
| 🔔 Verbinding | Bij elke verbinding op routes met `"notify": true` in config.json |
| 📊 Dagelijkse samenvatting | Elke dag om 08:00 UTC |
| ⚠️ Cert verloopt binnenkort | Dagelijks als een cert binnen 30 dagen (🟡) of 14 dagen (🔴) verloopt |

### Statistieken (runtime, gereset bij herstart)

Per TLS-route: aantal succesvolle verbindingen en geweigerd (route uitgeschakeld).  
Per TCP-route: idem. Daarnaast: aantal verbindingen met onbekende SNI.

## Beveiliging

### Systeem- en procesisolatie

- **Dedicated systeemgebruiker** — de service draait als `pyproxy` (geen login shell, geen home dir) vanuit `/opt/py_proxy`. Dit beperkt de blast radius bij een eventuele kwetsbaarheid.
- **SELinux-vriendelijk deploy** — bestanden in `/opt` krijgen `usr_t` context na `restorecon`; systemd kan deze uitvoeren. Bestanden in `$HOME` met `user_home_t` worden geblokkeerd.
- **Sudoers strikt begrensd** — `pyproxy` mag uitsluitend `sudo systemctl restart py-proxy` uitvoeren; geen andere escalatiemogelijkheden.
- **config.json niet in git** — bevat Gmail app-wachtwoord, Telegram bot-token en TOTP-geheim. Nooit committen. Op het systeem alleen leesbaar als root.
- **TOTP-geheim backup** — sla het geheim op bij het instellen. Zonder backup én zonder werkende e-mail/Telegram-fallback ben je buitengesloten als je de authenticator-app kwijtraakt.

### Netwerk en toegangscontrole

- **Admin UI niet direct bereikbaar** — poort 9443 staat niet open in de firewall; de UI is alleen bereikbaar via de TLS route `proxy.budie.eu` (SNI → localhost:9443).
- **Admin UI vereist HTTPS** — de proxy weigert te starten zonder geldig `tls_cert`/`tls_key`; plaintext HTTP is niet mogelijk.
- **SNI-validatie** — verbindingen zonder geldig SNI-veld in de ClientHello worden direct verbroken; de proxy routeert nooit blindweg.
- **Uitgeschakelde routes** — TCP routes laten de verbinding direct vallen; TLS routes sturen een 503-pagina terug als er een cert beschikbaar is, anders stille sluiting.
- **FreeCourts firewall-regel** (8444→8443) — omzeilt de proxy volledig. Nu disabled; niet inschakelen tenzij bewust gewenst.

### TLS en certificaten

- **TLS private key permissiecheck** — bij elke start logt de proxy een waarschuwing als een key-bestand ruimere permissies heeft dan `0o600`.
- **TLS handshake timeout** — 10 seconden; hangende handshakes worden afgebroken.
- **Idle connection timeout** (TLS-terminatie modus) — verbindingen zonder activiteit worden na 30 seconden gesloten; voorkomt event-loop-vervuiling door idle keep-alive sessies.
- **SMTP via SSL/TLS** — OTP-e-mails worden verstuurd via `SMTP_SSL` (versleuteld kanaal); het Gmail app-wachtwoord gaat nooit plaintext over het netwerk.

### Authenticatie en sessies

Zie ook de volledige beschrijving onder [Authenticatie](#authenticatie).

- **TOTP geheimgeneratie** — `secrets.token_bytes(20)` (160 bits); cryptografisch veilig, niet voorspelbaar.
- **Constante-tijd vergelijking** — TOTP-codes worden vergeleken met `hmac.compare_digest()` om timing-aanvallen te voorkomen.
- **TOTP replay-bescherming** — gebruikte time-steps worden bijgehouden in `_totp_used_steps`; hergebruik van een code binnen hetzelfde venster wordt geblokkeerd.
- **OTP willekeurigheid** — 8-cijferige codes gegenereerd met `secrets.randbelow()`; niet met `random`.
- **OTP rate limiting** — minimaal 60 seconden tussen aanvragen, gehandhaafd per IP-adres; bij overschrijding HTTP 429.
- **OTP brute force-bescherming** — na 10 foutieve verificatiepogingen wordt de openstaande code ongeldig gemaakt.
- **Sessiecookie flags** — `proxy_session` heeft `HttpOnly; Secure; SameSite=Strict`; JavaScript kan de cookie niet uitlezen en cross-site requests sturen de cookie niet mee (CSRF-bescherming zonder apart token).
- **Sliding window expiry** — elke geauthenticeerde request verlengt de sessie-TTL met 30 minuten; na 30 minuten inactiviteit vervalt de sessie automatisch.
- **Sessie cleanup** — verlopen sessies en OTP-codes worden elke 60 seconden opgeruimd.

### Telegram-beveiliging

- **Outbound long-polling** — de bot werkt puur via uitgaande HTTPS-verbindingen naar de Telegram API; er is geen inkomende poort of webhook nodig.
- **WebApp initData-validatie** — de Mini App stuurt een HMAC-SHA256 gesigneerde `initData`; de proxy verifieert de handtekening met een sleutel afgeleid van het bot-token.
- **auth_date tijdvenster** — `initData` ouder dan 24 uur wordt geweigerd; dit beperkt de herbruikbaarheid van onderschepte tokens.
- **allowed_chat_ids gehandhaafd op alle handlers** — zowel bot-commando's, callback queries als WebApp-requests worden geweigerd als de chat-ID niet in de allowlist staat. Een lege lijst sluit iedereen buiten.
- **Gevoelige data gefilterd in /logs** — regels met `password`, `secret`, `token` of `key` worden verwijderd vóór verzending naar Telegram.

### Input-validatie en XSS-preventie

- **html.escape() op foutpagina's** — de SNI-hostnaam en het admin-adres worden ge-escaped vóór opname in HTML-responses; voorkomt reflected XSS.
- **JSON-parsing met validatie** — alle API-endpoints parsen de body in een try/except en retourneren HTTP 400 bij malformed JSON of ontbrekende velden.
- **TOTP secret-validatie** — het geheim wordt base32-gedecodeerd vóór opslag; ongeldige geheimen worden geweigerd.

### Request- en verbindingstimeouts (admin UI)

| Fase | Timeout |
|------|---------|
| Request-regel lezen | 30 seconden |
| Headers lezen | 10 seconden per regel |
| Body lezen | 10 seconden |
| Backend connect | configureerbaar, standaard 10 s |
| Backend read | configureerbaar, standaard 5 s |
| TLS handshake | 10 seconden |
| Idle (TLS-terminatie) | 30 seconden |

## Bekende valkuilen

- De service draait als `pyproxy` vanuit `/opt/py_proxy`. Op SELinux-systemen (RHEL/AlmaLinux) blokkeert SELinux het uitvoeren van bestanden met `user_home_t` context vanuit systemd. Door te deployen naar `/opt` krijgen bestanden `usr_t` context na `restorecon` — dit werkt wel.
- Cert-bestanden in `/home/admin/ssl/` zijn standaard niet leesbaar voor `pyproxy` — zie de `setfacl`-commando's in de installatiesectie.
- Admin poort is 9443 — HTTPS verplicht, proxy weigert te starten zonder geldig `tls_cert`/`tls_key`.
- `config.json` staat niet in git vanwege het Gmail app-wachtwoord en Telegram bot-token — na een verse checkout handmatig aanmaken.
- De admin UI gebruikt `Connection: keep-alive` met een `while True` loop zodat de TLS-verbinding open blijft na een response. Zonder keep-alive stuurt asyncio's SSL-transport een TCP RST als de browser's `close_notify` nog in de buffer zit.
- `onchange`-attribuut in de admin UI gebruikt enkele aanhalingstekens — `JSON.stringify` geeft dubbele aanhalingstekens terug die het HTML-attribuut anders zouden breken.
- Pad-gebaseerde routing (hostname + pad) is geprobeerd maar werkt niet betrouwbaar voor applicaties zoals pfSense die URLs dynamisch opbouwen in JavaScript. Gebruik altijd een eigen subdomein per applicatie.
- HTTP/2 connection coalescing: als twee domeinen hetzelfde wildcard-cert en IP-adres delen, hergebruikt de browser de TLS-verbinding. Geef zulke domeinen een eigen cert om dit te voorkomen.
- Bij containerdeployment werkt het Telegram `/restart`-commando niet (roept `systemctl` aan). Gebruik `podman compose restart py-proxy` als handmatige fallback.
- Bij containerdeployment werkt `/logs` (leest journald) mogelijk niet als journald niet beschikbaar is in de container. Gebruik `docker compose logs` in dat geval.
