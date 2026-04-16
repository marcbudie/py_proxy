# Security Audit Report — proxy.py

**Datum**: 2026-04-16  
**Methode**: Statische code-analyse van de volledige `proxy.py`  
**Auditor**: Claude (claude-sonnet-4-6)

---

## Overzicht

| Ernst    | Aantal |
|----------|--------|
| Critical | 1      |
| High     | 6      |
| Medium   | 8      |
| Low      | 8      |
| **Totaal** | **23** |

---

## Critical

### C1 — Telegram Mini App: iedereen geautoriseerd als whitelist leeg is
**Locatie:** ~regel 2124  
**Probleem:** `authorized` wordt als `True` geïnitialiseerd. Als `allowed_chat_ids` leeg is in de config, slaat de code de validatie over en is iedereen geautoriseerd voor de Mini App.

```python
authorized = True  # standaard True!
if allowed:
    ...validatie...
```

**Aanbeveling:** Zet `authorized = False` als default en vereis een expliciete whitelist:
```python
authorized = False
if allowed:
    ...validatie...
```

---

## High

### H1 — SNI parsing: geen bounds-check op extensie-lengte
**Locatie:** ~regel 310–322  
**Probleem:** Na het uitlezen van `ext_len` wordt `pos += ext_len` uitgevoerd zonder te controleren of `pos + ext_len <= len(data)`. Een kwaadaardig TLS ClientHello kan hierdoor een buffer overread veroorzaken.

```python
pos += ext_len  # pos kan buiten len(data) gaan
```

**Aanbeveling:** Voeg vóór de increment een check toe:
```python
if pos + ext_len > len(data):
    return None
pos += ext_len
```

---

### H2 — WebSocket: onbegrensde frame size → DoS
**Locatie:** ~regel 745  
**Probleem:** Bij een 127-byte length-indicator wordt de frame size uitgelezen als 64-bit integer (`>Q`), wat tot 2^63 bytes kan zijn. `reader.readexactly(length)` blokkeert dan de event loop.

```python
length = struct.unpack('>Q', await reader.readexactly(8))[0]  # tot 2^63 bytes
```

**Aanbeveling:**
```python
if length > 1_048_576:  # 1 MB max
    raise ValueError("WebSocket frame too large")
```

---

### H3 — TOTP secret opgeslagen als plaintext in config.json
**Locatie:** ~regel 2272  
**Probleem:** Het TOTP-geheim wordt onversleuteld geschreven naar `config.json`. Wie toegang heeft tot het bestand (of een backup) heeft daarmee direct toegang tot de authenticator.

**Aanbeveling:** Sla het TOTP-geheim op in een apart bestand met `chmod 600` en eigenaar `pyproxy`, buiten de reguliere config. Alternatief: versleutel het veld met een machine-specifieke sleutel.

---

### H4 — OTP rate limiting is globaal, niet per IP
**Locatie:** ~regel 2150–2155  
**Probleem:** `_last_code_ts` is één globale timestamp. Meerdere aanvallers kunnen parallel OTP-codes aanvragen en proberen vanaf verschillende verbindingen, zonder geblokkeerd te worden.

**Aanbeveling:** Vervang door een per-IP dictionary:
```python
_code_requests: dict[str, float] = {}  # ip → timestamp
```
Blokkeer per bron-IP, niet globaal.

---

### H5 — OTP slechts 6 cijfers (1 miljoen mogelijkheden)
**Locatie:** ~regel 465  
**Probleem:** Een 6-cijferige code biedt slechts 10^6 combinaties. Gecombineerd met een TTL van 5 minuten en beperkte rate limiting is brute-force haalbaar.

```python
code = f"{secrets.randbelow(1_000_000):06d}"
```

**Aanbeveling:** Verhoog naar 8 cijfers (`10_000_000`) of gebruik een alfanumerieke code van 8 tekens.

---

### H6 — Telegram /logs filtert geen gevoelige regels
**Locatie:** ~regel 2588–2602  
**Probleem:** Het `/logs` commando stuurt de laatste 30 regels van `journalctl` onge­filterd naar Telegram. Logregels kunnen wachtwoorden, tokens of sleutels bevatten als die ooit gelogd zijn.

**Aanbeveling:** Filter regels met gevoelige termen vóór verzending:
```python
SENSITIVE = re.compile(r'password|secret|token|key|passwd', re.IGNORECASE)
lines = [l for l in lines if not SENSITIVE.search(l)]
```

---

## Medium

### M1 — Config reload zonder lock (race condition)
**Locatie:** ~regel 2828–2844  
**Probleem:** `reload()` vervangt `self.cfg` zonder locking. In-flight requests kunnen een inconsistente mix van oud en nieuw config zien.

**Aanbeveling:** Gebruik een `asyncio.Lock` rond config-access, of maak de vervanging atomair via een lokale variabele die pas aan het eind wordt toegewezen.

---

### M2 — `_stats` dict: concurrent writes zonder locking
**Locatie:** ~regel 668  
**Probleem:** `_stats["tls_ok"][sni] = _stats["tls_ok"].get(sni, 0) + 1` is geen atomaire operatie. In asyncio is dit veilig zolang er geen `await` tussen zit, maar de structuur is fragiel.

**Aanbeveling:** Gebruik `collections.Counter` of een expliciete `asyncio.Lock` voor stats-updates.

---

### M3 — Sessiecookie wordt nooit geroteerd
**Locatie:** ~regel 2193  
**Probleem:** De sessiecookie is 30 minuten geldig en wordt nooit vervangen. Een gestolen cookie is voor de volledige resterende duur bruikbaar.

**Aanbeveling:** Genereer bij elke API-aanroep een nieuwe token en invalideer de oude (rolling sessions).

---

### M4 — CSRF: alleen SameSite=Strict, geen expliciet token
**Locatie:** ~regel 2139  
**Probleem:** SameSite=Strict biedt goede bescherming, maar er is geen CSRF-token als extra verdedigingslaag. Bij een toekomstige cookie-configuratiewijziging vervalt de enige bescherming.

**Aanbeveling:** Voeg een per-sessie CSRF-token toe dat in POST-bodies geverifieerd wordt.

---

### M5 — Terminal WebSocket: geen limiet op gelijktijdige sessies
**Locatie:** ~regel 2054–2070  
**Probleem:** Een geauthenticeerde gebruiker kan onbeperkt WebSocket-verbindingen openen naar `/term_sock`.

**Aanbeveling:** Begrens tot 1 actieve WebSocket per sessie via een global dict.

---

### M6 — Stack traces in productielogs
**Locatie:** ~regel 708  
**Probleem:** `logger.exception()` logt volledige tracebacks. In productie kunnen tracebacks interne paden, variabelenamen en gevoelige context lekken.

**Aanbeveling:** Gebruik `logger.error(f"{exc.__class__.__name__}: {exc}")` in productie, of beperk `logger.exception()` tot expliciete debug-modus.

---

### M7 — TLS private key: bestandspermissies niet gecontroleerd
**Locatie:** ~regel 2796  
**Probleem:** De private key wordt geladen zonder te controleren of het bestand voldoende beperkte rechten heeft (zou `0o600` moeten zijn).

**Aanbeveling:**
```python
mode = os.stat(key).st_mode & 0o177
if mode != 0o600:
    logger.warning(f"Private key {key} heeft brede permissies: {oct(mode)}")
```

---

### M8 — Session/OTP cleanup niet periodiek
**Locatie:** ~regel 433–440  
**Probleem:** `_cleanup_expired()` wordt alleen aangeroepen bij het genereren van een nieuwe OTP-code. Als dit lang niet gebeurt, groeien `_sessions` en `_otp_store` onbegrensd.

**Aanbeveling:** Roep cleanup aan in een achtergrondtaak die elke 60 seconden draait:
```python
asyncio.create_task(_periodic_cleanup())
```

---

## Low

### L1 — TOTP verificatie: timing-verschil in loop
**Locatie:** ~regel 525–548  
**Probleem:** De TOTP-verificatieloop breekt vroegtijdig af bij een match. Timing-verschil tussen early-exit en volledige iteratie kan informatie lekken over welk tijdvenster geldig is.

**Aanbeveling:** Bereken alle codes vooraf in een lijst en vergelijk constant-time over alle elementen.

---

### L2 — JSON body: geen expliciete maximum content-length
**Locatie:** ~regel 2041–2047  
**Probleem:** `read(min(content_length, 4096))` beperkt de read, maar een extreem grote `Content-Length` header wordt niet geweigerd met een 413-response.

**Aanbeveling:** Stuur HTTP 413 terug als `content_length > 65536`.

---

### L3 — `_totp_used_steps` groeit onbegrensd bij herhaald gebruik
**Locatie:** ~regel 540  
**Probleem:** Cleanup gebruikt een vaste marge van 10 stappen. Bij intensief gebruik of klok-afwijkingen kan de dict langzaam groeien.

**Aanbeveling:** Voeg een maximale grootte toe: als `len(_totp_used_steps) > 500`, verwijder alle entries ouder dan 1 uur.

---

### L4 — Telegram `init_data` parsing: losse JSON-validatie
**Locatie:** ~regel 2128–2129  
**Probleem:** `json.loads(params.get("user", "{}"))` wordt beschermd door een try/except, maar er is geen validatie op de structuur vooraf.

**Aanbeveling:** Controleer met regex of de string een JSON-object is vóór parsing: `if not user_str.startswith('{'): authorized = False`.

---

### L5 — HTML injection: inconsistente toepassing van `html.escape()`
**Locatie:** ~regel 417  
**Probleem:** Correct gebruik van `html.escape()` op SNI en admin_host, maar niet alle error-paden zijn geaudit op consistentie.

**Aanbeveling:** Zorg dat alle user-controlled strings in HTML-responses via `html.escape()` gaan.

---

### L6 — SNI hostname gelogd in plaintext
**Locatie:** ~regel 668  
**Probleem:** Volledige hostnamen worden gelogd, inclusief potentieel privé subdomeinen.

**Aanbeveling:** Overweeg hostnamen te hashen in logs, of maak verbose logging optioneel via een config-vlag.

---

### L7 — TOTP replay state: race condition bij simultane requests
**Locatie:** ~regel 535–543  
**Probleem:** Tussen de check `if first_use is None` en de write `_totp_used_steps[s] = now` zit geen atomaire garantie. Twee gelijktijdige verzoeken met dezelfde code kunnen beide slagen.

**Aanbeveling:** Gebruik `dict.setdefault()` voor atomaire insert-if-absent semantiek.

---

### L8 — Telegram polling timeout bij trage API
**Locatie:** ~regel 2972–2975  
**Probleem:** `timeout=30` in getUpdates betekent dat de bot 30 seconden kan blokkeren bij een trage Telegram API. Gecombineerd met een urllib timeout van 35 seconden kan dit de asyncio event loop beïnvloeden.

**Aanbeveling:** Voer de polling uit in een separate thread of gebruik een async HTTP client.

---

## Wat al correct is geïmplementeerd

- `secrets` module correct gebruikt voor OTP-codes, sessietokens en TOTP-secrets (geen `random`)
- `hmac.compare_digest()` gebruikt voor TOTP-vergelijking (timing-safe)
- Sessiecookie heeft `HttpOnly; Secure; SameSite=Strict`
- SNI-hostnamen worden lowercase genormaliseerd vóór routing
- TOTP replay-bescherming aanwezig via `_totp_used_steps`
- OTP-codes zijn eenmalig bruikbaar
- Admin UI is niet direct bereikbaar via de firewall (alleen via TLS SNI route)
- Verbindingen zonder geldig SNI worden direct verbroken

---

## Prioriteitenlijst

| Prio | Bevinding | Ernst |
|------|-----------|-------|
| 1 | C1 — Telegram whitelist default open | Critical |
| 2 | H1 — SNI buffer overread | High |
| 3 | H2 — WebSocket DoS | High |
| 4 | H4 — OTP rate limiting per IP | High |
| 5 | H6 — Telegram /logs filtert niet | High |
| 6 | H3 — TOTP secret plaintext | High |
| 7 | H5 — OTP 6 cijfers | High |
| 8 | M1 — Config reload race condition | Medium |
| 9 | M8 — Geen periodieke session cleanup | Medium |
| 10 | M3 — Geen sessie-rotatie | Medium |
