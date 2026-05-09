# DiaGO Backend (v2.0)

Savarankiškas FastAPI serveris su:
- 🤖 AI pokalbių asistentu (Claude Haiku 4.5)
- 🔍 Klaidos kodų analizatoriumi (Claude Sonnet 4.5)
- 📊 Anonimiška analitika (MongoDB)
- 💬 Atsiliepimų sistema
- 🔐 Admin panele su statistika ir kainų valdymu

## Reikalingi env kintamieji (Render → Environment)

| Pavadinimas | Privaloma | Reikšmė |
|---|---|---|
| `EMERGENT_LLM_KEY` | ✅ TAIP | Emergent universalus LLM raktas |
| `MONGODB_URI` | ⚠️ Privaloma analitikai | MongoDB Atlas connection string |
| `MONGODB_DB` | Neprivaloma | DB pavadinimas (default: `diago`) |
| `ADMIN_EMAIL` | ✅ TAIP | Admin el. paštas (pvz., `info@diago.lt`) |
| `ADMIN_PASSWORD` | ✅ TAIP | Admin slaptažodis (paprastu tekstu, mes patys hash'inam) |
| `JWT_SECRET` | ✅ TAIP | Atsitiktinė ilga eilutė admin sesijai |

## MongoDB Atlas paruošimas (5 min, nemokama)

1. Eikite į https://www.mongodb.com/cloud/atlas/register
2. Užsiregistruokite (galima per Google)
3. Pasirinkite **M0 Free** planą
4. Provider: **AWS**, Region: **Frankfurt (eu-central-1)** (arčiausiai LT)
5. Cluster pavadinimas: `diago-cluster`
6. Saugumas → **Database Access** → Add User:
   - Username: `diago_app`
   - Password: sugeneruokite stiprų (išsaugokite!)
   - Role: `Read and write to any database`
7. Saugumas → **Network Access** → Add IP Address → **0.0.0.0/0** (Allow from anywhere – Render naudoja dinaminius IP)
8. **Connect** → **Drivers** → nukopijuokite connection string:
   ```
   mongodb+srv://diago_app:<password>@diago-cluster.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
9. **Pakeiskite `<password>`** į savo slaptažodį
10. Pridėkite į Render env: `MONGODB_URI=<jūsų-string>`

## Render env atnaujinimas (po jau veikiančio deploymento)

1. Render Dashboard → Jūsų service → **Environment**
2. Pridėkite naujus kintamuosius (žr. lentelę aukščiau)
3. **Save** → Render automatiškai per-deploy'ins
4. Patikrinkite logus → turi rodyti `✅ MongoDB prisijungta.`

## Lokalus paleidimas (testavimui)

```bash
pip install -r requirements.txt
export EMERGENT_LLM_KEY=...
export MONGODB_URI=...
export ADMIN_EMAIL=info@diago.lt
export ADMIN_PASSWORD=keisk_si_slaptazodi
export JWT_SECRET=$(openssl rand -hex 32)
uvicorn server:app --host 0.0.0.0 --port 8000
```

## API endpoint'ai

### Vieši
- `GET /api/health` – sveikatos patikra
- `POST /api/chat` – pokalbis su DiaGO konsultantu
- `POST /api/check-error` – klaidos kodo analizė
- `POST /api/track/visit` – anoniminis lankomumo žymėjimas
- `POST /api/feedback` – atsiliepimas (👍/👎 + komentaras)
- `GET /api/pricing` – matomi (enabled) kainų planai

### Admin (reikia Bearer token)
- `POST /api/admin/login` – admin prisijungimas
- `GET /api/admin/stats` – bendra statistika
- `GET /api/admin/error-codes` – TOP klaidos kodai
- `GET /api/admin/error-checks-recent` – paskutiniai 50 patikrinimų
- `GET /api/admin/feedbacks` – atsiliepimai
- `GET /api/admin/pricing` – kainų valdymas
- `PUT /api/admin/pricing` – kainos atnaujinimas

## DB kolekcijos

| Kolekcija | Aprašymas |
|---|---|
| `visits` | Anonimiški lankomumo įrašai (visitor_id + data + page) |
| `error_checks` | Klaidos patikrinimai (kodas, technika, automobilis) |
| `chat_events` | Pokalbio eventai (tik metaduomenys, NE turinys) |
| `feedbacks` | Vartotojų atsiliepimai |
| `pricing` | Kainų konfigūracija |

## Privatumas (GDPR)

✅ **NESAUGOM:** IP adresų, vartotojo vardo, naršyklės info, asmens duomenų
✅ **SAUGOM:** Anoniminį `visitor_id` (atsitiktinis cookie kliento naršyklėje)

Jei norite ištrinti visus duomenis – ištrinkite kolekcijas MongoDB Atlas UI.
