# DiaGO Backend (FastAPI + MongoDB)

Diagnostikos paslaugų backend'as su AI analize, Stripe mokėjimais ir
PDF ataskaitų generavimu.

## Paleidimas lokaliai

```bash
python -m venv venv
source venv/bin/activate      # arba: venv\Scripts\activate (Windows)
pip install -r requirements.txt

cp .env.example .env          # ir įrašykite savo API raktus
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

Reikalingi paslaugų raktai (į .env):
- `MONGO_URL` – jūsų MongoDB connection string
- `STRIPE_SECRET_KEY` + `STRIPE_PUBLISHABLE_KEY` – iš https://dashboard.stripe.com
- `EMERGENT_LLM_KEY` – AI integracijai (Claude / Gemini / OpenAI)
- `ADMIN_PASSWORD` – admin panelės slaptažodis

## Struktūra

- `server.py` – pagrindinis FastAPI entry point, visi /api/* maršrutai
- `pdf_report.py` – individualizuotas PDF ataskaitos generatorius
- `build_source_archive.py` / `build_deploy_archives.py` – source eksportas
- `tests/` – backend testai

## API maršrutai

Visi po prefiksu `/api/*` (kad atskirti nuo frontend'o). Pagrindiniai:
- `POST /api/sessions` – nauja diagnostikos sesija
- `POST /api/ai/scan-errors` – OBD2 klaidų skenavimas
- `GET /api/reports/{sid}.pdf` – PDF ataskaita
- `POST /api/support/chat` – AI pagalbos chat'as
- `POST /api/checkout/session` – Stripe mokėjimas
