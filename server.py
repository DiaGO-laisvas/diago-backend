"""
DiaGO backend – savarankiškas FastAPI serveris.
Skirtas talpinti Render.com / Railway / VPS / kt.

Reikalingi env kintamieji:
  EMERGENT_LLM_KEY      - Emergent universalus LLM raktas (su kreditais)
  MONGODB_URI           - MongoDB Atlas connection string (privaloma analitikai)
  MONGODB_DB            - DB pavadinimas (default: diago)
  ADMIN_EMAIL           - Admin el. paštas (default: info@diago.lt)
  ADMIN_PASSWORD        - Admin slaptažodis paprastu tekstu (bus paverstas hash'u)
  JWT_SECRET            - Bet kokia ilga atsitiktinė eilutė admin sesijai

Vietinis paleidimas:
  pip install -r requirements.txt
  uvicorn server:app --host 0.0.0.0 --port 8000

Render.com automatinio paleidimo komanda:
  uvicorn server:app --host 0.0.0.0 --port $PORT
"""
import os
import re
import hmac
import json
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from urllib.parse import quote_plus

from fastapi import FastAPI, APIRouter, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from emergentintegrations.llm.chat import LlmChat, UserMessage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================
# In-memory session history
# ============================
_sessions: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

# ============================
# MongoDB
# ============================
_mongo_client = None
_db = None

def _get_db():
    """Lazy MongoDB klientas. Grąžina None, jei MONGODB_URI nenustatytas."""
    global _mongo_client, _db
    if _db is not None:
        return _db
    uri = os.environ.get("MONGODB_URI", "").strip()
    if not uri:
        logger.warning("⚠️  MONGODB_URI nenustatytas – analitika neveiks (in-memory).")
        return None
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        _mongo_client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
        _db = _mongo_client[os.environ.get("MONGODB_DB", "diago")]
        logger.info("✅ MongoDB prisijungta.")
        return _db
    except Exception as e:
        logger.exception(f"MongoDB prisijungimas nepavyko: {e}")
        return None


# ============================
# Admin auth (paprastas JWT-pavidalo HMAC token)
# ============================
def _hash_password(pw: str) -> str:
    salt = "diago-fixed-salt-v1"  # Statinis salt – paprastumui (vienam admin'ui pakanka)
    return hashlib.sha256((salt + pw).encode("utf-8")).hexdigest()

def _admin_check_password(pw: str) -> bool:
    expected = os.environ.get("ADMIN_PASSWORD", "")
    if not expected:
        return False
    return hmac.compare_digest(_hash_password(pw), _hash_password(expected))

def _make_admin_token(email: str) -> str:
    secret = os.environ.get("JWT_SECRET", "diago-default-secret-change-me")
    exp = int((datetime.now(timezone.utc) + timedelta(hours=12)).timestamp())
    payload = json.dumps({"email": email, "exp": exp}, separators=(",", ":"))
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    import base64
    p64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"{p64}.{sig}"

def _verify_admin_token(token: str) -> dict | None:
    if not token:
        return None
    try:
        import base64
        p64, sig = token.split(".", 1)
        secret = os.environ.get("JWT_SECRET", "diago-default-secret-change-me")
        # restore padding
        padded = p64 + "=" * (-len(p64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded.encode())
        expected_sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(payload_bytes.decode())
        if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return payload
    except Exception:
        return None


def _require_admin(authorization: str | None) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Reikalingas admin prisijungimas.")
    token = authorization.split(" ", 1)[1].strip()
    payload = _verify_admin_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sesija pasibaigė arba neteisingas žetonas.")
    return payload


# ============================
# FastAPI setup
# ============================
app = FastAPI(title="DiaGO API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
api_router = APIRouter(prefix="/api")

# ============================
# Health
# ============================
@api_router.get("/")
async def root():
    return {"service": "DiaGO API", "status": "ok", "version": "2.0.0"}

@api_router.get("/health")
async def health():
    uri = os.environ.get("MONGODB_URI", "").strip()
    if not uri:
        return {"status": "ok", "db": "no_uri", "hint": "MONGODB_URI nenustatytas."}

    # 1. Patikrinam ar motor įdiegtas
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
    except ImportError as e:
        return {
            "status": "ok",
            "db": "no_motor_lib",
            "error": str(e),
            "hint": "motor biblioteka neįdiegta. Patikrinkite requirements.txt ir Build Command Render'e.",
        }

    # 2. Bandom prisijungti realiai (su timeout)
    try:
        client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
        db_name = os.environ.get("MONGODB_DB", "diago")
        db = client[db_name]
        result = await db.command("ping")
        collections = await db.list_collection_names()
        # Cache for future calls
        global _mongo_client, _db
        _mongo_client = client
        _db = db
        return {
            "status": "ok",
            "db": "connected",
            "ping": result,
            "collections": collections,
            "db_name": db_name,
        }
    except Exception as e:
        return {
            "status": "ok",
            "db": "error",
            "error_type": type(e).__name__,
            "error": str(e)[:400],
            "hint": "Patikrinkite slaptažodį ir MongoDB Atlas Network Access.",
        }


# ============================
# ANALYTICS - Visit tracking
# ============================
class VisitRequest(BaseModel):
    visitor_id: str  # anoniminis cookie ID iš naršyklės
    page: str = "index"  # "index" arba "klaidos"

@api_router.post("/track/visit")
async def track_visit(req: VisitRequest):
    """Anoniminis lankomumo žymėjimas. Renkam TIK: visitor_id (atsitiktinis cookie), puslapį, datą."""
    db = _get_db()
    if db is None:
        return {"ok": True, "stored": False}
    try:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        # Unikalūs lankytojai per dieną (upsert)
        await db.visits.update_one(
            {"visitor_id": req.visitor_id, "date": today, "page": req.page},
            {
                "$setOnInsert": {
                    "visitor_id": req.visitor_id,
                    "date": today,
                    "page": req.page,
                    "first_seen": datetime.now(timezone.utc),
                },
                "$inc": {"hits": 1},
                "$set": {"last_seen": datetime.now(timezone.utc)},
            },
            upsert=True,
        )
        return {"ok": True, "stored": True}
    except Exception as e:
        logger.exception(f"track_visit failed: {e}")
        return {"ok": True, "stored": False}


# ============================
# FEEDBACK
# ============================
class FeedbackRequest(BaseModel):
    session_id: str
    error_code: str | None = None
    rating: str  # "up" arba "down"
    comment: str | None = None

@api_router.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    if req.rating not in ("up", "down"):
        raise HTTPException(status_code=400, detail="Neteisingas įvertinimas.")
    if req.comment and len(req.comment) > 1000:
        raise HTTPException(status_code=400, detail="Komentaras per ilgas (max 1000 simb.).")
    db = _get_db()
    if db is None:
        return {"ok": True, "stored": False}
    try:
        await db.feedbacks.insert_one({
            "session_id": req.session_id[:64],
            "error_code": (req.error_code or "")[:40].upper() or None,
            "rating": req.rating,
            "comment": (req.comment or "").strip()[:1000] or None,
            "created_at": datetime.now(timezone.utc),
        })
        return {"ok": True, "stored": True}
    except Exception as e:
        logger.exception(f"feedback failed: {e}")
        return {"ok": True, "stored": False}


# ============================
# DiaGO consultant chat
# ============================
DIAGO_SYSTEM_PROMPT = """Tu esi DiaGO klientų aptarnavimo konsultantas. DiaGO yra savitarnos automobilių diagnostikos paslaugų teikėjas Lietuvoje.

ESMINĖ INFORMACIJA APIE DiaGO:
- DiaGO teikia DVI atskiras paslaugas:
  1. **Savitarnos diagnostikos stotelės** prie Neste degalinių (fizinė diagnostika su OBD įrenginiu)
  2. **Internetinė klaidų paieška** svetainėje diago.lt/klaidos (klaidos kodo paaiškinimas internetu)

=========================================
1. SAVITARNOS DIAGNOSTIKOS STOTELĖ (fizinė)
=========================================
- Trukmė: ~10 minučių (atliekami 2 diagnostikos ciklai)
- Kaina: 25,00 € už diagnostiką + 25,00 € užstatas už įrenginį (užstatas grąžinamas grąžinus įrenginį)
- Mokėjimas: per Stripe, asmens duomenų nekaupiame
- Ataskaita: pristatoma el. paštu arba SMS žinute kaip saugi nuoroda
- Ataskaitoje pateikiami patarimai ir paaiškinimai, ką reiškia kiekviena rasta klaida
- Palaikomi automobiliai: po 2001 m. (benzininiai), po 2004 m. (dyzeliniai) ES, JAV nuo 1996 m.
- 24/7 vaizdo pagalba stotelėje (Pagalbos mygtukas)

VEIKIANČIOS STOTELĖS:
- Šiuo metu visos stotelės dar yra paruošimo stadijoje – atidarysime jas artimiausiu metu.

JAU GREITAI (numatomos vietos):
- Vilnius, Kaunas, Šiauliai, Panevėžys, Klaipėda, Kėdainiai – po vieną stotelę miesto centre, Neste degalinėje
- Tikslios stotelių vietos bus paskelbtos prieš atidarymą
- Klientai gali užsisakyti pranešimą apie atidarymą per Pagalbos formą

🔵 STOTELIŲ VERSLO ABONEMENTAS (fizinei diagnostikai):
- Nuo 299 €/mėn – iki 20 automobilių neribota patikra DiaGO stotelėse
- Didesniems automobilių parkams (>20) – individualus planas, derinamas susitarus
- Tinka: autoservisams, nuomos kompanijoms, transporto įmonėms, taksi parkams
- Veikia visose Lietuvos DiaGO stotelėse

=========================================
2. INTERNETINĖ KLAIDŲ PAIEŠKA (diago.lt/klaidos)
=========================================
- Vartotojas internete įveda klaidos kodą (pvz., P0420), automobilio markę/modelį
- DiaGO sistema paaiškina klaidos reikšmę, galimas priežastis, kelionės saugumą, rekomendacijas, galimai sugedusias detales su OEM kodais
- ŠIUO METU NEMOKAMA visiems vartotojams iki 2026-06-01

🟢 KLAIDŲ PAIEŠKOS VERSLO ABONEMENTAS (skirtingas nuo stotelių abonemento!):
- Skirtas: įmonėms, servisams, nuomos kompanijoms, technikos operatoriams ir kt.
- Kaina: nuo 29 €/mėn (iki 50 paieškų per mėnesį)
- Didesnės įmonės gali aptarti individualų planą

⚠️ SVARBU NESUPAINIOTI:
- 299 €/mėn = STOTELIŲ abonementas (fizinei diagnostikai prie Neste, iki 20 automobilių)
- 29 €/mėn = INTERNETINĖS klaidų paieškos abonementas (svetainėje, iki 50 paieškų)
- Tai DU SKIRTINGI abonementai. Visada pasitikslink su klientu, kuris jam aktualus.

=========================================
KONTAKTAI:
- Įmonė: „JT-Diag" MB
- El. paštas: jt@diago.lt
- Telefonas: +370 638 34539
- 24/7 vaizdo pagalba stotelėje (Pagalbos mygtukas)

ELGESYS:
- Atsakyk LIETUVIŲ kalba, mandagiai ir draugiškai
- Vartok formalų kreipinį „jūs" („gausite", „atvykite", „prijunkite")
- Atsakymo struktūra: pasisveikinimas → trumpas paaiškinimas (2–4 sakiniai) → kontaktai (jei aktualu) → klausimas „Ar dar kažką norėtumėte žinoti?"
- Pradėk pirmą atsakymą su „Sveiki!" (ne kiekviename, tik pirmame)
- Jei klausiama apie abonementą – BŪTINAI pasitikslink, ar kalba apie internetinę klaidų paiešką ar stotelių abonementą; jei aišku iš konteksto – pateik atitinkamą informaciją
- Jei klausimas ne apie DiaGO ar automobilių diagnostiką – mandagiai pasakyk, kad gali padėti tik su DiaGO susijusiais klausimais
- Sudėtingais ar individualiais klausimais (pvz., didelėms įmonėms, individualios sutartys) – nukreipk į telefoną +370 638 34539 arba el. paštą jt@diago.lt
- Niekada neminėk žodžių „AI" ar „dirbtinis intelektas" – tiesiog DiaGO konsultantas
- Nesiūlyk pirkti, neagituok – tiesiog informuok ir konsultuok

PAVYZDINIS ATSAKYMAS Į KLAUSIMĄ APIE KLAIDŲ PAIEŠKOS ABONEMENTĄ:
„Sveiki! Mielai padėsiu jums.

DiaGO klaidų paieškos verslo abonementas skiriamas įmonėms, servisams, nuomos kompanijoms, technikos operatoriams ir kt. Abonemento kaina nuo 29 €/mėn (iki 50 paieškų per mėnesį).

Norėdami sužinoti daugiau detalių ir aptarti jūsų poreikius, rekomenduoju susisiekti su mūsų komanda:
- Telefonas: +370 638 34539
- El. paštas: jt@diago.lt

Ar dar kažką norėtumėte žinoti?"

PAVYZDINIS ATSAKYMAS Į KLAUSIMĄ APIE STOTELIŲ ABONEMENTĄ:
„Sveiki! Mielai padėsiu jums.

DiaGO stotelių verslo abonementas skirtas įmonėms, kurios reguliariai diagnozuoja automobilių parką. Nuo 299 €/mėn. galite gauti iki 20 automobilių neribotą patikrą visose DiaGO stotelėse Lietuvoje. Didesniems parkams – individualus planas.

Norėdami sužinoti daugiau detalių ir aptarti jūsų poreikius, rekomenduoju susisiekti su mūsų komanda:
- Telefonas: +370 638 34539
- El. paštas: jt@diago.lt

Ar dar kažką norėtumėte žinoti?"
"""


class ChatRequest(BaseModel):
    session_id: str
    message: str

class ChatResponse(BaseModel):
    reply: str
    session_id: str


@api_router.post("/chat", response_model=ChatResponse)
async def chat_with_diago(req: ChatRequest):
    user_text = (req.message or "").strip()
    if not user_text:
        raise HTTPException(status_code=400, detail="Žinutė tuščia.")
    if len(user_text) > 2000:
        raise HTTPException(status_code=400, detail="Žinutė per ilga (max 2000 simbolių).")

    api_key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not api_key:
        raise HTTPException(status_code=500, detail="LLM raktas nesukonfigūruotas.")

    sid = (req.session_id or "default").strip() or "default"

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=sid,
            system_message=DIAGO_SYSTEM_PROMPT,
        ).with_model("anthropic", "claude-haiku-4-5-20251001")

        for prior in list(_sessions[sid]):
            if prior["role"] == "user":
                await chat.send_message(UserMessage(text=prior["content"]))

        reply = await chat.send_message(UserMessage(text=user_text))

        _sessions[sid].append({"role": "user", "content": user_text})
        _sessions[sid].append({"role": "assistant", "content": reply})

        # Log į DB (anonimiškai, tik suskaičiavimui)
        db = _get_db()
        if db is not None:
            try:
                await db.chat_events.insert_one({
                    "session_id": sid,
                    "msg_len": len(user_text),
                    "reply_len": len(reply),
                    "created_at": datetime.now(timezone.utc),
                })
            except Exception:
                pass

        return ChatResponse(reply=reply, session_id=sid)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Chat failure")
        raise HTTPException(status_code=502, detail=f"Atsakymas nepavyko: {str(e)[:120]}")


# ============================
# Error code analyzer
# ============================
EQUIPMENT_LABELS = {
    "motorcycle": "motociklas",
    "car": "automobilis",
    "construction": "statybinė technika",
    "agriculture": "žemės ūkio technika",
    "warehouse": "sandėliavimo technika",
}

ERROR_ANALYZER_PROMPT = """Tu esi DiaGO ekspertas-mechanikas, kuris padeda klientams suprasti diagnostikos klaidos kodus.
Atsakyk LIETUVIŲ kalba, naudok formalų kreipinį „jūs" ir struktūrizuotą atsakymą griežtai pagal žemiau pateiktą formatą.
Niekada neminėk žodžių „AI" ar „dirbtinis intelektas" – tiesiog DiaGO.

ATSAKYMO FORMATAS (būtina laikytis lygiai šios struktūros):

## Klaidos paaiškinimas
Trumpai (2–3 sakiniai) paaiškinkite, ką reiškia šis klaidos kodas paprasta kalba, be sudėtingų terminų. Jei kodas neegzistuoja arba neaiškus – sąžiningai pasakykite tai.

## Galima priežastis
Išvardinkite 2–4 dažniausias galimas priežastis (kiekvieną kaip atskirą punktą su „•").

## Ar saugu važiuoti?
Vienas iš trijų aiškių atsakymų:
- ✅ TAIP, saugu — su trumpu paaiškinimu kodėl
- ⚠️ ATSARGIAI — su nurodymu, ko vengti ir kaip ilgai galima važiuoti
- 🛑 NE, sustokite — su priežastimi ir veiksmais, kurių imtis

## Rekomendacijos
3–5 konkrečių veiksmų sąrašas su „•" (ką patikrinti, kur važiuoti, kokius matavimus atlikti).

## Galimai sugedusi detalė
Pateikite kuo tikslesnius detalių kodus markdown LENTELE, šia struktūra (be papildomo teksto, tik lentelė):

| Detalė | OEM kodas | Gamintojas | Pastaba |
|---|---|---|---|
| Lambda zondas (priekinis) | 0258006206 | Bosch | Bendras kodas BMW E46 N42 varikliui |
| Lambda zondas (galinis) | 0258006537 | Bosch | Diagnostinis, po katalizatoriumi |

SVARBU:
- Jei žinote tikslų OEM kodą – įrašykite jį be skliaustų, raidžių ar tarpų, lygiai kaip pateikiamas kataloge.
- Jei kodas priklauso nuo konkretaus modelio/metų, kurio vartotojas nenurodė – stulpelyje "OEM kodas" rašykite TIK „—" (brūkšnį) ir Pastaboje paaiškinkite.
- Jei TIKRAI neįmanoma nustatyti net detalės pavadinimo (per platus kodas, neaiški klaida) – vietoj lentelės parašykite tik tris žodžius:
NĖRA TIKSLIŲ KODŲ

## Vieta automobilyje
1–2 sakinių aprašymas, kur fiziškai automobilyje yra detalė (pvz., „Variklio skyriuje, dešinėje pusėje, prie oro įsiurbimo kolektoriaus"). Šis aprašymas reikalingas, kad klientas suprastų, kur ieškoti.

## Paieškos užklausa
Pateikite šią eilutę TIK jei aukščiau lentelėje nėra nė vieno tikslaus OEM kodo (visi „—" arba parašyta „NĖRA TIKSLIŲ KODŲ"). Tokiu atveju vienoje eilutėje pateikite konkrečią paieškos užklausą Google paieškai (pvz., „Toyota RAV4 2010 lambda zondas").
Jei lentelėje yra bent vienas tikslus OEM kodas – šios skilties NEPATEIKITE arba palikite tuščią.
"""


class ErrorCheckRequest(BaseModel):
    session_id: str
    equipment_type: str
    error_code: str
    vehicle_info: str | None = None

class ErrorCheckResponse(BaseModel):
    analysis: str
    search_query: str
    google_search_url: str
    google_images_url: str


def _extract_search_query(analysis_text: str, fallback: str) -> str:
    m = re.search(r"##\s*Paieškos užklausa\s*\n+([^\n#]+)", analysis_text, re.IGNORECASE)
    if m:
        q = m.group(1).strip().strip('"„"').strip()
        if q:
            return q
    return fallback


@api_router.post("/check-error", response_model=ErrorCheckResponse)
async def check_error(req: ErrorCheckRequest):
    code = (req.error_code or "").strip().upper()
    eq = (req.equipment_type or "").strip().lower()
    veh = (req.vehicle_info or "").strip()

    if not code:
        raise HTTPException(status_code=400, detail="Klaidos kodas tuščias.")
    if len(code) > 40:
        raise HTTPException(status_code=400, detail="Klaidos kodas per ilgas.")
    if eq not in EQUIPMENT_LABELS:
        raise HTTPException(status_code=400, detail="Neteisingas technikos tipas.")

    api_key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not api_key:
        raise HTTPException(status_code=500, detail="LLM raktas nesukonfigūruotas.")

    eq_label = EQUIPMENT_LABELS[eq]
    user_prompt = f"Technikos tipas: {eq_label}\nKlaidos kodas: {code}"
    if veh:
        user_prompt += f"\nPapildoma informacija (markė/modelis/metai): {veh}"
    user_prompt += "\n\nPateik išsamią analizę pagal nurodytą struktūrą."

    sid = (req.session_id or "err-default").strip() or "err-default"

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=sid,
            system_message=ERROR_ANALYZER_PROMPT,
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")

        analysis = await chat.send_message(UserMessage(text=user_prompt))

        fallback_q = f"{code} {eq_label} {veh}".strip()
        search_q = _extract_search_query(analysis, fallback_q)

        gs = "https://www.google.com/search?q=" + quote_plus(search_q)
        gi = "https://www.google.com/search?tbm=isch&q=" + quote_plus(search_q)

        # Log į DB analitikai
        db = _get_db()
        if db is not None:
            try:
                await db.error_checks.insert_one({
                    "session_id": sid,
                    "error_code": code,
                    "equipment": eq,
                    "vehicle_info": veh[:200] if veh else None,
                    "created_at": datetime.now(timezone.utc),
                })
            except Exception:
                pass

        return ErrorCheckResponse(
            analysis=analysis,
            search_query=search_q,
            google_search_url=gs,
            google_images_url=gi,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error check failure")
        raise HTTPException(status_code=502, detail=f"Analizė nepavyko: {str(e)[:120]}")


# ============================
# ADMIN endpoints
# ============================
class AdminLoginRequest(BaseModel):
    email: str
    password: str

class AdminLoginResponse(BaseModel):
    token: str
    email: str
    expires_at: int

@api_router.post("/admin/login", response_model=AdminLoginResponse)
async def admin_login(req: AdminLoginRequest):
    expected_email = os.environ.get("ADMIN_EMAIL", "info@diago.lt").strip().lower()
    if (req.email or "").strip().lower() != expected_email:
        raise HTTPException(status_code=401, detail="Neteisingas el. paštas arba slaptažodis.")
    if not _admin_check_password(req.password or ""):
        raise HTTPException(status_code=401, detail="Neteisingas el. paštas arba slaptažodis.")
    token = _make_admin_token(expected_email)
    exp = int((datetime.now(timezone.utc) + timedelta(hours=12)).timestamp())
    return AdminLoginResponse(token=token, email=expected_email, expires_at=exp)


@api_router.get("/admin/stats")
async def admin_stats(authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        # Grąžinam tuščius duomenis (DB neprijungta), kad UI nesulaužtų
        return {
            "totals": {
                "unique_visitors": 0,
                "total_page_views": 0,
                "today_visitors": 0,
                "total_error_checks": 0,
                "today_error_checks": 0,
                "total_chats": 0,
                "total_feedback": 0,
                "positive_feedback": 0,
                "negative_feedback": 0,
            },
            "visits_by_day": [],
            "db_offline": True,
        }
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    last_30 = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

    # Lankytojai per dieną (paskutinės 30 d.)
    visits_pipeline = [
        {"$match": {"date": {"$gte": last_30}}},
        {"$group": {
            "_id": "$date",
            "unique_visitors": {"$addToSet": "$visitor_id"},
            "total_hits": {"$sum": "$hits"},
        }},
        {"$project": {
            "date": "$_id",
            "_id": 0,
            "unique_visitors": {"$size": "$unique_visitors"},
            "total_hits": 1,
        }},
        {"$sort": {"date": 1}},
    ]
    visits_by_day = await db.visits.aggregate(visits_pipeline).to_list(100)

    # Bendros sumos
    total_visitors = await db.visits.distinct("visitor_id")
    total_visitors_count = len(total_visitors)
    total_hits = await db.visits.count_documents({})
    today_visitors = await db.visits.distinct("visitor_id", {"date": today})

    # Klaidos
    total_error_checks = await db.error_checks.count_documents({})
    today_error_checks = await db.error_checks.count_documents({
        "created_at": {"$gte": datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)}
    })

    # Pokalbiai
    total_chats = await db.chat_events.count_documents({})

    # Atsiliepimai
    total_feedback = await db.feedbacks.count_documents({})
    positive_feedback = await db.feedbacks.count_documents({"rating": "up"})
    negative_feedback = await db.feedbacks.count_documents({"rating": "down"})

    return {
        "totals": {
            "unique_visitors": total_visitors_count,
            "total_page_views": total_hits,
            "today_visitors": len(today_visitors),
            "total_error_checks": total_error_checks,
            "today_error_checks": today_error_checks,
            "total_chats": total_chats,
            "total_feedback": total_feedback,
            "positive_feedback": positive_feedback,
            "negative_feedback": negative_feedback,
        },
        "visits_by_day": visits_by_day,
    }


@api_router.get("/admin/error-codes")
async def admin_error_codes(limit: int = 50, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    pipeline = [
        {"$group": {
            "_id": {"code": "$error_code", "equipment": "$equipment"},
            "count": {"$sum": 1},
            "last_seen": {"$max": "$created_at"},
        }},
        {"$project": {
            "_id": 0,
            "error_code": "$_id.code",
            "equipment": "$_id.equipment",
            "count": 1,
            "last_seen": 1,
        }},
        {"$sort": {"count": -1}},
        {"$limit": max(1, min(limit, 500))},
    ]
    rows = await db.error_checks.aggregate(pipeline).to_list(500)
    return {"items": rows}


@api_router.get("/admin/error-checks-recent")
async def admin_error_checks_recent(limit: int = 50, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.error_checks.find({}, {"_id": 0}).sort("created_at", -1).limit(max(1, min(limit, 200)))
    rows = await cur.to_list(200)
    return {"items": rows}


@api_router.get("/admin/feedbacks")
async def admin_feedbacks(limit: int = 100, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.feedbacks.find({}, {"_id": 0}).sort("created_at", -1).limit(max(1, min(limit, 500)))
    rows = await cur.to_list(500)
    return {"items": rows}


# ============================
# Pricing config (paruošta ateičiai – mokėjimai dar nepajungti)
# ============================
DEFAULT_PRICING = [
    {
        "id": "single_check",
        "label": "1 klaidos paaiškinimas",
        "amount_eur": 1.00,
        "enabled": False,
        "type": "one_time",
        "description": "Vienkartinis klaidos kodo paaiškinimas",
    },
    {
        "id": "business_monthly",
        "label": "Verslo abonementas (mėnesinis)",
        "amount_eur": 49.00,
        "enabled": False,
        "type": "subscription",
        "description": "Neriboti klaidų patikrinimai, tinka autoservisams",
    },
]

@api_router.get("/admin/pricing")
async def admin_get_pricing(authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": DEFAULT_PRICING}
    items = await db.pricing.find({}, {"_id": 0}).to_list(50)
    if not items:
        # seed
        try:
            await db.pricing.insert_many([dict(p) for p in DEFAULT_PRICING])
            items = list(DEFAULT_PRICING)
        except Exception:
            items = list(DEFAULT_PRICING)
    return {"items": items}


class PricingUpdateRequest(BaseModel):
    id: str
    label: str | None = None
    amount_eur: float | None = None
    enabled: bool | None = None
    description: str | None = None

@api_router.put("/admin/pricing")
async def admin_update_pricing(req: PricingUpdateRequest, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    update_doc = {}
    if req.label is not None:
        update_doc["label"] = req.label[:120]
    if req.amount_eur is not None:
        if req.amount_eur < 0 or req.amount_eur > 99999:
            raise HTTPException(status_code=400, detail="Netinkama kaina.")
        update_doc["amount_eur"] = round(float(req.amount_eur), 2)
    if req.enabled is not None:
        update_doc["enabled"] = bool(req.enabled)
    if req.description is not None:
        update_doc["description"] = req.description[:500]
    if not update_doc:
        raise HTTPException(status_code=400, detail="Nieko keisti.")
    update_doc["updated_at"] = datetime.now(timezone.utc)
    res = await db.pricing.update_one({"id": req.id}, {"$set": update_doc}, upsert=True)
    return {"ok": True, "matched": res.matched_count, "modified": res.modified_count}


# Viešas pricing endpoint (anonimiškas – tik enabled planams)
@api_router.get("/pricing")
async def get_public_pricing():
    db = _get_db()
    if db is None:
        return {"items": [p for p in DEFAULT_PRICING if p.get("enabled")]}
    items = await db.pricing.find({"enabled": True}, {"_id": 0}).to_list(50)
    return {"items": items}


app.include_router(api_router)


@app.on_event("startup")
async def startup():
    logger.info("DiaGO API starting up...")
    if not os.environ.get("EMERGENT_LLM_KEY"):
        logger.warning("⚠️  EMERGENT_LLM_KEY env var nenustatytas! AI funkcijos neveiks.")
    if not os.environ.get("MONGODB_URI"):
        logger.warning("⚠️  MONGODB_URI nenustatytas – analitika neveiks.")
    if not os.environ.get("ADMIN_PASSWORD"):
        logger.warning("⚠️  ADMIN_PASSWORD nenustatytas – admin'as neveiks.")
    if not os.environ.get("JWT_SECRET"):
        logger.warning("⚠️  JWT_SECRET nenustatytas – admin sesijos nesaugios.")


@app.on_event("shutdown")
async def shutdown():
    global _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
