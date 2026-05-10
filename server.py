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


# ============================
# User auth (pbkdf2 - per-user salt)
# ============================
def _user_hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Grąžina (salt_hex, hash_hex). Saugu naudoti pbkdf2_hmac su 200k iteracijų."""
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
    else:
        salt_bytes = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 200_000)
    return salt_bytes.hex(), dk.hex()


def _user_verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        _, computed = _user_hash_password(password, salt_hex)
        return hmac.compare_digest(computed, hash_hex)
    except Exception:
        return False


def _make_user_token(user_id: str, email: str) -> str:
    """JWT-pavidalo HMAC token vartotojui (30d galiojimas)."""
    secret = os.environ.get("JWT_SECRET", "diago-default-secret-change-me")
    exp = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
    payload = json.dumps({"uid": user_id, "email": email, "exp": exp, "scope": "user"}, separators=(",", ":"))
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    import base64
    p64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"{p64}.{sig}"


def _verify_user_token(token: str) -> dict | None:
    if not token:
        return None
    try:
        import base64
        p64, sig = token.split(".", 1)
        secret = os.environ.get("JWT_SECRET", "diago-default-secret-change-me")
        padded = p64 + "=" * (-len(p64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded.encode())
        expected_sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(payload_bytes.decode())
        if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            return None
        if payload.get("scope") != "user":
            return None
        return payload
    except Exception:
        return None


async def _get_current_user(authorization: str | None) -> dict | None:
    """Grąžina prisijungusio user dokumentą iš DB arba None."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    payload = _verify_user_token(token)
    if not payload:
        return None
    db = _get_db()
    if db is None:
        return None
    try:
        user = await db.users.find_one({"email": payload.get("email")}, {"password_hash": 0, "password_salt": 0})
        return user
    except Exception:
        return None

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
- DiaGO teikia DVI atskiras paslaugas su SKIRTINGU technikos palaikymu:
  1. **Savitarnos diagnostikos stotelės** prie Neste degalinių – TIK AUTOMOBILIAMS (fizinė diagnostika su OBD įrenginiu)
  2. **Internetinė klaidų paieška** svetainėje diago.lt/klaidos – BET KOKIAI TECHNIKAI: automobiliams, motociklams, statybinei technikai (krautuvai, ekskavatoriai), žemės ūkio technikai (traktoriai, kombainai), sandėliavimo technikai (autokrautuvai) ir kt.

🔴 KRITIŠKAI SVARBU – TECHNIKOS APRIBOJIMAI:
- Klausiant „ar galiu patikrinti TRAKTORIŲ / motociklą / krautuvą / statybinę techniką?" – TAIP, **internetinė klaidų paieška veikia bet kokiai technikai**. Niekada nesakyk „skirta tik automobiliams" – tai NETIESA dėl klaidų paieškos paslaugos!
- Tik FIZINĖS DiaGO stotelės skirtos automobiliams. Jei kas klausia apie traktoriaus diagnostiką stotelėje – pasakyk, kad fizinės stotelės skirtos tik automobiliams, BET internetinė klaidų paieška veikia ir traktoriams.

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
- 🔴 KRITIŠKAI SVARBU – KAI KLAUSIAMA APIE „ABONEMENTĄ" arba „VERSLO PASIŪLYMĄ" be aiškaus konteksto:
  PRIVALU paminėti ABU abonementus (klaidų paieškos IR stotelių). Niekada neminėk tik vieno!
  Pateik trumpai abu variantus ir paklausk klientą, kuris jam aktualus.
- Jei klausimas aiškiai apie konkretų abonementą (pvz., „kiek kainuoja klaidų paieškos abonementas?" arba „stotelių abonementas") – pateik atsakymą tik apie tą vieną
- 🔴 JOKIU BŪDU NEMINĖKITE skaičių „199" ar „50 vairuotojų" – tai SENA, nebegaliojanti informacija. Galiojančios kainos: 29 € (klaidų paieška) ir 299 € (stotelės)
- Jei klausimas ne apie DiaGO ar automobilių diagnostiką – mandagiai pasakyk, kad gali padėti tik su DiaGO susijusiais klausimais
- Sudėtingais ar individualiais klausimais (pvz., didelėms įmonėms, individualios sutartys) – nukreipk į telefoną +370 638 34539 arba el. paštą jt@diago.lt
- Niekada neminėk žodžių „AI" ar „dirbtinis intelektas" – tiesiog DiaGO konsultantas
- Nesiūlyk pirkti, neagituok – tiesiog informuok ir konsultuok

PAVYZDINIS ATSAKYMAS Į NEAIŠKŲ KLAUSIMĄ APIE „ABONEMENTĄ" / „VERSLO PASIŪLYMĄ":
„Sveiki! Mielai padėsiu jums. DiaGO turi du atskirus verslo abonementus, priklausomai nuo Jūsų poreikių:

🟢 **Klaidų paieškos abonementas** (internetinė paieška svetainėje) – nuo 29 €/mėn., iki 50 paieškų per mėnesį. Tinka įmonėms, servisams, nuomos kompanijoms, technikos operatoriams.

🔵 **Stotelių abonementas** (fizinė diagnostika DiaGO stotelėse) – nuo 299 €/mėn., iki 20 automobilių neribota patikra visose DiaGO stotelėse Lietuvoje. Didesniems parkams – individualus planas.

Kuris iš jų Jus labiau domina? Galiu papasakoti detaliau. Norėdami aptarti individualią sutartį, susisiekite:
- Telefonas: +370 638 34539
- El. paštas: jt@diago.lt"

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

        # Log į DB (pilna pokalbio žinutė admin'o peržiūrai)
        db = _get_db()
        if db is not None:
            try:
                await db.chat_events.insert_one({
                    "session_id": sid,
                    "user_message": user_text[:2000],
                    "assistant_reply": (reply or "")[:8000],
                    "msg_len": len(user_text),
                    "reply_len": len(reply or ""),
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

## Poveikis
1–2 sakinių aprašymas, kaip ši klaida paveiks techniką (automobilį / motociklą / traktorių / krautuvą / ir kt., priklausomai nuo technikos tipo), jei nebus išspręsta (pvz., „Padidėjęs degalų suvartojimas, gali nepraeiti TA" arba „Krautuvas gali prarasti galią pakėlimo metu").

## Atsargumo priemonės
1–2 sakinių praktinis patarimas operatoriui ar vairuotojui (pritaikytas pagal technikos tipą, pvz., automobiliui – „Nevažiuoti dideliu greičiu ar ilgais maršrutais kol bus pakeista detalė", krautuvui – „Nekelti maksimalios apkrovos kol bus pašalinta klaida").

## Remonto kaina (orientacinė)
Pateikite orientacinį remonto kainos diapazoną EUR formatu (pvz., „80–250 €" arba „30–800 €", arba „0–200 € jei vienkartinis"). Skirta tik bendrai informacijai – tikslias kainas pasako autoservisas.

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

## Vieta technikoje
1–2 sakinių aprašymas, kur fiziškai technikoje (automobilyje, motocikle, traktoriuje, krautuve ir pan., priklausomai nuo konteksto) yra detalė (pvz., „Variklio skyriuje, dešinėje pusėje, prie oro įsiurbimo kolektoriaus" arba „Hidraulinės sistemos linijoje, šalia siurblio"). Šis aprašymas reikalingas, kad klientas suprastų, kur ieškoti.

## Paieškos užklausa
Pateikite šią eilutę TIK jei aukščiau lentelėje nėra nė vieno tikslaus OEM kodo (visi „—" arba parašyta „NĖRA TIKSLIŲ KODŲ"). Tokiu atveju vienoje eilutėje pateikite konkrečią paieškos užklausą Google paieškai (pvz., „Toyota RAV4 2010 lambda zondas").
Jei lentelėje yra bent vienas tikslus OEM kodas – šios skilties NEPATEIKITE arba palikite tuščią.
"""


class ErrorCheckRequest(BaseModel):
    session_id: str
    equipment_type: str
    error_code: str
    vehicle_info: str | None = None
    visitor_id: str | None = None  # nemokamų užklausų sekiojimui


class ErrorCheckResponse(BaseModel):
    analysis: str
    search_query: str
    google_search_url: str
    google_images_url: str
    quota: dict | None = None  # { logged_in, unlimited, limit, used, remaining }


def _extract_search_query(analysis_text: str, fallback: str) -> str:
    m = re.search(r"##\s*Paieškos užklausa\s*\n+([^\n#]+)", analysis_text, re.IGNORECASE)
    if m:
        q = m.group(1).strip().strip('"„"').strip()
        if q:
            return q
    return fallback


@api_router.post("/check-error", response_model=ErrorCheckResponse)
async def check_error(req: ErrorCheckRequest, request: Request, authorization: str | None = Header(default=None)):
    code = (req.error_code or "").strip().upper()
    eq = (req.equipment_type or "").strip().lower()
    veh = (req.vehicle_info or "").strip()

    if not code:
        raise HTTPException(status_code=400, detail="Klaidos kodas tuščias.")
    if len(code) > 40:
        raise HTTPException(status_code=400, detail="Klaidos kodas per ilgas.")
    if eq not in EQUIPMENT_LABELS:
        raise HTTPException(status_code=400, detail="Neteisingas technikos tipas.")

    # === Free quota patikra (jei NEPRISIJUNGĘS) ===
    user = await _get_current_user(authorization)
    db = _get_db()
    quota_info = None
    quota_doc = None  # išsaugom referencijai vėliau (count inkrementui)
    if not user:
        if db is not None:
            ip = request.client.host if request.client else ""
            ip_hash = _hash_ip(ip)
            visitor_id = (req.visitor_id or "").strip()[:64]
            quota_doc = await _get_or_create_quota(db, ip_hash, visitor_id)
            used = int(quota_doc.get("count", 0))
            if used >= FREE_QUOTA_LIMIT:
                # Peržengta riba – siūlom prisiregistruoti
                raise HTTPException(
                    status_code=402,
                    detail=(
                        f"Išnaudoti visi {FREE_QUOTA_LIMIT} nemokami patikrinimai. "
                        "Prašome prisiregistruoti nemokamai (iki 2026-06-01) – tęskite naudojimąsi be ribų."
                    ),
                )

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

        # Log į DB analitikai + quota inkrementas
        if db is not None:
            try:
                await db.error_checks.insert_one({
                    "session_id": sid,
                    "user_id": user.get("user_id") if user else None,
                    "error_code": code,
                    "equipment": eq,
                    "vehicle_info": veh[:200] if veh else None,
                    "created_at": datetime.now(timezone.utc),
                })
                if user:
                    # Užregistruotas vartotojas – tik bendras counter
                    await db.users.update_one(
                        {"user_id": user["user_id"]},
                        {"$inc": {"checks_count": 1}, "$set": {"last_check_at": datetime.now(timezone.utc)}},
                    )
                    quota_info = {"logged_in": True, "unlimited": True, "limit": None, "used": user.get("checks_count", 0) + 1, "remaining": None}
                else:
                    # Anonim – inkrementuojam free quota
                    ip = request.client.host if request.client else ""
                    ip_hash = _hash_ip(ip)
                    visitor_id = (req.visitor_id or "").strip()[:64]
                    await _increment_quota(db, ip_hash, visitor_id)
                    new_used = int(quota_doc.get("count", 0)) + 1 if quota_doc else 1
                    quota_info = {
                        "logged_in": False, "unlimited": False, "limit": FREE_QUOTA_LIMIT,
                        "used": new_used, "remaining": max(0, FREE_QUOTA_LIMIT - new_used),
                    }
            except Exception:
                pass

        return ErrorCheckResponse(
            analysis=analysis,
            search_query=search_q,
            google_search_url=gs,
            google_images_url=gi,
            quota=quota_info,
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


@api_router.get("/admin/chats-recent")
async def admin_chats_recent(limit: int = 100, authorization: str | None = Header(default=None)):
    """Paskutinės AI pokalbių žinutės su pilnu tekstu (admin'o peržiūrai)."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.chat_events.find({}, {"_id": 0}).sort("created_at", -1).limit(max(1, min(limit, 500)))
    rows = await cur.to_list(500)
    return {"items": rows}


@api_router.get("/admin/chats-by-session")
async def admin_chats_by_session(session_id: str, limit: int = 200, authorization: str | None = Header(default=None)):
    """Visi konkrečios sesijos pokalbiai chronologine tvarka."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.chat_events.find({"session_id": session_id}, {"_id": 0}).sort("created_at", 1).limit(max(1, min(limit, 500)))
    rows = await cur.to_list(500)
    return {"items": rows}


@api_router.get("/admin/chat-sessions")
async def admin_chat_sessions(limit: int = 50, authorization: str | None = Header(default=None)):
    """Sesijų suvestinė: kiekvienai sesijai – žinučių kiekis, paskutinė data, paskutinė user žinutė."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    pipeline = [
        {"$sort": {"created_at": -1}},
        {"$group": {
            "_id": "$session_id",
            "messages": {"$sum": 1},
            "last_at": {"$max": "$created_at"},
            "first_at": {"$min": "$created_at"},
            "last_user_message": {"$first": "$user_message"},
            "last_assistant_reply": {"$first": "$assistant_reply"},
        }},
        {"$project": {
            "_id": 0,
            "session_id": "$_id",
            "messages": 1,
            "last_at": 1,
            "first_at": 1,
            "last_user_message": 1,
            "last_assistant_reply": 1,
        }},
        {"$sort": {"last_at": -1}},
        {"$limit": max(1, min(limit, 200))},
    ]
    rows = await db.chat_events.aggregate(pipeline).to_list(200)
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


# ============================
# CHAT ANALYTICS (admin)
# ============================
# Lietuviški „stop words" – nešalinami iš n-grams analizės
LT_STOPWORDS = set("""
ar bei jei kad kai kas kiek kodėl koks kokia kokie kokios kuri kuris kurie kurios
ne nei net o tai taip taigi tu jūs jis ji jie jos man mane mums tau tave jam jus
jūs jį ją jiems joms su nuo iki per pas prie po dėl už ant prieš tarp be be tik
yra buvo bus bet būti turi turėti turiu turite gali galima galiu galite norėčiau
norėtumėte gerai labai daug mažai jau dar arba ir su mes aš joje jame
diago info paslaugos paslaugą paslauga paslaugos paslaugos lietuvoje lietuva
visa visi visiems visus visas visomis savo manau jūsų mūsų jokio jokia jokie
""".split())

def _tokenize_lt(text: str) -> list[str]:
    """Paprastas lietuviškas tokenizatorius. Mažosios + raidės/skaičiai."""
    if not text:
        return []
    # Žodis = raidės/skaičiai (palaikom lietuviškas)
    words = re.findall(r"[a-zA-ZąčęėįšųūžĄČĘĖĮŠŲŪŽ0-9]+", text.lower())
    # Filtruojam stopžodžius ir per trumpus
    return [w for w in words if len(w) >= 3 and w not in LT_STOPWORDS]


def _ngrams(tokens: list[str], n: int) -> list[str]:
    if len(tokens) < n:
        return []
    return [" ".join(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]


# Iš anksto numatytos kategorijos – greitas raktažodžių klasifikavimas
CHAT_CATEGORIES = [
    ("Kainos / mokėjimas", ["kain", "moket", "moke", "pinig", "atsiskait", "pigi", "brangi", "užstat", "uzstat", "diskon", "stripe", "paysera", "akcij", "nuolaid"]),
    ("Stotelės / vietos", ["stotel", "neste", "vilnius", "kaun", "klaipėd", "klaipėd", "panevėž", "panevez", "šiauli", "siauli", "kėdaini", "kedaini", "vieta", "miest", "adres"]),
    ("Verslo abonementas", ["abonemen", "verslo", "įmon", "imon", "servis", "nuom", "parka", "fleet", "29", "299", "individual", "individuali"]),
    ("Internetinė klaidų paieška", ["internetin", "klaid", "kod", "obd", "p0", "p1", "p2", "p3", "u0", "b0", "c0", "online"]),
    ("Motociklai / kita technika", ["motocikl", "trakto", "kombain", "krautuv", "ekskavato", "statybin", "žemės", "zemes", "sandėl", "sandel"]),
    ("Diagnostikos eiga", ["trukmė", "trukme", "kiek užtrunk", "kiek uztrunk", "kaip vyks", "kaip atlik", "ataskait", "rezultat", "ciklas", "minut"]),
    ("Atidarymas / data", ["atidar", "kada", "greitai", "atidarym", "bus", "paleidim", "veikia", "veikti"]),
    ("Klientų aptarnavimas", ["pagalb", "kontakt", "telefon", "el. pašt", "el pašt", "skambin", "raš"]),
    ("Saugumas / privatumas", ["saug", "duomen", "privat", "asmen", "gdpr", "slapuk"]),
    ("Pretenzijos / problemos", ["neveiki", "blogai", "problem", "klaid", "neaiš", "neais", "skund", "preten", "atgal"]),
]


def _classify_message(text: str) -> str:
    """Grąžina kategoriją pagal raktažodžius. „Kita" jei nė viena nesuveikia."""
    if not text:
        return "Kita"
    t = text.lower()
    for label, keywords in CHAT_CATEGORIES:
        if any(kw in t for kw in keywords):
            return label
    return "Kita"


@api_router.get("/admin/chat-analytics")
async def admin_chat_analytics(
    days: int = 30,
    use_ai: bool = False,
    authorization: str | None = Header(default=None),
):
    """Pokalbių analizė: kategorijos, top frazės, sesijų skaičius.

    Args:
        days: Periodas dienomis (7, 30, 90)
        use_ai: Jei True – pridedama AI sumarizuota santrauka (vienas Haiku call'as ~$0.001)
    """
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"period_days": days, "total_messages": 0, "categories": [], "top_phrases": [], "summary": "DB nepasiekiama."}

    days = max(1, min(days, 365))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Paimam VISAS user_message žinutes per laikotarpį
    cur = db.chat_events.find(
        {"created_at": {"$gte": since}},
        {"_id": 0, "user_message": 1, "session_id": 1, "created_at": 1},
    ).limit(5000)
    rows = await cur.to_list(5000)

    total = len(rows)
    if total == 0:
        return {
            "period_days": days,
            "total_messages": 0,
            "unique_sessions": 0,
            "categories": [],
            "top_phrases": [],
            "top_questions": [],
            "summary": "Per pasirinktą laikotarpį pokalbių nebuvo.",
        }

    unique_sessions = len({r.get("session_id") for r in rows})

    # 1) Kategorijos (raktažodžių klasifikavimas)
    cat_counts: dict[str, int] = defaultdict(int)
    for r in rows:
        cat = _classify_message(r.get("user_message", ""))
        cat_counts[cat] += 1
    categories = [
        {"label": k, "count": v, "pct": round(v / total * 100, 1)}
        for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])
    ]

    # 2) N-grams: top frazės (1-, 2- ir 3-žodžiai junginiai)
    phrase_counts: dict[str, int] = defaultdict(int)
    for r in rows:
        toks = _tokenize_lt(r.get("user_message", ""))
        for ng in toks:
            phrase_counts[ng] += 1
        for ng in _ngrams(toks, 2):
            phrase_counts[ng] += 1
        for ng in _ngrams(toks, 3):
            phrase_counts[ng] += 1
    # Filtruojam: bigramos/trigramos turi būti pasitaikiusios bent 2 kartus
    top_phrases = sorted(
        ((p, c) for p, c in phrase_counts.items() if c >= 2),
        key=lambda x: -x[1],
    )[:30]
    top_phrases_list = [{"phrase": p, "count": c} for p, c in top_phrases]

    # 3) Top dažniausiai besikartojantys pirmieji klausimai (panašūs)
    # Paprasčiausia: imam pirmą sesijos žinutę ir grupuojam pagal pirmus 60 simbolių (lower)
    first_msgs: dict[str, list] = defaultdict(list)
    seen_sessions = set()
    for r in sorted(rows, key=lambda x: x.get("created_at") or datetime.now(timezone.utc)):
        sid = r.get("session_id")
        if sid in seen_sessions:
            continue
        seen_sessions.add(sid)
        msg = (r.get("user_message") or "").strip()
        key = re.sub(r"\s+", " ", msg.lower())[:80]
        if key:
            first_msgs[key].append(msg)
    top_questions_raw = sorted(first_msgs.items(), key=lambda x: -len(x[1]))[:15]
    top_questions = [
        {"question": items[0][:200], "count": len(items)}
        for _, items in top_questions_raw if items
    ]

    # 4) AI santrauka (neprivaloma)
    summary = None
    if use_ai:
        api_key = os.environ.get("EMERGENT_LLM_KEY", "")
        if api_key:
            try:
                # Imam top 50 unikalių pirmų žinučių
                sample_questions = [items[0] for _, items in top_questions_raw[:50] if items]
                prompt = (
                    f"Pateikiu sąrašą {len(sample_questions)} klientų klausimų DiaGO konsultantui per "
                    f"paskutines {days} dienų. Trumpai (4-6 sakiniais) apibendrink, ko klientai DAŽNIAUSIAI klausė ir "
                    f"kokios yra pagrindinės temos. Atsakyk LIETUVIŲ kalba, dalykiškai. Pradėk frazę „Per paskutines {days} dienų klientai dažniausiai...\".\n\n"
                    "Klausimai:\n" + "\n".join(f"- {q}" for q in sample_questions)
                )
                chat = LlmChat(
                    api_key=api_key,
                    session_id=f"analytics-{int(datetime.now(timezone.utc).timestamp())}",
                    system_message="Tu – analitikas, glaustai apibendrinantis klientų klausimus.",
                ).with_model("anthropic", "claude-haiku-4-5-20251001")
                summary = await chat.send_message(UserMessage(text=prompt))
            except Exception as e:
                logger.warning(f"AI summary failed: {e}")
                summary = f"AI santrauka nepavyko: {str(e)[:100]}"
        else:
            summary = "EMERGENT_LLM_KEY nenustatytas."

    return {
        "period_days": days,
        "total_messages": total,
        "unique_sessions": unique_sessions,
        "categories": categories,
        "top_phrases": top_phrases_list,
        "top_questions": top_questions,
        "summary": summary,
    }


# ============================
# USER AUTH (privatus / verslo) – paprastas vienas prisijungimas
# ============================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

class RegisterRequest(BaseModel):
    email: str
    password: str
    accept_privacy: bool = True


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    token: str
    email: str
    user_id: str
    has_profile: bool


class ProfileUpdateRequest(BaseModel):
    type: str | None = None  # "private" | "business"
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    company_name: str | None = None
    company_code: str | None = None
    vat_code: str | None = None
    address: str | None = None
    city: str | None = None
    country: str | None = None
    contact_person: str | None = None


@api_router.post("/auth/register", response_model=UserResponse)
async def auth_register(req: RegisterRequest):
    email = (req.email or "").strip().lower()
    pw = req.password or ""
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Neteisingas el. pašto formatas.")
    if len(pw) < 6:
        raise HTTPException(status_code=400, detail="Slaptažodis turi būti bent 6 simbolių.")
    if len(pw) > 200:
        raise HTTPException(status_code=400, detail="Slaptažodis per ilgas.")
    if not req.accept_privacy:
        raise HTTPException(status_code=400, detail="Reikia sutikti su privatumo politika.")

    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")

    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="Šis el. paštas jau užregistruotas. Prašome prisijungti.")

    salt, h = _user_hash_password(pw)
    user_id = "u-" + secrets.token_urlsafe(8)
    now = datetime.now(timezone.utc)
    await db.users.insert_one({
        "user_id": user_id,
        "email": email,
        "password_hash": h,
        "password_salt": salt,
        "type": None,  # bus nustatytas pildant profilį
        "profile": {},
        "created_at": now,
        "last_login": now,
        "checks_count": 0,
    })
    token = _make_user_token(user_id, email)
    return UserResponse(token=token, email=email, user_id=user_id, has_profile=False)


@api_router.post("/auth/login", response_model=UserResponse)
async def auth_login(req: LoginRequest):
    email = (req.email or "").strip().lower()
    pw = req.password or ""
    if not email or not pw:
        raise HTTPException(status_code=400, detail="Įveskite el. paštą ir slaptažodį.")

    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")

    user = await db.users.find_one({"email": email})
    if not user or not _user_verify_password(pw, user.get("password_salt", ""), user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Neteisingas el. paštas arba slaptažodis.")

    await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.now(timezone.utc)}})

    token = _make_user_token(user["user_id"], user["email"])
    has_profile = bool(user.get("type")) and bool(user.get("profile"))
    return UserResponse(token=token, email=user["email"], user_id=user["user_id"], has_profile=has_profile)


@api_router.get("/auth/me")
async def auth_me(authorization: str | None = Header(default=None)):
    user = await _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Nepatvirtinta sesija.")
    user.pop("_id", None)
    return {"user": user}


@api_router.put("/auth/profile")
async def auth_update_profile(req: ProfileUpdateRequest, authorization: str | None = Header(default=None)):
    user = await _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Nepatvirtinta sesija.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")

    update = {}
    if req.type is not None:
        if req.type not in ("private", "business"):
            raise HTTPException(status_code=400, detail="Neteisingas vartotojo tipas.")
        update["type"] = req.type

    profile_fields = {
        "first_name": req.first_name, "last_name": req.last_name, "phone": req.phone,
        "company_name": req.company_name, "company_code": req.company_code, "vat_code": req.vat_code,
        "address": req.address, "city": req.city, "country": req.country,
        "contact_person": req.contact_person,
    }
    profile_update = {}
    for k, v in profile_fields.items():
        if v is not None:
            profile_update[f"profile.{k}"] = (v or "").strip()[:200]
    update.update(profile_update)
    update["updated_at"] = datetime.now(timezone.utc)

    await db.users.update_one({"user_id": user["user_id"]}, {"$set": update})
    return {"ok": True}


# ============================
# FREE QUOTA (3 nemokami patikrinimai be prisijungimo)
# ============================
FREE_QUOTA_LIMIT = 3
FREE_QUOTA_DAYS = 90  # quota nuliuojamas kas 90d (pagal MongoDB TTL)


def _hash_ip(ip: str) -> str:
    if not ip:
        return ""
    salt = os.environ.get("JWT_SECRET", "diago-default-secret-change-me")
    return hashlib.sha256((salt + "|ip|" + ip).encode("utf-8")).hexdigest()[:24]


async def _get_or_create_quota(db, ip_hash: str, visitor_id: str) -> dict:
    """Grąžina esamą quota dokumentą (max iš ip ir visitor_id įrašų)."""
    now = datetime.now(timezone.utc)
    # Imam tiek pagal ip_hash, tiek pagal visitor_id - blokuojam jei BET KURIS peržengė
    candidates = []
    if ip_hash:
        c1 = await db.free_checks.find_one({"key_type": "ip", "key": ip_hash})
        if c1:
            candidates.append(c1)
    if visitor_id:
        c2 = await db.free_checks.find_one({"key_type": "vid", "key": visitor_id})
        if c2:
            candidates.append(c2)
    if not candidates:
        return {"count": 0, "first_at": now, "last_at": now}
    # Grąžinam tą, kurio count didžiausias
    return max(candidates, key=lambda x: x.get("count", 0))


async def _increment_quota(db, ip_hash: str, visitor_id: str):
    now = datetime.now(timezone.utc)
    if ip_hash:
        await db.free_checks.update_one(
            {"key_type": "ip", "key": ip_hash},
            {
                "$inc": {"count": 1},
                "$set": {"last_at": now},
                "$setOnInsert": {"first_at": now, "key_type": "ip", "key": ip_hash},
            },
            upsert=True,
        )
    if visitor_id:
        await db.free_checks.update_one(
            {"key_type": "vid", "key": visitor_id},
            {
                "$inc": {"count": 1},
                "$set": {"last_at": now},
                "$setOnInsert": {"first_at": now, "key_type": "vid", "key": visitor_id},
            },
            upsert=True,
        )


@api_router.get("/quota/status")
async def quota_status(
    request: Request,
    visitor_id: str = "",
    authorization: str | None = Header(default=None),
):
    """Grąžina nemokamų užklausų statusą (kiek liko / ar prisijungęs)."""
    user = await _get_current_user(authorization)
    if user:
        return {
            "logged_in": True,
            "unlimited": True,
            "limit": None,
            "used": user.get("checks_count", 0),
            "remaining": None,
        }

    db = _get_db()
    if db is None:
        # DB nepasiekiama – leidžiam visiems
        return {"logged_in": False, "unlimited": False, "limit": FREE_QUOTA_LIMIT, "used": 0, "remaining": FREE_QUOTA_LIMIT}

    ip = request.client.host if request.client else ""
    ip_hash = _hash_ip(ip)
    quota = await _get_or_create_quota(db, ip_hash, visitor_id.strip()[:64])
    used = int(quota.get("count", 0))
    remaining = max(0, FREE_QUOTA_LIMIT - used)
    return {
        "logged_in": False,
        "unlimited": False,
        "limit": FREE_QUOTA_LIMIT,
        "used": used,
        "remaining": remaining,
    }


# ============================
# ADMIN – Vartotojai
# ============================
@api_router.get("/admin/users")
async def admin_users_list(limit: int = 100, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.users.find(
        {},
        {"_id": 0, "password_hash": 0, "password_salt": 0},
    ).sort("created_at", -1).limit(max(1, min(limit, 500)))
    items = await cur.to_list(500)
    return {"items": items}


class AdminResetPasswordRequest(BaseModel):
    user_id: str
    new_password: str

@api_router.post("/admin/users/reset-password")
async def admin_users_reset_password(req: AdminResetPasswordRequest, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    if len(req.new_password or "") < 6:
        raise HTTPException(status_code=400, detail="Slaptažodis turi būti bent 6 simbolių.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    salt, h = _user_hash_password(req.new_password)
    res = await db.users.update_one(
        {"user_id": req.user_id},
        {"$set": {"password_hash": h, "password_salt": salt, "updated_at": datetime.now(timezone.utc)}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vartotojas nerastas.")
    return {"ok": True}


async def _ensure_indexes():
    """Sukuria reikalingus MongoDB indeksus, įskaitant TTL pokalbių auto-trynimui (90d)."""
    db = _get_db()
    if db is None:
        return
    try:
        # TTL indeksas: chat_events automatiškai trinami po 90 dienų
        await db.chat_events.create_index(
            "created_at",
            expireAfterSeconds=90 * 24 * 60 * 60,
            name="ttl_90d",
        )
        # Greitos paieškos pagal session_id
        await db.chat_events.create_index("session_id", name="by_session")
        # Klaidų checks – 180d retencija (po 6 mėn. trinami)
        await db.error_checks.create_index(
            "created_at",
            expireAfterSeconds=180 * 24 * 60 * 60,
            name="ttl_180d",
        )
        # Visits – 1 metai retencija
        await db.visits.create_index(
            "last_seen",
            expireAfterSeconds=365 * 24 * 60 * 60,
            name="ttl_365d",
        )
        logger.info("✅ MongoDB indeksai sukurti (įskaitant TTL).")
    except Exception as e:
        logger.warning(f"Index creation issue: {e}")
    # users + free_checks indeksai (auth + quota)
    try:
        await db.users.create_index("email", unique=True, name="users_email_unique")
        await db.users.create_index("user_id", name="users_user_id")
        # free_checks – 90d auto-trynimas (kvotos atsinaujinimas)
        await db.free_checks.create_index(
            "last_at",
            expireAfterSeconds=FREE_QUOTA_DAYS * 24 * 60 * 60,
            name="free_checks_ttl",
        )
        await db.free_checks.create_index([("key_type", 1), ("key", 1)], unique=True, name="free_checks_unique")
        logger.info("✅ users + free_checks indeksai sukurti.")
    except Exception as e:
        logger.warning(f"Auth indexes issue: {e}")


# Routerio registracija – po VISŲ endpoint'ų deklaracijų
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
    # Indeksai (įskaitant TTL pokalbių auto-trynimui po 90d)
    try:
        await _ensure_indexes()
    except Exception as e:
        logger.warning(f"_ensure_indexes failed: {e}")


@app.on_event("shutdown")
async def shutdown():
    global _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
