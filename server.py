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
from emergentintegrations.llm.chat import LlmChat, UserMessage, ImageContent

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
  1. **Savitarnos diagnostikos stotelės** – TIK AUTOMOBILIAMS (fizinė diagnostika su OBD įrenginiu)
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
- Vilnius, Kaunas, Šiauliai, Panevėžys, Klaipėda, Kėdainiai – po vieną stotelę miesto centre
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
- 299 €/mėn = STOTELIŲ abonementas (fizinei diagnostikai DiaGO stotelėse, iki 20 automobilių)
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
        ).with_model("gemini", "gemini-2.5-flash")

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

🔴 ŠALTINIO TAISYKLĖ (PRIVALOMA):
Atsakyk TIK remdamasis oficialiais gamintojo klaidų kodų žinynais (OEM service manuals, OBD-II SAE J2012 standarto, gamintojo techninio biuletenio TSB ar oficialios diagnostinės dokumentacijos). Jei informacija prieštaringa tarp šaltinių, pateik ABI versijas su paaiškinimu, kada kuri taikoma (pvz., „pagal SAE J2012 bendrą standartą... TAČIAU pagal Audi TSB 2017-08... taikoma tokiai variklio versijai"). Niekada neišgalvok kodų aprašymų, OEM detalių numerių ar techninių parametrų – jei nesi tikras, geriau pasakyk, kad reikia papildomos informacijos arba pažymėk kodą kaip nežinomą.

SVARBU – TIKSLUMAS:
- Visada pirmiausia patikrinkite, ar pateiktas kodas tikrai egzistuoja konkrečiam technikos tipui ir gamintojui (P-/U-/B-/C- kodai automobiliams ir komercinei technikai; gamintojo specifiniai kodai – pvz., Linde T-kodai, Caterpillar E-kodai, John Deere DTC ir kt.).
- Jei kodas yra GAMINTOJO SPECIFINIS – atsižvelkite į konkretų gamintoją ir modelį, NE į bendrinį standarto aprašymą.
- **JEI KODAS NEEGZISTUOJA, neaiškus, nesusijęs su pateikta technika ar yra rašymo klaida** – tas konkretus kodas turi būti pažymėtas kaip nežinomas DiaGO_META bloke (žr. žemiau). Jei VISI įvesti kodai yra nežinomi – pradėkite atsakymą būtent eilute `## NEZINOMAS KODAS` (be jokio kito teksto prieš ją), po to paaiškinkite kodėl ir ką klientas turėtų padaryti. Šis žymėjimas yra KRITIŠKAS – pagal jį sistema NESKAIČIUOJA tų patikrinimų kaip naudotų.
- OEM detalių kodus pateikite TIK jei esate įsitikinę dėl tikslumo. Neegzistuojančių dalių kodų neišgalvokite.

KELIŲ KODŲ ANALIZĖ (svarbiausia):
- Klientas gali įvesti kelis (iki 5) kodus vienu metu, kableliais atskirtus (pvz., „P0301, P0171, P0420").
- Analizuokite VISUS kodus VIENOJE bendroje ataskaitoje – susiekite juos, jei jie tarpusavyje susiję (pvz., P0301 + P0171 dažnai kartu rodo degalų sistemos arba uždegimo sistemos problemą; tokiu atveju paminėkite tai „Galima priežastis" skiltyje).
- Jei klientas pateikia ir gedimo simptomų aprašymą – privaloma jį panaudoti analizėje (jis dažnai padeda atskirti, kuri iš galimų priežasčių labiausiai tikėtina).
- Jei pateiktas VIN ar serijinis numeris – jį galite panaudoti tik kaip pagalbą identifikuojant tikslesnį modelį/variklį (pvz., VIN 4–8 simboliai dažnai koduoja gamintoją ir modelio versiją). Niekada neskelbkite paties VIN'o atsakyme (privatumas).

VIN/SERIJINIO NUMERIO TAISYKLĖS:
- Jei VIN turi ≠17 simbolių arba turi raides I/O/Q – traktuokite kaip serijinį numerį, ne VIN.
- Tikras VIN gali padėti tiksliau identifikuoti gamintoją, modelio versiją, variklio kodą; bet jei kliento įvestas markė/modelis prieštarauja VIN kodui – pasižymėkite tai „Pataisyta technikos info" skiltyje.

VIDINIS METADATA BLOKAS (PRIVALOMA):
PIRMIAUSIA atsakymo viršuje (prieš bet kokią kitą skiltį) pateikite paslėptą bloką šia forma:

## DiaGO_META
known: <atpažintų kodų sąrašas atskirtas kableliais arba palik tuščią>
unknown: <neatpažintų kodų sąrašas atskirtas kableliais arba palik tuščią>
severity_critical: <RIMTŲ kodų sąrašas atskirtas kableliais arba tuščia>
severity_warning: <ĮSPĖJIMŲ kodų sąrašas atskirtas kableliais arba tuščia>
severity_info: <INFORMACINIŲ kodų sąrašas atskirtas kableliais arba tuščia>

(Sistema šį bloką pašalins prieš rodydama klientui – jis NĖRA matomas vartotojui. Jis naudojamas: viena atpažinta klaida = 1 kvotos vienetas, neatpažintos – nemokamos. Severity laukai naudojami suvestinės kortelei: rimtos / įspėjimai / informacinės.)

TECHNIKOS DUOMENŲ TIKSLINIMAS:
- Klientas pateikia gamintoją, modelį ir metus. Dažnai daro rašymo klaidų (pvz., „Audy" → „Audi", „bmv" → „BMW", „pasat" → „Passat", „lynde" → „Linde").
- **JEI ATPAŽĮSTATE rašymo klaidą arba galite tiksliau identifikuoti modelį pagal kodą+kontekstą** – pataisykite tyliai (vidiniame procese) IR pridėkite po META bloko šį specialų bloką:
  ```
  ## Pataisyta technikos info
  Pastebėjome, kad turbūt turėjote omenyje: <tiksli markė> <tikslus modelis> <metai>. Analizė atlikta būtent šiai technikai.
  ```

ATSAKYMO STRUKTŪRA (privaloma):

Jei VIENAS kodas → naudokite paprastą formatą (žr. „Vieno kodo formatas" žemiau).
Jei DAUGIAU NEI VIENAS kodas → naudokite išplėstą formatą (žr. „Kelių kodų formatas" žemiau).

================================================
A) VIENO KODO FORMATAS (kai pateiktas tik 1 kodas):
================================================

## Klaidos paaiškinimas
Trumpai (2–3 sakiniai) paaiškinkite, ką reiškia šis klaidos kodas paprasta kalba.

## Galima priežastis
Išvardinkite 2–4 dažniausias galimas priežastis (kiekvieną kaip „•" punktą).

## Ar saugu važiuoti?
Vienas iš: ✅ TAIP, saugu / ⚠️ ATSARGIAI / 🛑 NE, sustokite — su trumpu paaiškinimu.

## Rekomendacijos
3–5 konkrečių veiksmų sąrašas su „•".

## Poveikis
1–2 sakinių aprašymas, kaip klaida paveiks techniką, jei nebus išspręsta.

## Atsargumo priemonės
1–2 sakinių praktinis patarimas operatoriui ar vairuotojui.

## Remonto kaina (orientacinė)
EUR diapazonas (pvz., „80–250 €").

## Galimai sugedusi detalė
Markdown LENTELĖ:
| Detalė | OEM kodas | Gamintojas | Pastaba |
|---|---|---|---|
| ... | ... | ... | ... |

Jei TIKRAI neįmanoma – vietoj lentelės parašykite: NĖRA TIKSLIŲ KODŲ

## Vieta technikoje
1–2 sakiniai – kur fiziškai detalė technikoje.

## Paieškos užklausa
Pateikite TIK jei lentelėje nėra OEM kodų. Vienoje eilutėje – Google paieškos užklausa.

================================================
B) KELIŲ KODŲ FORMATAS (kai pateikta 2–5 kodai):
================================================

## Bendra apžvalga
2–4 sakiniai – paaiškinkite, kaip kodai tarpusavyje susiję, kuri pagrindinė problemos šaknis ir kokios sistemos paveiktos. Jei kodai NESUSIJĘ – aiškiai pasakykite tai („Šie kodai nėra tiesiogiai susiję; kiekvienas reikalauja atskiros analizės").

Tada KIEKVIENAM atpažintam kodui pateikite atskirą bloką tokia struktūra:

## Kodas: <KODAS> [<RIMTUMO ŽYMĖ>]
**Sistema:** <pvz., EGR, Transmisija, Variklio valdymas>
**Paaiškinimas:** 1–2 sakiniai paprasta kalba.
**Galimos priežastys:**
• Priežastis 1
• Priežastis 2
**Rekomendacijos:**
• Veiksmas 1
• Veiksmas 2
**Vieta technikoje:** Trumpas aprašymas, kur ieškoti.
**Orientacinė kaina:** EUR diapazonas.

Rimtumo žymos: 🛑 RIMTA / ⚠️ ĮSPĖJIMAS / ℹ️ INFORMACINĖ. Žymą pridėkite ant tos pačios eilutės su kodu antraštėje (pvz., `## Kodas: P0301 🛑 RIMTA`).

NEŽINOMIEMS kodams atskirų blokų NEKURKITE – tik užfiksuokite juos DiaGO_META unknown sąraše.

Po visų kodų blokų – BENDROS skiltys (apima visus kodus):

## Galimai sugedusios detalės
Vienoje BENDROJE lentelėje pateikite detales VISIEMS atpažintiems kodams. Pridėkite stulpelį „Susijęs kodas":

| Detalė | OEM kodas | Gamintojas | Pastaba | Susijęs kodas |
|---|---|---|---|---|
| ... | ... | ... | ... | P0301 |

Jei TIKRAI neįmanoma – parašykite: NĖRA TIKSLIŲ KODŲ

## Bendra išvada ir prioritetai
**Prioritetas Nr. 1:** <kuri klaida turi būti taisoma pirmiausia ir kodėl, su konkrečiu kodu>
**Prioritetas Nr. 2:** <antra prioriteto klaida ir kodėl, jei reikia>
**Ar saugu naudoti dabar:** Vienas iš: ✅ TAIP / ⚠️ ATSARGIAI / 🛑 NE — su 1–2 sakinių paaiškinimu, atsižvelgiant į VISŲ kodų rimtumą bendrai.
**Bendra orientacinė remonto kaina:** Pateikite SUMĄ pridėjus visų atskirų kodų kainų diapazonus (pvz., jei kodas A = 80–250 € ir kodas B = 200–800 €, bendra suma = 280–1050 €). Pateikite vienoje eilutėje EUR formatu.

## Paieškos užklausa
Pateikite TIK jei „Galimai sugedusios detalės" lentelėje nėra nė vieno tikslaus OEM kodo. Vienoje eilutėje – konkreti Google paieškos užklausa.
"""


class ErrorCheckRequest(BaseModel):
    session_id: str
    equipment_type: str
    error_code: str  # vienas kodas arba keli kableliais atskirti (max 5)
    vehicle_info: str | None = None
    visitor_id: str | None = None  # nemokamų užklausų sekiojimui
    vin: str | None = None  # neprivaloma – VIN arba serijinis numeris (max 50)
    fault_description: str | None = None  # neprivaloma – simptomų aprašymas (max 500)
    image_base64: str | None = None  # neprivaloma – nuotraukos su klaidomis kodų ekranu (TIK prisijungusiems)


class ErrorCheckResponse(BaseModel):
    analysis: str
    search_query: str
    google_search_url: str
    google_images_url: str
    quota: dict | None = None  # { logged_in, unlimited, limit, used, remaining, deducted }
    is_unknown_code: bool = False  # true, jei VISI įvesti kodai pažymėti kaip nežinomi
    codes: list[str] | None = None  # visi įvesti kodai
    known_codes: list[str] | None = None  # AI atpažinti kodai
    unknown_codes: list[str] | None = None  # AI nežinomi kodai
    severity_map: dict[str, str] | None = None  # {kodas: 'critical'|'warning'|'info'}
    deducted_units: int = 0  # kiek kvotos vienetų atskaityta (=len(known_codes))


def _extract_search_query(analysis_text: str, fallback: str) -> str:
    m = re.search(r"##\s*Paieškos užklausa\s*\n+([^\n#]+)", analysis_text, re.IGNORECASE)
    if m:
        q = m.group(1).strip().strip('"„"').strip()
        if q:
            return q
    return fallback


_VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)


def _parse_codes(raw: str, max_codes: int = 5) -> list[str]:
    """Iš teksto su kableliais ištraukia unikalius kodus didžiosiomis raidėmis (max N)."""
    if not raw:
        return []
    parts = re.split(r"[,\s;]+", raw.strip())
    seen = set()
    out: list[str] = []
    for p in parts:
        c = p.strip().upper()
        if not c:
            continue
        if len(c) > 40:
            continue
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
        if len(out) >= max_codes:
            break
    return out


# Maksimalus kodų skaičius vienai užklausai pagal įvedimo būdą
MAX_CODES_TYPED = 5    # ranka įvedant
MAX_CODES_IMAGE = 10   # iš nuotraukos (gali daugiau, jei matosi)


def _parse_diago_meta(analysis: str) -> tuple[str, list[str], list[str], dict]:
    """
    Iš atsakymo ištraukia DiaGO_META bloką ir grąžina (švarus_atsakymas, known_codes, unknown_codes, severity_map).
    severity_map: { "P0420": "warning", "P0301": "critical", ... }
    Bloko pavyzdys:
      ## DiaGO_META
      known: P0420, P0301
      unknown: XXXX99
      severity_critical: P0301
      severity_warning: P0420
      severity_info:
    """
    if not analysis:
        return analysis or "", [], [], {}
    m = re.search(
        r"##\s*DiaGO[_\s-]?META\s*\n+(.*?)(?=\n##\s|$)",
        analysis,
        re.IGNORECASE | re.DOTALL,
    )
    known: list[str] = []
    unknown: list[str] = []
    severity: dict[str, str] = {}
    if m:
        block = m.group(1)
        def _parse_line(label: str) -> list[str]:
            # SVARBU: naudojam `[ \t]*` (tik tarpai/tab), ne `\s*`, kad neapimtų newline
            mm = re.search(rf"^[ \t]*{label}[ \t]*:[ \t]*([^\n]*)", block, re.IGNORECASE | re.MULTILINE)
            if not mm:
                return []
            return [c.strip().upper() for c in re.split(r"[,\s;]+", mm.group(1)) if c.strip()]
        known = _parse_line("known")
        unknown = _parse_line("unknown")
        for c in _parse_line("severity_critical"):
            severity[c] = "critical"
        for c in _parse_line("severity_warning"):
            severity[c] = "warning"
        for c in _parse_line("severity_info"):
            severity[c] = "info"
        # Pašalinam meta bloką iš atsakymo (kad vartotojas nematytų)
        analysis = analysis.replace(m.group(0), "").lstrip()
    return analysis, known, unknown, severity


@api_router.post("/check-error", response_model=ErrorCheckResponse)
async def check_error(req: ErrorCheckRequest, request: Request, authorization: str | None = Header(default=None)):
    raw_codes = (req.error_code or "").strip()
    eq = (req.equipment_type or "").strip().lower()
    veh = (req.vehicle_info or "").strip()
    vin_raw = (req.vin or "").strip().upper()[:50]
    fault_desc = (req.fault_description or "").strip()[:500]
    img_b64 = (req.image_base64 or "").strip()
    has_image = bool(img_b64)

    if not raw_codes and not has_image:
        raise HTTPException(status_code=400, detail="Įveskite klaidos kodą arba įkelkite nuotrauką su klaidomis.")
    if eq not in EQUIPMENT_LABELS:
        raise HTTPException(status_code=400, detail="Neteisingas technikos tipas.")

    # Image limit check (~6 MB base64 ≈ 4.5 MB raw — Gemini limit is 20MB but kept lower)
    if has_image and len(img_b64) > 8_000_000:
        raise HTTPException(status_code=413, detail="Nuotrauka per didelė. Maksimalus dydis ~6 MB.")

    # Strip data URL prefix if present
    if has_image and img_b64.startswith("data:"):
        try:
            img_b64 = img_b64.split(",", 1)[1]
        except Exception:
            pass

    # Limitas priklauso nuo įvedimo būdo
    max_codes_limit = MAX_CODES_IMAGE if has_image else MAX_CODES_TYPED
    codes = _parse_codes(raw_codes, max_codes=max_codes_limit) if raw_codes else []
    if not codes and not has_image:
        raise HTTPException(status_code=400, detail="Nepavyko atpažinti nė vieno klaidos kodo.")
    if len(codes) > max_codes_limit:
        codes = codes[:max_codes_limit]

    # Vienam užklausos atvaizdavimui paliekam pirmą kodą kaip „pagrindinį" – analitikai/UI
    code = codes[0] if codes else "[NUOTRAUKA]"
    # Jei tik nuotrauka – preliminariai užtikrinam bent 1 vienetą; tikslus skaičius nustatomas po AI atsakymo
    units_needed = max(1, len(codes))

    # VIN klasifikacija
    is_real_vin = bool(_VIN_RE.match(vin_raw)) if vin_raw else False

    # === Free quota patikra (jei NEPRISIJUNGĘS) arba abonemento patikra (jei prisijungęs) ===
    user = await _get_current_user(authorization)

    # Nuotraukos įkėlimas TIK prisijungusiems vartotojams
    if has_image and not user:
        raise HTTPException(
            status_code=401,
            detail="Nuotraukos įkėlimas prieinamas TIK prisijungusiems vartotojams. Prisijunkite arba užsiregistruokite (nemokamai iki 2026-06-01).",
        )

    db = _get_db()
    quota_info = None
    quota_doc = None
    if user and db is not None:
        user = await _maybe_reset_monthly_quota(db, user)
        if user.get("subscription_active"):
            sub_quota = int(user.get("subscription_quota", 0))
            sub_used = int(user.get("subscription_used_this_month", 0))
            if sub_quota > 0 and (sub_used + units_needed) > sub_quota:
                remaining_slots = max(0, sub_quota - sub_used)
                raise HTTPException(
                    status_code=402,
                    detail=(
                        f"Įvedėte {units_needed} kodus, bet abonemento limite liko tik {remaining_slots} "
                        f"({sub_used}/{sub_quota}). Sumažinkite kodų skaičių arba pratęskite abonementą."
                    ),
                )
    elif not user:
        if db is not None:
            ip = request.client.host if request.client else ""
            ip_hash = _hash_ip(ip)
            visitor_id = (req.visitor_id or "").strip()[:64]
            quota_doc = await _get_or_create_quota(db, ip_hash, visitor_id)
            used = int(quota_doc.get("count", 0))
            if (used + units_needed) > FREE_QUOTA_LIMIT:
                remaining_slots = max(0, FREE_QUOTA_LIMIT - used)
                if remaining_slots == 0:
                    raise HTTPException(
                        status_code=402,
                        detail=(
                            f"Išnaudoti visi {FREE_QUOTA_LIMIT} nemokami patikrinimai. "
                            "Prašome prisiregistruoti nemokamai (iki 2026-06-01) – tęskite naudojimąsi be ribų."
                        ),
                    )
                raise HTTPException(
                    status_code=402,
                    detail=(
                        f"Įvedėte {units_needed} kodus, bet nemokamame likime liko tik {remaining_slots} "
                        f"({used}/{FREE_QUOTA_LIMIT}). Sumažinkite kodų skaičių arba prisiregistruokite."
                    ),
                )

    api_key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not api_key:
        raise HTTPException(status_code=500, detail="LLM raktas nesukonfigūruotas.")

    eq_label = EQUIPMENT_LABELS[eq]
    codes_str = ", ".join(codes) if codes else "(NENURODYTI – išgaukite iš nuotraukos)"
    user_prompt = f"Technikos tipas: {eq_label}"
    if codes:
        user_prompt += f"\nKlaidos kodai ({len(codes)} vnt.): {codes_str}"
    elif has_image:
        user_prompt += f"\nKlaidos kodai: NEPATEIKTI – PRIVALOMA juos išgauti iš pridėtos nuotraukos (klientas įkėlė skenerio ekrano nuotrauką)."
    if veh:
        user_prompt += f"\nMarkė/modelis/metai: {veh}"
    if vin_raw:
        if is_real_vin:
            user_prompt += f"\nVIN (17 simb., naudokite tik vidiniam tikslinimui, neminėkite atsakyme): {vin_raw}"
        else:
            user_prompt += f"\nSerijinis numeris: {vin_raw}"
    if fault_desc:
        user_prompt += f"\nKliento aprašyti simptomai: {fault_desc}"
    if has_image:
        user_prompt += (
            "\n\nNUOTRAUKA: prie užklausos pridėta nuotrauka su klaidomis (skenerio ekranas, dashboard ar pan.). "
            "PRIVALOMA INSTRUKCIJA NUOTRAUKAI:\n"
            "1) Atidžiai išnagrinėkite VISĄ nuotrauką ir išgaukite VISUS matomus klaidos kodus (iki 10).\n"
            "2) PRIE KIEKVIENO KODO BŪTINAI nuskaitykite ir aprašymo tekstą, esantį šalia kodo (pvz., 'Forward gear solenoid valve. Current too low' ar 'Coolant temperature sensor. Incorrect or missing CAN message'). Šis aprašymas yra GAMINTOJO oficialus tekstas ir TURI PIRMENYBĘ prieš jūsų bendrą žinojimą apie kodą – jei jūsų žinojimas konfliktuoja su nuotraukoje matomu aprašymu, vadovaukitės nuotraukos tekstu (skenerio aprašymai dažnai būna SPN.FMI gamintojo specifika, kuri skiriasi nuo bendrų OBD-II kodų).\n"
            "3) Į DiaGO_META known sąrašą įrašykite kodus, kuriuos pamatėte ir kuriems galite atlikti analizę (turite gamintojo aprašymą iš nuotraukos arba savo žinių).\n"
            "4) Į unknown – tik tuos, kurie nuotraukoje neaiškūs ar netinkami (per neryškūs, nukirpti).\n"
            "5) Kiekvieno kodo bloke pradžioje paminėkite tikslų aprašymą iš skenerio ekrano (pvz., **Skenerio aprašymas:** \"Forward gear solenoid valve. Current too low\"), tada toliau atlikite pilną analizę pagal struktūrą.\n"
            "6) Jeigu yra pasikartojimo skaičius (pvz., 'x79' arba 'x46') – tai parodo, kiek kartų klaida pasikartojo; rimtumo vertinimui dažnai pasikartojanti klaida yra svarbesnė, paminėkite tai skiltyje 'Galimos priežastys' ar 'Rekomendacijos'."
        )
    user_prompt += (
        "\n\nPateik išsamią analizę pagal nurodytą struktūrą. "
        "PRIVALOMA: pirmoje atsakymo dalyje pateik ## DiaGO_META bloką su known/unknown kodų sąrašais bei severity_critical/warning/info. "
        "Jei daugiau nei vienas kodas – analizuok juos kartu, susiek susijusius gedimus, atsižvelk į simptomus."
    )

    sid = (req.session_id or "err-default").strip() or "err-default"

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=sid,
            system_message=ERROR_ANALYZER_PROMPT,
        ).with_model("gemini", "gemini-2.5-pro").with_params(temperature=0.0, top_p=1)

        # Sukuriam UserMessage – su nuotrauka, jei pateikta
        if has_image:
            try:
                msg = UserMessage(text=user_prompt, file_contents=[ImageContent(image_base64=img_b64)])
            except Exception as ie:
                logger.exception("ImageContent failure")
                raise HTTPException(status_code=400, detail=f"Nepavyko apdoroti nuotraukos: {str(ie)[:120]}")
        else:
            msg = UserMessage(text=user_prompt)

        analysis = await chat.send_message(msg)

        # Ištraukiam ir pašalinam DiaGO_META bloką
        analysis, known_codes, unknown_codes_meta, severity_map = _parse_diago_meta(analysis or "")

        # Jei tik nuotrauka (be teksto kodų) – kodų sąrašą formuojam iš AI grąžintų kodų
        if not codes and (known_codes or unknown_codes_meta):
            codes = (known_codes + unknown_codes_meta)[:5]
            if codes:
                code = codes[0]

        # Patikrinam, ar AI pradėjo su `## NEZINOMAS KODAS` (visi kodai nežinomi)
        analysis_stripped = (analysis or "").lstrip()
        all_unknown_marker = analysis_stripped.upper().startswith("## NEZINOMAS KODAS") \
                             or analysis_stripped.upper().startswith("##NEZINOMAS KODAS")

        # Apibendriname known/unknown
        codes_set = {c.upper() for c in codes}
        known_set = {c for c in known_codes if c in codes_set}
        unknown_set = {c for c in unknown_codes_meta if c in codes_set}
        # Jei meta nepateikta arba tuščia – fallback
        if not known_set and not unknown_set:
            if all_unknown_marker:
                unknown_set = set(codes)
            else:
                known_set = set(codes)
        # Sutvarkome – jeigu kodų sąraše yra dubliuotų ar trūkstamų
        for c in codes:
            if c not in known_set and c not in unknown_set:
                # AI nepasakė – traktuojame kaip žinomą (fail-safe)
                known_set.add(c)

        known_codes_list = [c for c in codes if c in known_set]
        unknown_codes_list = [c for c in codes if c in unknown_set]
        deducted = len(known_codes_list)
        is_unknown_code = (deducted == 0)

        fallback_q = f"{codes_str} {eq_label} {veh}".strip()
        search_q = _extract_search_query(analysis, fallback_q)

        gs = "https://www.google.com/search?q=" + quote_plus(search_q)
        gi = "https://www.google.com/search?tbm=isch&q=" + quote_plus(search_q)

        # Log į DB analitikai (vienas įrašas per kodą) + quota inkrementas
        if db is not None:
            try:
                now = datetime.now(timezone.utc)
                # Įrašome kiekvieną kodą atskirai analitikai
                docs = []
                for c in codes:
                    docs.append({
                        "session_id": sid,
                        "user_id": user.get("user_id") if user else None,
                        "error_code": c,
                        "equipment": eq,
                        "vehicle_info": veh[:200] if veh else None,
                        "vin_provided": bool(vin_raw),
                        "is_vin": is_real_vin,
                        "fault_description_provided": bool(fault_desc),
                        "is_unknown_code": c in unknown_set,
                        "batch_size": len(codes),
                        "created_at": now,
                    })
                if docs:
                    await db.error_checks.insert_many(docs)

                # Kvotos atskaitymas tik už atpažintus kodus
                if deducted > 0:
                    if user:
                        await db.users.update_one(
                            {"user_id": user["user_id"]},
                            {"$inc": {"checks_count": deducted, "subscription_used_this_month": deducted},
                             "$set": {"last_check_at": now}},
                        )
                        new_used = int(user.get("subscription_used_this_month", 0)) + deducted
                        sub_quota = int(user.get("subscription_quota", 0))
                        quota_info = {
                            "logged_in": True,
                            "unlimited": (sub_quota == 0),
                            "limit": sub_quota or None,
                            "used": new_used,
                            "remaining": max(0, sub_quota - new_used) if sub_quota > 0 else None,
                            "deducted": deducted,
                        }
                    else:
                        ip = request.client.host if request.client else ""
                        ip_hash = _hash_ip(ip)
                        visitor_id = (req.visitor_id or "").strip()[:64]
                        for _ in range(deducted):
                            await _increment_quota(db, ip_hash, visitor_id)
                        new_used = int(quota_doc.get("count", 0)) + deducted if quota_doc else deducted
                        quota_info = {
                            "logged_in": False,
                            "unlimited": False,
                            "limit": FREE_QUOTA_LIMIT,
                            "used": new_used,
                            "remaining": max(0, FREE_QUOTA_LIMIT - new_used),
                            "deducted": deducted,
                        }
                else:
                    # Nebuvo atskaityta nieko – visi kodai nežinomi
                    if user:
                        sub_quota = int(user.get("subscription_quota", 0))
                        sub_used = int(user.get("subscription_used_this_month", 0))
                        quota_info = {
                            "logged_in": True,
                            "unlimited": (sub_quota == 0),
                            "limit": sub_quota or None,
                            "used": sub_used,
                            "remaining": max(0, sub_quota - sub_used) if sub_quota > 0 else None,
                            "deducted": 0,
                            "not_charged": True,
                        }
                    elif quota_doc is not None:
                        used_now = int(quota_doc.get("count", 0))
                        quota_info = {
                            "logged_in": False,
                            "unlimited": False,
                            "limit": FREE_QUOTA_LIMIT,
                            "used": used_now,
                            "remaining": max(0, FREE_QUOTA_LIMIT - used_now),
                            "deducted": 0,
                            "not_charged": True,
                        }
            except Exception:
                logger.exception("error_checks logging failed")

        return ErrorCheckResponse(
            analysis=analysis,
            search_query=search_q,
            google_search_url=gs,
            google_images_url=gi,
            quota=quota_info,
            is_unknown_code=is_unknown_code,
            codes=codes,
            known_codes=known_codes_list,
            unknown_codes=unknown_codes_list,
            severity_map={c: severity_map.get(c, "info") for c in known_codes_list},
            deducted_units=deducted,
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
    ("Stotelės / vietos", ["stotel", "vilnius", "kaun", "klaipėd", "klaipėd", "panevėž", "panevez", "šiauli", "siauli", "kėdaini", "kedaini", "vieta", "miest", "adres"]),
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
                ).with_model("gemini", "gemini-2.5-flash")
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
    db = _get_db()
    if db is not None:
        user = await _maybe_reset_monthly_quota(db, user)
    user.pop("_id", None)
    # Pridedam abonemento dienų likučius (kiek dienų iki pabaigos)
    days_until_renew = None
    renews_at = user.get("subscription_renews_at")
    if isinstance(renews_at, datetime):
        delta = renews_at - datetime.now(timezone.utc)
        days_until_renew = max(0, delta.days)
    return {"user": user, "days_until_renew": days_until_renew}


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

    # Pažymim, kurie vartotojai turi neuždarytą (pending) abonemento pratęsimo užklausą
    try:
        pending_cur = db.renewal_requests.find({"status": "pending"}, {"_id": 0, "user_id": 1})
        pending_user_ids = {r.get("user_id") for r in await pending_cur.to_list(1000) if r.get("user_id")}
    except Exception:
        pending_user_ids = set()
    for u in items:
        u["has_pending_renewal"] = u.get("user_id") in pending_user_ids

    return {"items": items, "pending_renewals_count": len(pending_user_ids)}


class AdminResetPasswordRequest(BaseModel):
    user_id: str
    new_password: str


class AdminSubscriptionRequest(BaseModel):
    user_id: str
    subscription_active: bool
    subscription_price: float | None = None  # €/mėn
    subscription_quota: int | None = None    # nemokamų patikrinimų per mėn (0 = neribota)
    subscription_note: str | None = None


def _next_month_first(now: datetime | None = None) -> datetime:
    """Grąžina kito kalendorinio mėnesio 1 d. 00:00 UTC."""
    now = now or datetime.now(timezone.utc)
    if now.month == 12:
        return datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    return datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)


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


@api_router.post("/admin/users/subscription")
async def admin_users_subscription(req: AdminSubscriptionRequest, authorization: str | None = Header(default=None)):
    """Admin'as nustato vartotojo abonementą (varnelę, kainą, mėnesio kvotą)."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    update = {
        "subscription_active": bool(req.subscription_active),
        "subscription_updated_at": datetime.now(timezone.utc),
    }
    if req.subscription_active:
        update["subscription_price"] = max(0.0, float(req.subscription_price or 0))
        update["subscription_quota"] = max(0, int(req.subscription_quota or 0))
        update["subscription_renews_at"] = _next_month_first()
        # Reset'as – aktyvuojant naują abonementą, einamasis mėnuo prasideda nuo 0
        update["subscription_used_this_month"] = 0
        if req.subscription_note is not None:
            update["subscription_note"] = (req.subscription_note or "").strip()[:500]
    else:
        # Deaktyvavus – išvalom kvotą, nors istorijos paliekam
        update["subscription_price"] = 0
        update["subscription_quota"] = 0
    res = await db.users.update_one({"user_id": req.user_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vartotojas nerastas.")
    return {"ok": True, "subscription_active": req.subscription_active}


class RenewalRequest(BaseModel):
    note: str | None = None


@api_router.post("/auth/renewal-request")
async def auth_renewal_request(req: RenewalRequest, authorization: str | None = Header(default=None)):
    """Vartotojas pateikia abonemento pratęsimo užklausą (admin'as ją mato)."""
    user = await _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Nepatvirtinta sesija.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    await db.renewal_requests.insert_one({
        "user_id": user["user_id"],
        "email": user["email"],
        "current_subscription_active": user.get("subscription_active", False),
        "current_subscription_price": user.get("subscription_price", 0),
        "renews_at": user.get("subscription_renews_at"),
        "note": (req.note or "").strip()[:500],
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
    })
    return {"ok": True, "message": "Užklausa gauta. Susisieksime artimiausiu metu."}


@api_router.get("/admin/renewal-requests")
async def admin_renewal_requests(limit: int = 100, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.renewal_requests.find({}, {"_id": 0}).sort("created_at", -1).limit(max(1, min(limit, 500)))
    items = await cur.to_list(500)
    return {"items": items}


class RenewalDoneRequest(BaseModel):
    user_id: str


@api_router.post("/admin/renewal-requests/mark-done")
async def admin_renewal_mark_done(req: RenewalDoneRequest, authorization: str | None = Header(default=None)):
    """Pažymi visas vartotojo pending pratęsimo užklausas kaip atliktas."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    res = await db.renewal_requests.update_many(
        {"user_id": req.user_id, "status": "pending"},
        {"$set": {"status": "done", "done_at": datetime.now(timezone.utc)}},
    )
    return {"ok": True, "updated": res.modified_count}


async def _maybe_reset_monthly_quota(db, user: dict) -> dict:
    """Jei einamasis mėnesinis ciklas baigėsi (subscription_renews_at praeity) – reset'inam kvotą."""
    if not user or not user.get("subscription_active"):
        return user
    renews_at = user.get("subscription_renews_at")
    if not renews_at:
        return user
    if isinstance(renews_at, str):
        try:
            renews_at = datetime.fromisoformat(renews_at.replace("Z", "+00:00"))
        except Exception:
            return user
    now = datetime.now(timezone.utc)
    if renews_at and renews_at <= now:
        new_renews_at = _next_month_first(now)
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {
                "subscription_renews_at": new_renews_at,
                "subscription_used_this_month": 0,
            }},
        )
        user["subscription_renews_at"] = new_renews_at
        user["subscription_used_this_month"] = 0
    return user


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
