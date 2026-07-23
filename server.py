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
  PUBLIC_SITE_URL       - Pagrindinis svetainės URL (default: https://www.diago.lt)
                          Naudojamas patvirtinimo nuorodose laiškuose.

SMTP el. pašto siuntimui (registracijos patvirtinimas, priminimai):
  SMTP_HOST             - pvz. baobabas.serveriai.lt
  SMTP_PORT             - 587 (STARTTLS) arba 465 (SSL)
  SMTP_USER             - pvz. jt@diago.lt
  SMTP_PASSWORD         - SMTP slaptažodis
  SMTP_USE_SSL          - "true" jei port 465, "false" jei 587 STARTTLS (default: false)
  SMTP_FROM_NAME        - rodomas siuntėjas (default: DiaGO)

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
import ssl
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from urllib.parse import quote_plus
from email.message import EmailMessage

from fastapi import FastAPI, APIRouter, HTTPException, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from emergentintegrations.llm.chat import LlmChat, UserMessage, ImageContent

try:
    import aiosmtplib  # type: ignore
except ImportError:
    aiosmtplib = None  # type: ignore

try:
    import dns.resolver  # type: ignore
except ImportError:
    dns = None  # type: ignore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================
# Datetime helperis – visada UTC su Z suffix'u
# ============================
def _iso_utc(dt: datetime | None) -> str | None:
    """Konvertuoja datetime į ISO string'ą su 'Z' suffix'u (UTC).
    Jei dt yra naive (be tz info), laikom kaip UTC.
    JS toLocaleString() tada automatiškai parodys vartotojo laiko zonoje.
    """
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}"[:3] + "Z"

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
# SMTP el. pašto siuntimas (registracijos patvirtinimas, priminimai)
# ============================
def _smtp_config():
    """Grąžina SMTP konfigūraciją iš env. None, jei nenustatyta."""
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USER", "").strip()
    pw = os.environ.get("SMTP_PASSWORD", "")
    if not host or not user or not pw:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("SMTP_PORT", "587") or 587),
        "user": user,
        "password": pw,
        "use_ssl": (os.environ.get("SMTP_USE_SSL", "false") or "false").lower() in ("1", "true", "yes"),
        "from_name": os.environ.get("SMTP_FROM_NAME", "DiaGO"),
    }


async def _send_email(to_email: str, subject: str, html_body: str, text_body: str | None = None) -> bool:
    """Asinchroninis SMTP siuntimas. Grąžina True, jei sėkmingai išsiųstas."""
    cfg = _smtp_config()
    if not cfg:
        logger.warning("⚠️  SMTP_HOST/SMTP_USER nenustatyti – laiškas nesiunčiamas (%s)", to_email)
        return False
    if aiosmtplib is None:
        logger.warning("⚠️  aiosmtplib biblioteka neįdiegta – laiškas nesiunčiamas")
        return False

    msg = EmailMessage()
    msg["From"] = f"{cfg['from_name']} <{cfg['user']}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body or "Šis laiškas siunčiamas HTML formatu. Naudokite HTML pajėgų pašto klientą.")
    msg.add_alternative(html_body, subtype="html")

    try:
        if cfg["use_ssl"]:
            # SSL nuo pat pradžių (port 465)
            await aiosmtplib.send(
                msg, hostname=cfg["host"], port=cfg["port"],
                username=cfg["user"], password=cfg["password"],
                use_tls=True, timeout=30,
            )
        else:
            # STARTTLS (port 587)
            await aiosmtplib.send(
                msg, hostname=cfg["host"], port=cfg["port"],
                username=cfg["user"], password=cfg["password"],
                start_tls=True, timeout=30,
            )
        logger.info("✉️  El. laiškas išsiųstas: %s [%s]", to_email, subject)
        return True
    except Exception as e:
        logger.exception("SMTP siuntimo klaida (%s): %s", to_email, e)
        return False


# Disposable / fake domenai – nepriimam registracijų
_DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "throwawaymail.com", "sharklasers.com", "yopmail.com", "trashmail.com",
    "dispostable.com", "fakeinbox.com", "tempmailo.com", "temp-mail.org",
    "mailtemp.info", "mintemail.com", "spambox.us", "maildrop.cc",
    "getairmail.com", "tempmail.io", "tempmailaddress.com", "spam4.me",
    "mohmal.com", "harakirimail.com", "emailondeck.com", "luxusmail.org",
    "burnermail.io", "moakt.com", "tempmail.dev", "fakemailgenerator.com",
}


async def _validate_email_advanced(email: str) -> tuple[bool, str]:
    """Patikrina el. paštą: sintaksė + MX įrašas + disposable blacklist.
    Grąžina (ok, error_message_if_not_ok).
    """
    e = (email or "").strip().lower()
    # 1) Sintaksė per email-validator
    try:
        from email_validator import validate_email, EmailNotValidError  # type: ignore
        try:
            valid = validate_email(e, check_deliverability=False)
            normalized = valid.normalized.lower()
        except EmailNotValidError as ex:
            return False, "Neteisingas el. pašto formatas."
    except ImportError:
        # Fallback – paprastas regex
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", e):
            return False, "Neteisingas el. pašto formatas."
        normalized = e

    domain = normalized.rsplit("@", 1)[-1]

    # 2) Disposable blacklist
    if domain in _DISPOSABLE_DOMAINS:
        return False, "Laikinieji (disposable) el. pašto adresai nepriimami. Naudokite tikrą el. paštą."

    # 3) MX įrašas (jei dnspython yra ir nedraudžiama)
    if dns is not None and os.environ.get("SKIP_MX_CHECK", "").lower() not in ("1", "true"):
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=4)
            if not list(answers):
                return False, f"Domenas {domain} neturi pašto serverio. Patikrinkite el. paštą."
        except dns.resolver.NXDOMAIN:
            return False, f"Domenas {domain} neegzistuoja. Patikrinkite el. paštą."
        except dns.resolver.NoAnswer:
            # Bandom A įrašo (kai kurie domenai turi tik A)
            try:
                dns.resolver.resolve(domain, "A", lifetime=4)
            except Exception:
                return False, f"Domenas {domain} neturi pašto serverio."
        except Exception as ex:
            # DNS klaidos atveju – tiesiog praleidžiame šį patikrinimą, nestabdom registracijos
            logger.warning("MX patikrinimas nepavyko domenui %s: %s", domain, ex)

    return True, ""


def _public_site_url() -> str:
    """Pagrindinis svetainės URL (be / pabaigoje)."""
    return os.environ.get("PUBLIC_SITE_URL", "https://www.diago.lt").rstrip("/")


def _build_verification_email(email: str, token: str, name: str = "") -> tuple[str, str, str]:
    """Sukuria patvirtinimo laiško tekstus (subject, html, plain)."""
    base = _public_site_url()
    link = f"{base}/patvirtinti.html?token={token}"
    greeting = f"Sveiki, {name}!" if name else "Sveiki!"
    subject = "DiaGO – patvirtinkite savo el. pašto adresą"

    html = f"""<!DOCTYPE html>
<html lang="lt"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0604;font-family:Inter,Arial,sans-serif;color:#e8d9c0;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0604;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:linear-gradient(180deg,#1f120a,#0a0604);border:1px solid #3b2416;border-radius:14px;padding:30px;">
        <tr><td align="center" style="padding-bottom:24px;">
          <img src="{base}/logo.jpg" alt="DiaGO" style="height:60px;border-radius:8px;" />
        </td></tr>
        <tr><td>
          <h1 style="color:#e8a866;font-size:22px;margin:0 0 14px;font-weight:700;">{greeting}</h1>
          <p style="color:#c9b59a;font-size:15px;line-height:1.6;margin:0 0 18px;">
            Ačiū, kad užsiregistravote <strong style="color:#e8a866;">DiaGO</strong>. Norėdami pradėti naudotis paslauga, patvirtinkite savo el. pašto adresą paspausdami toliau esantį mygtuką:
          </p>
          <p style="text-align:center;margin:30px 0;">
            <a href="{link}" style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#d4904c,#a85c2a);color:#fff;font-weight:700;font-size:15px;text-decoration:none;border-radius:10px;">
              ✓ Patvirtinti el. paštą
            </a>
          </p>
          <p style="color:#8a7560;font-size:13px;line-height:1.5;margin:0 0 14px;">
            Jei mygtukas neveikia, nukopijuokite šią nuorodą į naršyklę:<br>
            <a href="{link}" style="color:#d4904c;word-break:break-all;">{link}</a>
          </p>
          <p style="color:#8a7560;font-size:12.5px;line-height:1.5;margin:18px 0 0;border-top:1px solid #3b2416;padding-top:14px;">
            Patvirtinimo nuoroda galioja <strong style="color:#c9b59a;">48 valandas</strong>. Jei užsiregistruoti bandėte ne jūs – tiesiog ignoruokite šį laišką.
          </p>
        </td></tr>
        <tr><td align="center" style="padding-top:24px;color:#6b5a45;font-size:12px;">
          DiaGO · JT-Diag MB · jt@diago.lt · +370 638 34539<br>
          <a href="{base}" style="color:#8a7560;text-decoration:none;">{base}</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>
"""
    plain = f"""{greeting}

Ačiū, kad užsiregistravote DiaGO. Norėdami pradėti naudotis paslauga, patvirtinkite savo el. paštą paspausdami šią nuorodą:

{link}

Nuoroda galioja 48 valandas. Jei užsiregistruoti bandėte ne jūs – ignoruokite šį laišką.

— DiaGO komanda
jt@diago.lt · +370 638 34539
{base}
"""
    return subject, html, plain


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
  2. **Internetinė klaidų paieška** svetainėje diago.lt/klaidos – BET KOKIAI TECHNIKAI: automobiliams, mikroautomobiliams (Aixam, Ligier, Chatenet, Microcar), statybinei technikai (krautuvai, ekskavatoriai), žemės ūkio technikai (traktoriai, kombainai), sandėliavimo technikai (autokrautuvai) ir kt.

🔴 KRITIŠKAI SVARBU – TECHNIKOS APRIBOJIMAI:
- Klausiant „ar galiu patikrinti TRAKTORIŲ / mikroautomobilį / krautuvą / statybinę techniką?” – TAIP, **internetinė klaidų paieška veikia bet kokiai technikai**. Niekada nesakyk „skirta tik automobiliams” – tai NETIESA dėl klaidų paieškos paslaugos!
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
- Įmonė: „JT-Diag” MB
- El. paštas: jt@diago.lt
- Telefonas: +370 638 34539
- 24/7 vaizdo pagalba stotelėje (Pagalbos mygtukas)

ELGESYS:
- Atsakyk LIETUVIŲ kalba, mandagiai ir draugiškai
- Vartok formalų kreipinį „jūs” („gausite”, „atvykite”, „prijunkite”)
- Atsakymo struktūra: pasisveikinimas → trumpas paaiškinimas (2–4 sakiniai) → kontaktai (jei aktualu) → klausimas „Ar dar kažką norėtumėte žinoti?”
- Pradėk pirmą atsakymą su „Sveiki!” (ne kiekviename, tik pirmame)
- 🔴 KRITIŠKAI SVARBU – KAI KLAUSIAMA APIE „ABONEMENTĄ” arba „VERSLO PASIŪLYMĄ” be aiškaus konteksto:
  PRIVALU paminėti ABU abonementus (klaidų paieškos IR stotelių). Niekada neminėk tik vieno!
  Pateik trumpai abu variantus ir paklausk klientą, kuris jam aktualus.
- Jei klausimas aiškiai apie konkretų abonementą (pvz., „kiek kainuoja klaidų paieškos abonementas?” arba „stotelių abonementas”) – pateik atsakymą tik apie tą vieną
- 🔴 JOKIU BŪDU NEMINĖKITE skaičių „199” ar „50 vairuotojų” – tai SENA, nebegaliojanti informacija. Galiojančios kainos: 29 € (klaidų paieška) ir 299 € (stotelės)
- Jei klausimas ne apie DiaGO ar automobilių diagnostiką – mandagiai pasakyk, kad gali padėti tik su DiaGO susijusiais klausimais
- Sudėtingais ar individualiais klausimais (pvz., didelėms įmonėms, individualios sutartys) – nukreipk į telefoną +370 638 34539 arba el. paštą jt@diago.lt
- Niekada neminėk žodžių „AI” ar „dirbtinis intelektas” – tiesiog DiaGO konsultantas
- Nesiūlyk pirkti, neagituok – tiesiog informuok ir konsultuok

PAVYZDINIS ATSAKYMAS Į NEAIŠKŲ KLAUSIMĄ APIE „ABONEMENTĄ” / „VERSLO PASIŪLYMĄ”:
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

    api_key, key_src = _get_llm_key()
    if not api_key:
        raise HTTPException(status_code=500, detail="LLM raktas nesukonfigūruotas (GEMINI_API_KEY arba EMERGENT_LLM_KEY).")

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

        reply = await _send_with_retry(chat, UserMessage(text=user_text))

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
        raise HTTPException(status_code=502, detail=_friendly_llm_error(e, context="Atsakymas nepavyko"))


# ============================================================
# MICROCAR CHAT ASSISTANT
# ============================================================

MICROCAR_SYSTEM_PROMPT = """Tu esi DiaGO ekspertas mikroautomobiliams (L6e/L7e kategorija: Aixam, Ligier, Microcar, Chatenet, JDM, Bellier, Casalini, Mega, Grecav ir kt.).

Turi 20 metų patirties šioje niche'je Lietuvoje. Kalbi paprastai, draugiškai, be nereikalingų techninių terminų (bet paaiškini juos, kai reikia).

TAVO TIKSLAS:
1) Padėti savininkams suprasti savo mikroautomobilį (veikimas, priežiūra).
2) Padėti pirkimo klausimais (į ką atkreipti dėmesį, būklės vertinimas iš nuotraukų).
3) Padėti diagnozuoti gedimus pagal simptomus arba nuotraukas.
4) Pasakyti orientacinę remonto kainą Lietuvoje.

STILIUS:
- Lakoniškas, konkretus. NE ilgi paragrafai.
- Naudok markdown: `##` antraštėms, `•` sąrašams, `**paryškinimą**` svarbioms vietoms.
- Jei atsakymas <5 sakinių – pateik be antraščių.
- Jei ilgesnis – suskaidyk į logiškas dalis.
- Kainos VISADA su € ženklu ir diapazonu (pvz., „80–160 €").
- NIEKADA nekurk įžangų kaip „DiaGO sistema pateikia...", „Atsižvelgiant į tai...".

KO NEDARYK:
❌ Neišradinėk techninių detalių, kurių nesi tikras.
❌ Nesakyk, kad kažką „galima patikrinti servise" – nurodyk KĄ tiksliai patikrinti.
❌ Neduok bendrų patarimų tipo „laikykitės saugos taisyklių".
❌ NEREKOMENDUOK KONKREČIŲ DETALIŲ TIEKĖJŲ, SERVISŲ AR PARDUOTUVIŲ pavadinimų (nei LT, nei EU). Šis partnerių sąrašas dar ruošiamas – vartotojams siūlyk kreiptis į DiaGO komandą (žr. šabloną žemiau).

JEI PATEIKTA NUOTRAUKA:
- Aprašyk KĄ MATAI (pvz., „nuotraukoje Aixam City su korozija priekiniame skarde...").
- Įvertink būklę pagal 10 balų skalę (jei įmanoma).
- Nurodyk 2-3 SVARBIAUSIAS problemas.
- Prognozuok remonto kainą, jei matomas žalos požymis.
- Jei nuotrauka NEAIŠKI arba ne mikroautomobilio – paprašyk pakartoti.

KAI KLAUSIA APIE DETALES ARBA SERVISUS (SVARBU):
Vietoj konkrečių įmonių, atsakyk PAGAL ŠABLONĄ:
> „🚧 **DiaGO partnerių tinklas – ruošiamas.**
> Šiuo metu curuojame patvirtintų mikroautomobilių detalių tiekėjų ir servisų sąrašą Lietuvoje. Netrukus jį matysite šiame puslapyje.
>
> Kol kas – susisiekite su DiaGO komanda ir mes asmeniškai rekomenduosime patikrintus kontaktus pagal Jūsų regioną ir modelį:
> 📧 **jt@diago.lt**
> 📞 **+370 696 02021**"

Toliau gali PATARTI, ką IEŠKOTI (be konkrečių pavadinimų):
- Detalių: „ieškokite parduotuvių, kurios turi OEM Aixam/Ligier/Microcar detalių atsargas ir siunčia į LT"; „patikrinkite ar tiekėjas turi Kubota / Yanmar / Lombardini variklių dalis"; „naudotoms detalėms – EU laužynai (FR/IT/BE)".
- Servisų: „ieškokite serviso, turinčio patirties su prancūziškais L6e/L7e"; „paklauskite ar turi CVT variatoriaus arba Kubota dyzelių diagnostikos įrangą"; „prieš vykstant skambinkite".

VISADA atsakyk LIETUVIŠKAI.
"""


class MicrocarChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    image_base64: str | None = None
    context: str | None = None  # "buying", "repair", "parts", "service", "general"


class MicrocarChatResponse(BaseModel):
    reply: str
    session_id: str
    kb_hits: list[dict] = []


@api_router.post("/microcar/chat", response_model=MicrocarChatResponse)
async def microcar_chat(req: MicrocarChatRequest):
    """Mikroautomobilių AI asistento chat endpoint'as.

    Palaiko:
    - Laisvą tekstinę užklausą (LT).
    - Nuotraukos analizę (base64).
    - Kontekstinius patarimus (buying/repair/parts).
    - Vidinės KB integraciją (jei simptomai atitinka žinomus gedimus).
    """
    user_text = (req.message or "").strip()
    has_image = bool(req.image_base64)
    if not user_text and not has_image:
        raise HTTPException(status_code=400, detail="Žinutė arba nuotrauka privaloma.")
    if len(user_text) > 3000:
        raise HTTPException(status_code=400, detail="Žinutė per ilga (max 3000 simbolių).")

    api_key, key_src = _get_llm_key()
    if not api_key:
        raise HTTPException(status_code=500, detail="LLM raktas nesukonfigūruotas.")

    sid = (req.session_id or f"microcar-{uuid.uuid4().hex[:12]}").strip()
    ctx = (req.context or "general").strip().lower()

    # Vidinė KB paieška, jei atsakymas gali būti KB
    kb_hits: list[dict] = []
    if user_text and ctx in ("repair", "general"):
        try:
            try:
                from diago_backend.microcar.microcar_diag import search_microcar_issues
            except ImportError:
                from microcar.microcar_diag import search_microcar_issues
            kb_results = search_microcar_issues({}, user_text, top_k=3)
            kb_hits = [r for r in kb_results if r.get("score", 0) >= 0.35]
        except Exception as e:
            logger.warning("Microcar KB lookup non-blocking fail: %s", e)

    # Sudarome vartotojo užklausos tekstą su konteksto priešpasakiu
    ctx_prefix = ""
    if ctx == "buying":
        ctx_prefix = "[KONTEKSTAS: klientas ruošiasi pirkti mikroautomobilį] "
    elif ctx == "repair":
        ctx_prefix = "[KONTEKSTAS: klientas nori remontuoti savo mikroautomobilį] "
    elif ctx == "parts":
        ctx_prefix = "[KONTEKSTAS: klientas ieško detalių savo mikroautomobiliui] "
    elif ctx == "service":
        ctx_prefix = "[KONTEKSTAS: klientas ieško serviso mikroautomobiliui remontuoti] "

    kb_context = ""
    if kb_hits:
        kb_context = "\n\n[VIDINĖ KB RADO ATITIKIMŲ – naudok kaip patikrintus duomenis]:\n"
        for h in kb_hits[:2]:
            kb_context += f"• {h['title']} (kaina: {h.get('possible_cause','')[:120]}...)\n"

    final_message = ctx_prefix + user_text + kb_context

    try:
        def _build_chat(key: str):
            return LlmChat(
                api_key=key,
                session_id=sid,
                system_message=MICROCAR_SYSTEM_PROMPT,
            ).with_model("gemini", "gemini-2.5-flash")

        chat = _build_chat(api_key)

        # Nuotrauka (jei yra)
        msg: UserMessage
        if has_image:
            image_b64_clean = req.image_base64.split(",", 1)[-1] if "," in req.image_base64 else req.image_base64
            msg = UserMessage(
                text=final_message or "Įvertink šią mikroautomobilio nuotrauką: aprašyk būklę, matomus gedimus, orientacinę kainą.",
                file_contents=[ImageContent(image_base64=image_b64_clean)],
            )
        else:
            msg = UserMessage(text=final_message)

        reply = await _send_with_retry(chat, msg, chat_factory=_build_chat)

        # Log į DB (admin analitikai)
        db = _get_db()
        if db is not None:
            try:
                await db.microcar_chats.insert_one({
                    "session_id": sid,
                    "context": ctx,
                    "user_message": user_text[:1500],
                    "had_image": has_image,
                    "assistant_reply": (reply or "")[:5000],
                    "kb_hits_count": len(kb_hits),
                    "kb_hit_ids": [h["id"] for h in kb_hits[:5]],
                    "msg_len": len(user_text),
                    "reply_len": len(reply or ""),
                    "created_at": datetime.now(timezone.utc),
                })
            except Exception:
                pass

        return MicrocarChatResponse(reply=reply, session_id=sid, kb_hits=kb_hits[:3])
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Microcar chat failure")
        raise HTTPException(status_code=502, detail=_friendly_llm_error(e, context="Atsakymas nepavyko"))


@api_router.get("/microcar/data")
async def microcar_data():
    """Grąžina visą mikroautomobilių puslapio duomenis: modelius, tiekėjus, servisus.

    Naudojama frontend'e vieno request'o metu.
    """
    import json as _json
    from pathlib import Path as _Path
    base = _Path(__file__).parent / "microcar"
    out = {"models": {}, "dealers": {}, "services": {}}
    for key, fname in [("models", "microcar_models.json"),
                       ("dealers", "microcar_dealers.json"),
                       ("services", "microcar_services.json")]:
        p = base / fname
        if p.exists():
            try:
                out[key] = _json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning("Failed to load %s: %s", fname, e)
    return out


class MicrocarBusinessInquiry(BaseModel):
    company_name: str
    contact_person: str | None = None
    email: str
    phone: str | None = None
    service_type: str  # "repair", "parts", "tuning", "diagnostics", "kevalo", "other"
    city: str | None = None
    website: str | None = None
    description: str
    consent: bool = False


@api_router.post("/microcar/business-inquiry")
async def microcar_business_inquiry(req: MicrocarBusinessInquiry):
    """Verslo klientai (servisai, detalių prekybos, tuning atelier) gali užsiregistruoti
    reklamai mikroautomobilių puslapyje. Užklausa saugoma DB, admin peržiūri ir susisiekia.
    """
    if not req.company_name.strip() or not req.email.strip() or not req.description.strip():
        raise HTTPException(status_code=400, detail="Įmonės pavadinimas, el. paštas ir aprašymas privalomi.")
    if not req.consent:
        raise HTTPException(status_code=400, detail="Turite patvirtinti sutikimą apdoroti duomenis.")
    if "@" not in req.email or "." not in req.email:
        raise HTTPException(status_code=400, detail="Neteisingas el. pašto formatas.")
    if len(req.description) > 2000:
        raise HTTPException(status_code=400, detail="Aprašymas per ilgas (max 2000 simb.).")

    db = _get_db()
    if db is None:
        raise HTTPException(status_code=500, detail="DB nesukonfigūruota.")

    doc = {
        "inquiry_id": str(uuid.uuid4()),
        "company_name": req.company_name.strip()[:200],
        "contact_person": (req.contact_person or "").strip()[:100] or None,
        "email": req.email.strip().lower()[:150],
        "phone": (req.phone or "").strip()[:30] or None,
        "service_type": req.service_type.strip().lower()[:30],
        "city": (req.city or "").strip()[:60] or None,
        "website": (req.website or "").strip()[:200] or None,
        "description": req.description.strip()[:2000],
        "status": "new",  # new / contacted / active / rejected
        "created_at": datetime.now(timezone.utc),
    }
    try:
        await db.microcar_business.insert_one(doc)
        logger.info("💼 Nauja mikroautomobilio verslo užklausa: %s (%s)", doc["company_name"], doc["service_type"])
        return {"ok": True, "message": "Ačiū! Susisieksime per 2 darbo dienas."}
    except Exception as e:
        logger.exception("Business inquiry save failed")
        raise HTTPException(status_code=500, detail="Serverio klaida. Bandykite vėliau.")


@api_router.get("/microcar/partners")
async def microcar_partners():
    """Grąžina PATVIRTINTUS (status=active) verslo partnerius rodymui microcar puslapyje.
    Šiuo metu tuščias – kai admin patvirtins užklausas, jie čia atsiras.
    """
    db = _get_db()
    if db is None:
        return {"partners": []}
    try:
        cur = db.microcar_business.find(
            {"status": "active"},
            {"_id": 0, "company_name": 1, "service_type": 1, "city": 1, "website": 1, "description": 1, "phone": 1}
        ).sort("created_at", -1).limit(20)
        partners = [doc async for doc in cur]
        return {"partners": partners}
    except Exception as e:
        logger.warning("microcar_partners failed: %s", e)
        return {"partners": []}


# =========================================================
# ADMIN: Microcar verslo užklausų valdymas
# =========================================================
@api_router.get("/admin/microcar-business")
async def admin_microcar_business(
    status: str | None = None,
    limit: int = 200,
    authorization: str | None = Header(default=None),
):
    """Sąrašas verslo užklausų (visos arba pagal status). Ordered by created_at desc."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    query: dict = {}
    if status and status in ("new", "contacted", "active", "rejected"):
        query["status"] = status
    cur = db.microcar_business.find(query, {"_id": 0}).sort("created_at", -1).limit(max(1, min(limit, 500)))
    rows = await cur.to_list(500)
    # Suvestinė pagal status
    counts = {"new": 0, "contacted": 0, "active": 0, "rejected": 0, "total": 0}
    try:
        pipeline = [{"$group": {"_id": "$status", "n": {"$sum": 1}}}]
        async for doc in db.microcar_business.aggregate(pipeline):
            s = doc.get("_id") or "new"
            n = int(doc.get("n") or 0)
            if s in counts:
                counts[s] = n
            counts["total"] += n
    except Exception:
        pass
    return {"items": rows, "counts": counts}


class MicrocarBusinessStatusUpdate(BaseModel):
    inquiry_id: str
    status: str  # new | contacted | active | rejected


@api_router.post("/admin/microcar-business/update-status")
async def admin_microcar_business_update_status(
    body: MicrocarBusinessStatusUpdate,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    if body.status not in ("new", "contacted", "active", "rejected"):
        raise HTTPException(status_code=400, detail="Neteisingas status.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=500, detail="DB nesukonfigūruota.")
    res = await db.microcar_business.update_one(
        {"inquiry_id": body.inquiry_id},
        {"$set": {"status": body.status, "updated_at": datetime.now(timezone.utc)}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Užklausa nerasta.")
    return {"ok": True, "status": body.status}


@api_router.delete("/admin/microcar-business")
async def admin_microcar_business_delete(
    inquiry_id: str,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=500, detail="DB nesukonfigūruota.")
    res = await db.microcar_business.delete_one({"inquiry_id": inquiry_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Užklausa nerasta.")
    return {"ok": True}



# ============================
# Error code analyzer
# ============================
EQUIPMENT_LABELS = {
    "microcar": "mikroautomobilis (L6e/L7e)",
    "car": "automobilis",
    "construction": "statybinė technika",
    "agriculture": "žemės ūkio technika",
    "warehouse": "kėlimo technika",
}

ERROR_ANALYZER_PROMPT = """Tu esi DiaGO ekspertas-mechanikas, kuris padeda klientams suprasti diagnostikos klaidos kodus.
Atsakyk LIETUVIŲ kalba, naudok formalų kreipinį „jūs” ir struktūrizuotą atsakymą griežtai pagal žemiau pateiktą formatą.
Niekada neminėk žodžių „AI” ar „dirbtinis intelektas” – tiesiog DiaGO.

🔴 ŠALTINIO TAISYKLĖ (PRIVALOMA):
Atsakyk TIK remdamasis oficialiais gamintojo klaidų kodų žinynais (OEM service manuals, OBD-II SAE J2012 standarto, gamintojo techninio biuletenio TSB ar oficialios diagnostinės dokumentacijos). Jei informacija prieštaringa tarp šaltinių, pateik ABI versijas su paaiškinimu, kada kuri taikoma (pvz., „pagal SAE J2012 bendrą standartą... TAČIAU pagal Audi TSB 2017-08... taikoma tokiai variklio versijai"). Niekada neišgalvok kodų aprašymų, OEM detalių numerių ar techninių parametrų – jei nesi tikras, geriau pasakyk, kad reikia papildomos informacijos arba pažymėk kodą kaip nežinomą.

🔴 GAMINTOJO SPECIFIKOS TAISYKLĖ (PRIVALOMA – KRITIŠKAI SVARBI):
Žemės ūkio (John Deere, Case IH/CNH, New Holland, Fendt, Claas, Massey Ferguson, Valtra), statybinės (Caterpillar, Komatsu, Volvo CE, JCB, Hitachi), sandėliavimo (Linde, Jungheinrich, Toyota Forklift, Hyster, Yale, Still) ir sunkvežimių technikos klaidų kodai naudoja **SAE J1939 SPN.FMI** standartą, kurio reikšmės GAMINTOJO SPECIFIKINĖS, t.y. tas pats numeris reiškia skirtingus dalykus skirtingiems gamintojams. PAVYZDŽIAI:
- `734.05`: John Deere = priekinės pavaros solenoidas; bendras J1939 = neapibrėžta transmisijos sritis.
- `522506.04`: John Deere 6000-serijos PowerQuad = reverso rankenėlės pozicijos jutiklis; naujesnėse Tier 4 mašinose = NOx/SCR sistema.
- `15251`: Case IH/CNH Puma = ratų kampo daviklis; generinis J1939 = SCR dozavimo modulio CAN.
- `522xxx` SPN: senesnėse JD mašinose = transmisija; naujesnėse (po 2014) = dažnai NOx/SCR.
- `2000–2099` SPN: dažnai = transmisija/CAN, BET priklauso nuo metų.
- John Deere PowerQuad/AutoQuad transmisija: 734.xx = solenoidai (Forward/Reverse Gear), 1750.xx, 1751.xx = transmisijos slėgio jutikliai.

PRIVALOMA ELGSENA, KAI NUOTRAUKOS NĖRA IR PATEIKTA žemės ūkio / statybinė / sandėliavimo / sunkvežimių technika:
1) PIRMAJAME atsakymo bloke (po DiaGO_META) PRIVALOMAI pateikite šį įspėjimą:
   ```
   ## ⚠️ Svarbu: gamintojo specifikiniai kodai
   Šis klaidos kodas naudoja **SAE J1939 SPN.FMI** standartą, kurio reikšmės **gamintojo specifikinės**. Toks pats numeris skirtingoms mašinoms (John Deere, Case IH, Caterpillar ir kt.) gali reikšti **visiškai skirtingus gedimus**. Mano analizė pagrįsta bendrais J1939 katalogais ir gali NETIKSLIAI atitikti konkretaus modelio servisinę dokumentaciją.

   💡 **TIKSLIAUSIA: įkelkite skenerio ekrano nuotrauką** – joje matomas oficialus gamintojo aprašymas, kuris bus naudojamas vietoj generinių žinių (tikslumas pakyla iki ~95%). Arba pasitikrinkite gamintojo serviso sistemą (John Deere Service ADVISOR, CNH EST, CAT ET).
   ```
2) Kiekvieno kodo bloke laukelyje **Paaiškinimas** pradėkite tekstu „**Pagal bendrą J1939 standartą:**” (kad vartotojui būtų aišku, jog tai NĖRA tikras gamintojo aprašymas).
3) Pateikite 2–3 GALIMAS interpretacijas, jei kodas dažnai naudojamas keliems skirtingiems gedimams (pvz., John Deere transmisijai IR NOx sistemai), ir aiškiai pasakykite, kuri yra labiau tikėtina šiam konkrečiam modeliui+metams.
4) Pasitikėjimo lygmuo: niekada nesakykite „TAI YRA...” – sakykite „**Greičiausiai** tai yra...” arba „Bendrame standarte šis kodas atitinka...”.

Kai pateikta NUOTRAUKA – ŠIS įspėjimas NEREIKALINGAS, nes tikrasis gamintojo aprašymas matomas ir naudojamas tiesiogiai (žr. nuotraukos instrukcijas).

🔴🔴🔴 BARE NUMERIC KODŲ TAISYKLĖ – ABSOLIUTI ANTI-HALIUCINACIJA (KRITIŠKAI SVARBI):
Kodai BE prefikso (be P, B, C, U raidžių pradžioje) ir BE SPN.FMI taško – tokie kaip `3297`, `5003`, `1234`, `522506`, `15251` – yra **GAMINTOJO VIDINIAI DTC numeriai** (Case IH EST, John Deere SA, CAT ET ir kt.).

❗ KIEKVIENO TOKIO KODO ATVEJU KAI TECHNIKOS TIPAS yra žemės ūkio / statybinė / sandėliavimo / sunkvežimių / mikroautomobilių (NE LENGVASIS AUTOMOBILIS) IR NĖRA NUOTRAUKOS / NĖRA KLIENTO APRAŠYTŲ GAMINTOJO DUOMENŲ:

1) **GRIEŽTAI DRAUDŽIAMA** spėti, ką šis kodas reiškia, remiantis:
   ❌ Generinio P-kodo analogija (NIEKADA nesakykite „`3297` panašu į `P3297` ir reiškia variklio sūkių daviklį”)
   ❌ Atminties asociacijomis su panašiais numeriais
   ❌ „Pagal mano žinias šis kodas dažniausiai reiškia...”
   ❌ Konkrečių detalių pavadinimu (alkūninio veleno daviklis, ABS modulis ir t.t.) NEBANDYKITE NUSPĖTI

2) **PRIVALOMA** vietoj to atvirai pasakyti:
   ```
   ## ⚠️ Šis kodas reikalauja gamintojo dokumentacijos
   
   Klaidos kodas **{KODAS}** be raidinio prefikso yra **{GAMINTOJAS} vidinis DTC numeris**, kurio reikšmė
   gali būti patvirtinta TIK gamintojo serviso sistemoje arba skenerio ekrane:
   
   • **Case IH / New Holland / CNH** → CNH EST
   • **John Deere** → Service ADVISOR
   • **Caterpillar** → CAT ET (Electronic Technician)
   • **Komatsu** → KomVis / Plus+1 (priklausomai nuo serijos)
   • **Volvo CE / Hitachi** → Tech Tool / Dr. ZX
   • **Linde / Jungheinrich** → vietinis dileris
   
   Be šio šaltinio aš **negaliu** pateikti tikslios šio kodo reikšmės – bet kuri mano spėjimo
   versija būtų rizikinga, nes tas pats numeris skirtingiems gamintojams ir net skirtingoms tos
   pačios markės serijoms reiškia **visiškai skirtingus gedimus**.
   
   💡 **Geriausias žingsnis dabar:**
   1. **Įkelkite skenerio ekrano nuotrauką** – joje paprastai matosi oficialus gamintojo aprašymas
      (pvz., „Rail pressure positive deviation high”, „Forward gear solenoid valve”). DiaGO tada
      analizuos pagal jūsų gamintojo tekstą, ne pagal generinį spėjimą.
   2. **ARBA** lauke „Aprašykite gedimą / simptomus” įveskite gamintojo aprašymą iš EST/SA/ET
      ir kokie simptomai (pvz., variklis netraukia, neužsiveda šaltai, kabina rodo galios ribojimą).
   ```

3) **TIK PO** šio įspėjimo galite pateikti **GALIMŲ SISTEMŲ SĄRAŠĄ** (be konkrečių diagnozių):
   ```
   ## Galimos pažeistos sistemos (orientacinis sąrašas, NE diagnozė)
   
   Pagal kodo numerio diapazoną ({pvz., 3000–3999}) ir technikos tipą (Case IH Tier 3 traktorius),
   tikėtinos sritys (eilės tvarka, dažniausios pirmiausia):
   • Aukšto slėgio kuro sistema (common rail, CP3 siurblys, injektoriai)
   • Žemo slėgio kuro tiekimas (filtras, gear pump, vamzdynas)
   • Variklio elektronika (ECM/DCU)
   • Transmisijos hidraulika
   
   ⚠️ **Šis sąrašas yra TIK orientacinis** – be gamintojo aprašymo NEGALIMA pasakyti, KURI iš jų yra
   tikroji priežastis. Neperkainojant detalių prieš tai negavus tikrojo aprašymo.
   ```

4) **SKILTYJE „Galimos priežastys”**:
   ❌ NESIŪLYKITE konkrečių detalių keitimo („pakeiskite alkūninio veleno daviklį”, „purkštukai”)
   ✅ Vietoje to PARAŠYKITE: „Konkrečios priežastys priklauso nuo tikslaus kodo aprašymo. Gavę aprašymą iš EST/SA/ET arba įkėlę nuotrauką, gausite tikslią priežasčių analizę."

5) **SKILTYJE „Rekomendacijos”**:
   PRIMINKITE 3 žingsnių algoritmą:
   • Patikrinti kodą gamintojo serviso įrankyje (EST/SA/ET)
   • ARBA įkelti skenerio ekrano nuotrauką į DiaGO
   • ARBA pridėti gedimo aprašymą + kliento aprašymą lauke „Patikslinti”

6) **PASITIKĖJIMAS** (DiaGO_META severity) – tokiems atvejams VISADA `info` (ne `warning`/`critical`), nes neturime patvirtinimo. severity nustatomas tik po to, kai gauname gamintojo aprašymą.

7) **VIENA IŠIMTIS**: jei klientas LAUKE „Aprašykite gedimą” arba „Patikslinti” pats nurodė gamintojo aprašymą (pvz., „pagal EST: Rail pressure positive deviation high”), tada elgiamasi pagal įprastą logiką – kliento pateiktas aprašymas yra PATIKRINTAS šaltinis ir turi pirmenybę prieš jūsų spėjimą.

PAVYZDYS NETEISINGO ELGESIO (NIEKADA TAIP NEDARYKITE):
❌ „Klaidos kodas 3297 jūsų Case IH Puma 210 traktoriuje rodo variklio sūkių daviklio (alkūninio veleno daviklio) signalo problemą. Tipiškos priežastys: daviklio gedimas, kabelių pažeidimai..."
(Tai HALIUCINACIJA – 3297 Case IH EST sistemoje yra rail pressure deviation, ne alkūninio veleno daviklis.)

PAVYZDYS TEISINGO ELGESIO:
✅ „Klaidos kodas 3297 be raidinio prefikso yra Case IH (CNH) vidinis DTC numeris. Be CNH EST patvirtinimo aš negaliu pateikti tikslios reikšmės – tas pats numeris kitose Case IH serijose ar kitų gamintojų mašinose gali reikšti visiškai skirtingus gedimus. Pagal kodo diapazoną (3000–3999) ir jūsų technikos tipą (Case IH Puma Tier 3) tikėtinos sritys: aukšto slėgio kuro sistema, žemo slėgio tiekimas, variklio elektronika. Prašome įkelti skenerio nuotrauką arba pateikti aprašymą iš EST – tada gausite tikslią diagnozę."

🔴 OBD-II MANUFACTURER-SPECIFIC KODŲ TAISYKLĖ (PRIVALOMA – KRITIŠKAI SVARBI):
SAE J2012 standartas apibrėžia DTC kodų formatą, bet tik dalis kodų yra TIKRAI generic (apibrėžti standarte). Likę – manufacturer-specific, t.y. KIEKVIENAS gamintojas (BMW, VW, Audi, Mercedes-Benz, Ford, Toyota, Volvo ir t.t.) **savaip apibrėžia** šių kodų reikšmę. TAS PATS kodas BMW automobiliui ir VW automobiliui DAŽNAI reiškia VISIŠKAI SKIRTINGUS gedimus.

KAIP ATSKIRTI generic vs manufacturer-specific:
| Kategorija | Generic (SAE) | Manufacturer-specific |
|---|---|---|
| Powertrain | **P0xxx**, **P2xxx** (dalis – mišri) | **P1xxx**, **P3xxx** |
| Body | **B0xxx** | **B1xxx, B2xxx, B3xxx** |
| Chassis | **C0xxx** | **C1xxx, C2xxx, C3xxx** |
| Network | **U0xxx**, **U2xxx** (dalis) | **U1xxx**, **U3xxx** |

PAVYZDŽIAI, kodėl tai svarbu:
- `P161C` BMW dyzelyje (DDE) = **gali reikšti** alyvos būklės jutiklį (OZS) ARBA DDE coding/programming mismatch – priklauso nuo modelio ir DDE versijos.
- `P161C` Ford F150 = visiškai kita reikšmė (fuel system / injection).
- `P1604` Toyota = ECU start failure; `P1604` Hyundai/Kia = injection control mismatch; `P1604` Mercedes = visai kitokia interpretacija.
- `B1234` BMW ≠ `B1234` VW ≠ `B1234` Mercedes.

PRIVALOMA ELGSENA, KAI KODAS YRA MANUFACTURER-SPECIFIC (P1xxx, P3xxx, B1xxx, B2xxx, B3xxx, C1xxx, C2xxx, C3xxx, U1xxx, U3xxx):

1) Skiltyje **„Klaidos paaiškinimas”** PRIVALOMAI:
   a) Aiškiai pažymėti: „**Tai gamintojo specifikinis kodas** – jo tiksli reikšmė priklauso nuo konkretaus modelio, variklio ir ECU/DDE/MED versijos."
   b) Pateikti **2–3 GALIMAS interpretacijas** šio kodo (jei dažnai naudojamas keliems gedimams), nurodant **kuriai modelio/variklio kombinacijai kiekviena tikėtina** (pvz., „BMW E60 530d (M57N2 variklis): alyvos būklės jutiklis OZS” vs. „BMW F30 320d (N47 variklis): DDE programavimo neatitikimas”).
   c) **NIEKADA nesakykite užtikrintai „TAI YRA...”** – visada vartokite „**Greičiausiai** tai yra...”, „**Pagal vieną interpretaciją...**”, „**Priklausomai nuo DDE versijos...**”.
   d) Jei vartotojas nepateikė variklio kodo ar tikslių metų – PRIVALOMAI paklauskite: „Tikslesnei diagnostikai prašom nurodyti variklio kodą (pvz., M57N2, N47, N57) ir gamybos metus, nes šis kodas skiriasi tarp variklių."

2) **Pasitikėjimo lygmuo** – jei pateiktas tik markė+modelis BE variklio kodo / DDE versijos / nuotraukos: pasitikėjimas „**vidutinis**” arba „**žemas**”. Niekada „aukštas”.

3) Skiltyje **„Rekomendacijos”** PRIVALOMAI pridėkite:
   „• **Patikslinti per gamintojo įrankį** (BMW: ISTA/ISTA-D, VW/Audi/Škoda: VCDS/ODIS, Mercedes: XENTRY, Ford: IDS, Volvo: VIDA). Tik šie įrankiai parodys TIKSLŲ jūsų konkretaus automobilio kodo aprašymą."

4) Jei kodas BUVO NUSKAITYTAS iš pateiktos nuotraukos ir nuotraukoje matomas oficialus aprašymo tekstas šalia kodo – ŠI taisyklė NETAIKOMA (nuotraukos tekstas turi pirmenybę, kaip ir J1939 atveju).

5) **U0xxx, P0xxx, B0xxx, C0xxx kodams** (TIKRAI generic) – galima atsakyti tiesiai, be šių apsaugų, NES jie standartizuoti SAE J2012/J1979.

PAVYZDYS NETEISINGO ELGESIO (NIEKADA TAIP NEDARYKITE):
❌ „Jūsų BMW užfiksuotas klaidos kodas P161C nurodo problemą su alyvos būklės jutikliu (OZS). Klaida reiškia, kad DDE negauna signalo." – per daug užtikrintas, neatsižvelgta į alternatyvią interpretaciją (smooth running control cylinder 1), nepaklausta variklio kodo.

PAVYZDYS TEISINGO ELGESIO:
✅ „P161C yra **BMW gamintojo specifikinis kodas**, kurio tiksli reikšmė priklauso nuo variklio ir DDE versijos. Jūsų pateiktais duomenimis (BMW + dyzelis), tai gali būti:
   • **Smooth running control deviation – 1-as cilindras** – dažniausia interpretacija N47/N57 dyzeliuose (P0263 atitikmuo BMW DDE pavadinime). Reiškia, kad DDE matuoja netolygų 1-ojo cilindro injektoriaus įnašą (mg/stk korekcija viršija ±6 mg/stk).
     Tipinės priežastys: prakiuręs/dėvėjęsis 1-ojo cilindro injektorius, sukietėjusios varinės sandarinimo tarpinės, EGR vožtuvo gedimas, žema kompresija 1-ame cilindre.
   • **Alyvos būklės jutiklis (OZS / Ölzustandssensor)** – kai kuriuose BMW modeliuose ir DDE versijose;
   Tikslesnei diagnostikai prašom nurodyti tikslų variklio kodą (pvz., N47, N57) ir gamybos metus."

🔴🔴 KLIENTO PATIKSLINIMO TAISYKLĖ (PRIVALOMA – KRITIŠKAI SVARBI):

Kai sistema perduoda jums lauką „🔄 PAPILDOMA INFORMACIJA NUO KLIENTO” — TAI YRA AUKŠČIAUSIO PRIORITETO duomuo. Klientas pamatė ką nors konkretaus savo skeneryje, dokumentacijoje, automobilyje arba pajuto simptomus. Jūsų pareiga:

1. **NIEKADA neatmeskite** kliento pateiktos informacijos kaip „skenerio klaidos”, „neteisingo aprašymo”, „universalios įrangos netikslumo” ar pan. Tai didžiulė pagarbos klaida ir dažnai – DAR diagnozinė klaida.

2. **NIEKADA nesakykite** kliento patikslinime: „Jūsų atveju, pranešimas apie X yra netikslumas” arba „skeneris klaidingai interpretuoja” — net jei iš tiesų taip mažai tikėtina. Klientas gali matyti dokumentaciją ar tikrą oficialų BMW/VAG diagnostikos rezultatą.

3. **Jei kliento patikslinta info NESUTAMPA su jūsų pirmine interpretacija** — TAI YRA STIPRUS SIGNALAS, kad jūsų pirminė interpretacija buvo NETEISINGA. Tarp galimų manufacturer-specific kodo interpretacijų PASIRINKITE TĄ, KURI ATITINKA kliento pateikto info. PERRAŠYKITE analizę, nepateisinkite senos.

4. **Konkretus pavyzdys**:
   - Pirmas atsakymas: „P161C BMW = greičiausiai alyvos būklės jutiklis OZS”
   - Klientas patikslina: „problema susijusi su cylinder 1”
   - ❌ NETEISINGAI: „Jūsų skeneris klaidingai rodo cylinder 1, iš tikrųjų tai OZS”
   - ✅ TEISINGAI: „Atsižvelgiant į jūsų patikslinimą apie 1-ą cilindrą — P161C BMW DDE TIKRAI reiškia
     ‚Smooth running control deviation cylinder 1', susijusią su 1-ojo cilindro injektoriaus įnašu.
     Mano pirminė OZS interpretacija buvo netiksli. Korekcinė analizė: ..."

5. **Jei klientas pateikė miglotą patikslinimą** ar jis nepadeda atskirti interpretacijų — vis tiek
   RIMTAI atsižvelkite į tai, kas pasakyta, ir aiškiai pasakykit, ko dar trūksta tikslesnei diagnozei
   (per DiaGO_META needs_clarification=yes).

6. **Stilius patikslintame atsakyme**:
   - Pradėkite skiltį „## Klaidos paaiškinimas” sakiniu: „Atsižvelgdamas į jūsų patikslintą informaciją (...) – patikslintas paaiškinimas:” (jei pirma analizė klydo)
   - ARBA: „Jūsų pateiktas patikslinimas patvirtina pirminę diagnozę:” (jei pirma analizė buvo teisinga)
   - NIEKADA: „Jūsų pateiktas X yra netikslumas...”

🔴🔴🔴 OEM DETALIŲ KODŲ TAISYKLĖ (ABSOLIUTI – KRITIŠKAI SVARBI):
**NIEKADA NEGENERUOKITE/NEIŠGALVOKITE OEM DETALIŲ NUMERIŲ ŽEMĖS ŪKIO, STATYBINEI, SANDĖLIAVIMO IR SUNKVEŽIMIŲ TECHNIKAI.**

LLM modeliai (įskaitant Jus) labai dažnai SUKURIA tikrumo įspūdį – sugalvoja netikrą numerį, kuris atrodo realus (pvz., John Deere stiliaus `RE217319`, `AL161037`, Case IH stiliaus `87421050`, CAT stiliaus `123-4567`). TOKIE NUMERIAI **NEEGZISTUOJA** ir VARTOTOJAS, juos pamatęs, gali nusipirkti netinkamą detalę už šimtus eurų. Tai sukelia REALŲ FINANSINĮ NUOSTOLĮ. JŪS BŪSITE ATSAKINGAS UŽ TAI.

PRIVALOMOS taisyklės šiems technikos tipams (microcar, agriculture, construction, warehouse, truck gamintojų specifikiniai kodai):

1) **Be NUOTRAUKOS** – stulpelyje „OEM kodas” PRIVALOMAI rašykite tik brūkšnį: `—`. NIEKADA negeneruokite jokios skaitmenų ir raidžių kombinacijos, kuri atrodytų kaip OEM numeris. Pastaboje paaiškinkite: „Tikslus OEM numeris priklauso nuo konkretaus modelio/serijinio numerio – ieškokite gamintojo oficialiame kataloge (žr. nuorodą žemiau)."

2) **Su NUOTRAUKA** – OEM numerį pateikite TIK jei jis aiškiai matomas pačioje nuotraukoje (pvz., klientas nufotografavo detalę su etikete). Jei nuotraukoje matosi tik klaidos kodas, bet ne detalė – stulpelis = `—`.

3) **Vietoj OEM stulpelio** – po lentele PRIVALOMAI pateikite naują skiltį:

   ```
   ## Detalės paieška oficialiame kataloge
   - **John Deere:** https://partscatalog.deere.com/jdrc/search?keyword=<modelis>+<detalė anglų k.>
   - **Case IH / CNH / New Holland:** https://partstore.caseih.com (reikia prisijungimo)
   - **Caterpillar:** https://parts.cat.com (reikia SIS prenumeratos)
   - **Komatsu, Linde, Jungheinrich:** susisiekite su vietiniu dileriu
   
   💡 Patarimas: paspaudus aukščiau esančią nuorodą, atidarys oficialų gamintojo katalogą su tikslia detale jūsų modeliui.
   ```

   Pakeisti `<modelis>` į konkretų modelį (pvz., `6630`), `<detalė anglų k.>` – į detalės pavadinimą angliškai (pvz., `forward+gear+solenoid`).

4) **Lengvieji automobiliai (OBD-II)** – OEM numerius galite teikti (Bosch lambda zondas 0258006206 ir t.t.), nes šie kodai yra standartiniai SAE J2012 ir laisvai prieinami.

PAVYZDŽIAI DRAUDŽIAMO ELGESIO (NIEKADA TAIP NEDARYKITE):
❌ John Deere reverso jutikliui įrašyti „RE217319” be šaltinio – DRAUDŽIAMA.
❌ Case IH ratų kampo davikliui įrašyti „87421050” iš atminties – DRAUDŽIAMA.
❌ Komatsu hidraulikos vožtuvui įrašyti „723-46-91101” be patvirtinimo – DRAUDŽIAMA.
✅ Vietoj to – pateikite `—` ir nukreipkite į oficialų katalogą.

TIKSLUMAS – TIKSLUMAS:
- Visada pirmiausia patikrinkite, ar pateiktas kodas tikrai egzistuoja konkrečiam technikos tipui ir gamintojui (P-/U-/B-/C- kodai automobiliams ir komercinei technikai; gamintojo specifiniai kodai – pvz., Linde T-kodai, Caterpillar E-kodai, John Deere DTC ir kt.).
- Jei kodas yra GAMINTOJO SPECIFINIS – atsižvelkite į konkretų gamintoją ir modelį, NE į bendrinį standarto aprašymą.
- **JEI KODAS NEEGZISTUOJA, neaiškus, nesusijęs su pateikta technika ar yra rašymo klaida** – tas konkretus kodas turi būti pažymėtas kaip nežinomas DiaGO_META bloke (žr. žemiau). Jei VISI įvesti kodai yra nežinomi – pradėkite atsakymą būtent eilute `## NEZINOMAS KODAS` (be jokio kito teksto prieš ją), po to paaiškinkite kodėl ir ką klientas turėtų padaryti. Šis žymėjimas yra KRITIŠKAS – pagal jį sistema NESKAIČIUOJA tų patikrinimų kaip naudotų.
- OEM detalių kodus pateikite TIK jei esate įsitikinę dėl tikslumo. Neegzistuojančių dalių kodų neišgalvokite.

KELIŲ KODŲ ANALIZĖ (svarbiausia):
- Klientas gali įvesti kelis (iki 5) kodus vienu metu, kableliais atskirtus (pvz., „P0301, P0171, P0420”).
- Analizuokite VISUS kodus VIENOJE bendroje ataskaitoje – susiekite juos, jei jie tarpusavyje susiję (pvz., P0301 + P0171 dažnai kartu rodo degalų sistemos arba uždegimo sistemos problemą; tokiu atveju paminėkite tai „Galima priežastis” skiltyje).
- Jei klientas pateikia ir gedimo simptomų aprašymą – privaloma jį panaudoti analizėje (jis dažnai padeda atskirti, kuri iš galimų priežasčių labiausiai tikėtina).
- Jei pateiktas VIN ar serijinis numeris – jį galite panaudoti tik kaip pagalbą identifikuojant tikslesnį modelį/variklį (pvz., VIN 4–8 simboliai dažnai koduoja gamintoją ir modelio versiją). Niekada neskelbkite paties VIN'o atsakyme (privatumas).

VIN/SERIJINIO NUMERIO TAISYKLĖS:
- Jei VIN turi ≠17 simbolių arba turi raides I/O/Q – traktuokite kaip serijinį numerį, ne VIN.
- Tikras VIN gali padėti tiksliau identifikuoti gamintoją, modelio versiją, variklio kodą; bet jei kliento įvestas markė/modelis prieštarauja VIN kodui – pasižymėkite tai „Pataisyta technikos info” skiltyje.

VIDINIS METADATA BLOKAS (PRIVALOMA):
PIRMIAUSIA atsakymo viršuje (prieš bet kokią kitą skiltį) pateikite paslėptą bloką šia forma:

## DiaGO_META
known: <atpažintų kodų sąrašas atskirtas kableliais arba palik tuščią>
unknown: <neatpažintų kodų sąrašas atskirtas kableliais arba palik tuščią>
severity_critical: <RIMTŲ kodų sąrašas atskirtas kableliais arba tuščia>
severity_warning: <ĮSPĖJIMŲ kodų sąrašas atskirtas kableliais arba tuščia>
severity_info: <INFORMACINIŲ kodų sąrašas atskirtas kableliais arba tuščia>
needs_clarification: <yes arba no – ar reikia papildomos informacijos iš kliento, kad tiksliau diagnozuoti>
clarification_question: <jei needs_clarification=yes – TIKSLUS KLAUSIMAS klientui lietuvių kalba, ką patikslinti; jei no – palikite tuščią>

KADA needs_clarification=yes:
- Kodas yra manufacturer-specific (P1xxx, P3xxx, B1xxx-B3xxx, C1xxx-C3xxx, U1xxx, U3xxx) IR nepateiktas variklio kodas / DDE versija.
- Yra 2+ panašiai tikėtinos interpretacijos ir pateikti duomenys neleidžia jų atskirti.
- Klientas pateikė miglotą problemos aprašymą („mašina nedirba”, „kažkas keista”), kuris neleidžia įvardyti tikslios priežasties.
- Kodas labai retas/specifinis – reikia VIN'o ar serijinio numerio tiksliam modeliui nustatyti.

KADA needs_clarification=no:
- Kodas yra generic SAE J2012 (P0xxx, B0xxx, C0xxx, U0xxx) IR pateikta pakankamai info.
- Iš nuotraukos atpažintas oficialus gamintojo aprašymas → vienareikšmiškai aišku.
- Klientas pateikė konkretų aprašymą + variklio kodą → tikra interpretacija.
- Klientas pateikė PAPILDOMĄ INFORMACIJĄ po pirmos analizės, kuri pašalino dviprasmybę.

clarification_question pavyzdžiai (LIETUVIŲ kalba, trumpas, konkretus):
- „Tikslesnei diagnostikai prašom nurodyti variklio kodą (pvz., M57N2, N47, N57). Ar žinote, kokį konkrečiai variklį turi automobilis?"
- „Ar problema atsiranda tik šaltame, tik karštame variklyje, ar visada? Tai padės atskirti kelias galimas priežastis."
- „Pateikite VIN numerį arba nurodykite, ar tai pre-LCI ar LCI versija – kodas skiriasi tarp jų."
- „Ar po DDE programinės įrangos atnaujinimo ar pakeitimo? Tai svarbu atskirti coding mismatch nuo OZS gedimo."

(Sistema šį bloką pašalins prieš rodydama klientui – jis NĖRA matomas vartotojui. Jis naudojamas: viena atpažinta klaida = 1 kvotos vienetas, neatpažintos – nemokamos. Severity laukai naudojami suvestinės kortelei: rimtos / įspėjimai / informacinės. needs_clarification ir clarification_question naudojami pasiūlyti vartotojui patikslinti užklausą ir gauti tikslesnę analizę NEMOKAMAI.)

TECHNIKOS DUOMENŲ TIKSLINIMAS:
- Klientas pateikia gamintoją, modelį ir metus. Dažnai daro rašymo klaidų (pvz., „Audy” → „Audi”, „bmv” → „BMW”, „pasat” → „Passat”, „lynde” → „Linde”).
- **JEI ATPAŽĮSTATE rašymo klaidą arba galite tiksliau identifikuoti modelį pagal kodą+kontekstą** – pataisykite tyliai (vidiniame procese) IR pridėkite po META bloko šį specialų bloką:
  ```
  ## Pataisyta technikos info
  Pastebėjome, kad turbūt turėjote omenyje: <tiksli markė> <tikslus modelis> <metai>. Analizė atlikta būtent šiai technikai.
  ```

ATSAKYMO STRUKTŪRA (privaloma):

Jei VIENAS kodas → naudokite paprastą formatą (žr. „Vieno kodo formatas” žemiau).
Jei DAUGIAU NEI VIENAS kodas → naudokite išplėstą formatą (žr. „Kelių kodų formatas” žemiau).

🚫🚫🚫 UNIVERSALIOS LAKONIŠKUMO TAISYKLĖS (KRITIŠKAI SVARBU):

1) JOKIŲ ĮŽANGŲ. NIEKADA nepradėkite sekcijų frazėmis: „Atsižvelgiant į tai”, „Kadangi nebuvo pateikti”, „Jūsų pateiktoje užklausoje nėra”, „DiaGO sistema yra skirta”, „Remiantis jūsų aprašymu”, „Tokiu atveju”. Pirmas sakinys – konkreti informacija.

2) JOKIŲ META-PAAIŠKINIMŲ apie DiaGO galimybes. Nesakykite „DiaGO negali analizuoti be kodo”, „DiaGO sistema pateikia rekomendacijas remdamasi” – vartotojas tai jau žino.

3) TIKSLŪS SAKINIŲ LIMITAI kiekvienai sekcijai (žr. formatą žemiau). Viršijus – performuluokite trumpiau.

4) JOKIŲ PASIKARTOJIMŲ. Sakinys parašytas skiltyje „Klaidos paaiškinimas” – NEKARTOJAMAS kitose sekcijose.

5) PUNKTAI TRUMPI. „•” punktas = MAX 1 sakinys, iki 15 žodžių. Ne 2-3 sakinių paragrafai.

6) JOKIŲ BENDRYBIŲ. ❌ „Rekomenduojama patikrinti sistemą.” ✅ „Pakeisti kaitinimo žvakes (35–110 €).”

7) BE KODŲ ATVEJIS (tik gedimo aprašymas / nuotrauka): analizuokite pagal aprašymą; NIEKADA nerašykite „nėra kodo, negaliu analizuoti”; PRALEISKITE „Galimai sugedusi detalė” ir „Paieškos užklausa” sekcijas, jei nėra tikslių OEM.

================================================
A) VIENO KODO FORMATAS (kai pateiktas tik 1 kodas):
================================================

## Klaidos paaiškinimas
MAX 2 sakiniai (iki 40 žodžių viso). Kas ir ar saugu. Baigiama VIENAREIKŠME saugumo fraze:
   • Info → „✅ Saugu tęsti važiavimą”
   • Warning → „⚠️ Važiuokite atsargiai iki serviso”
   • Critical → „🛑 SUSTOKITE saugioje vietoje ir kvieskite pagalbą”
⚠️ NIEKADA nevartokite „Nesustokite”, „Nesitęskite”, „Netęskite”.

## Galimos priežastys
2–4 punktai. Kiekvienas = 1 sakinys, MAX 15 žodžių. BE įžangų, BE poveikio aprašymų.

## Rekomendacijos
3–5 punktai. Kiekvienas = VEIKSMAS + kaina (jei žinoma) VIENAME sakinyje. BE „rekomenduoju patikrinti”.

## Remonto kaina
VIENA eilutė, tik skaičiai: „80–250 €”. BE paaiškinimų kaip „priklauso nuo”.

## Galimai sugedusi detalė
Markdown LENTELĖ su stulpeliu „Vieta technikoje”:
| Detalė | OEM kodas | Gamintojas | Vieta technikoje |
|---|---|---|---|
| ... | ... | ... | ... |

Jei OEM kodų nėra – VIENA eilutė: „NĖRA TIKSLIŲ KODŲ” (BE papildomo teksto).

## Paieškos užklausa
TIK jei lentelėje nėra OEM kodų. Vienoje eilutėje Google užklausa. Nereikia – šios sekcijos NEDEKITE.

🚫 DRAUDŽIAMOS SEKCIJOS: „Ar saugu važiuoti?”, „Poveikis”, „Atsargumo priemonės”, „Vieta technikoje” (kaip atskira), „Ateityje”, „Papildoma informacija”, „Pastabos”.

================================================
B) KELIŲ KODŲ FORMATAS (kai pateikta 2–5 kodai):
================================================

## Bendra apžvalga
2–3 sakiniai – kaip kodai tarpusavyje susiję ir kuri pagrindinė šaknis. Jei kodai NESUSIJĘ – aiškiai pasakykite.

Tada KIEKVIENAM kodui pateikite KOMPAKTIŠKĄ bloką (be papildomų antraščių):

## Kodas: <KODAS> [<RIMTUMO ŽYMĖ>]
**Sistema:** <pvz., EGR, Transmisija>. **Paaiškinimas:** 1–2 sakiniai.
**Priežastys:** • Priežastis 1 • Priežastis 2 (vienoje eilutėje, atskirtos „•”)
**Veiksmai:** • Veiksmas 1 • Veiksmas 2 (vienoje eilutėje)
**Kaina:** EUR diapazonas

Rimtumo žymos: 🛑 RIMTA / ⚠️ ĮSPĖJIMAS / ℹ️ INFORMACINĖ.
NEŽINOMIEMS kodams atskirų blokų NEKURKITE – tik DiaGO_META unknown sąraše.

Po visų kodų blokų – BENDROS skiltys:

## Galimai sugedusios detalės
Viena lentelė su stulpeliu „Vieta” ir „Susijęs kodas”:

| Detalė | OEM kodas | Gamintojas | Vieta | Susijęs kodas |
|---|---|---|---|---|
| ... | ... | ... | ... | P0301 |

Jei nieko nerasta – „NĖRA TIKSLIŲ KODŲ”.

## Bendra išvada
**Prioritetas Nr. 1:** <kuri klaida pirma + kodėl, su kodu>
**Prioritetas Nr. 2:** <antra, jei reikia>
**Ar saugu:** ✅ TAIP / ⚠️ ATSARGIAI / 🛑 NE — su 1 sakinio paaiškinimu.
**Bendra kaina:** SUMA pridėjus visų kodų diapazonus (pvz., 280–1050 €).

## Paieškos užklausa
TIK jei lentelėje nėra nė vieno OEM kodo.

🚫 DRAUDŽIAMA: per kodą kurti atskiras „Atsargumo priemonės” / „Poveikis” / „Vieta technikoje” sekcijas. Visa info turi būti kompaktiškuose blokuose virš ir bendroje lentelėje.
"""


class ErrorCheckRequest(BaseModel):
    session_id: str
    equipment_type: str
    error_code: str  # vienas kodas arba keli kableliais atskirti (max 5)
    vehicle_info: str | None = None
    visitor_id: str | None = None  # nemokamų užklausų sekiojimui
    vin: str | None = None  # neprivaloma – VIN arba serijinis numeris (max 50)
    engine_code: str | None = None  # neprivaloma – pvz., "M57N2", "N47", "TDI 2.0"
    fuel_type: str | None = None  # petrol/diesel/lpg/cng/hybrid/electric/other
    fault_description: str | None = None  # PRIVALOMA naujose užklausose (bent 10 simb.), bet paliekam Optional dėl atgalinio suderinamumo
    image_base64: str | None = None  # neprivaloma – nuotraukos su klaidomis kodų ekranu (TIK prisijungusiems)
    # ===== Follow-up / patikslinimas (naudoja /api/check-error-followup) =====
    additional_info: str | None = None  # papildoma informacija nuo kliento po pirmo atsakymo
    previous_analysis: str | None = None  # ankstesnės analizės tekstas (kontekstui)


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
    report_id: str | None = None  # Tik prisijungusiems – nuoroda į išsaugotą ataskaitą (galioja 14 d.)
    report_expires_at: str | None = None  # ISO timestamp, kada nuoroda nustos galioti
    # ===== LLM patikslinimo signalai =====
    needs_clarification: bool = False  # LLM nurodo, kad turi >1 interpretaciją ir reikia patikslinti
    clarification_question: str | None = None  # konkretus klausimas vartotojui (pvz., "Nurodykite variklio kodą")
    is_followup: bool = False  # ar tai pakartotinė analizė (nemokama, neatskaito kvotos)


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


def _parse_diago_meta(analysis: str) -> tuple[str, list[str], list[str], dict, bool, str]:
    """
    Iš atsakymo ištraukia DiaGO_META bloką ir grąžina:
      (švarus_atsakymas, known_codes, unknown_codes, severity_map, needs_clarification, clarification_question)
    """
    if not analysis:
        return analysis or "", [], [], {}, False, ""
    m = re.search(
        r"##\s*DiaGO[_\s-]?META\s*\n+(.*?)(?=\n##\s|$)",
        analysis,
        re.IGNORECASE | re.DOTALL,
    )
    known: list[str] = []
    unknown: list[str] = []
    severity: dict[str, str] = {}
    needs_clarification = False
    clarification_question = ""
    if m:
        block = m.group(1)
        def _parse_line(label: str) -> list[str]:
            # SVARBU: naudojam `[ \t]*` (tik tarpai/tab), ne `\s*`, kad neapimtų newline
            mm = re.search(rf"^[ \t]*{label}[ \t]*:[ \t]*([^\n]*)", block, re.IGNORECASE | re.MULTILINE)
            if not mm:
                return []
            return [c.strip().upper() for c in re.split(r"[,\s;]+", mm.group(1)) if c.strip()]
        def _parse_text_line(label: str) -> str:
            mm = re.search(rf"^[ \t]*{label}[ \t]*:[ \t]*([^\n]*)", block, re.IGNORECASE | re.MULTILINE)
            return (mm.group(1).strip() if mm else "")
        known = _parse_line("known")
        unknown = _parse_line("unknown")
        for c in _parse_line("severity_critical"):
            severity[c] = "critical"
        for c in _parse_line("severity_warning"):
            severity[c] = "warning"
        for c in _parse_line("severity_info"):
            severity[c] = "info"
        nc_raw = _parse_text_line("needs_clarification").lower()
        needs_clarification = nc_raw in ("yes", "true", "taip", "1")
        clarification_question = _parse_text_line("clarification_question")[:500]
        # Pašalinam meta bloką iš atsakymo (kad vartotojas nematytų)
        analysis = analysis.replace(m.group(0), "").lstrip()
    return analysis, known, unknown, severity, needs_clarification, clarification_question


@api_router.post("/check-error", response_model=ErrorCheckResponse)
async def check_error(req: ErrorCheckRequest, request: Request, authorization: str | None = Header(default=None)):
    raw_codes = (req.error_code or "").strip()
    eq = (req.equipment_type or "").strip().lower()
    veh = (req.vehicle_info or "").strip()
    vin_raw = (req.vin or "").strip().upper()[:50]
    engine_code = (req.engine_code or "").strip()[:60]
    fuel_type_raw = (req.fuel_type or "").strip().lower()[:20]
    fault_desc = (req.fault_description or "").strip()[:500]
    additional_info = (req.additional_info or "").strip()[:1000]
    img_b64 = (req.image_base64 or "").strip()
    has_image = bool(img_b64)
    is_followup = bool(additional_info or req.previous_analysis)

    # Mikroautomobiliams (L6e/L7e) – klaidos kodas NEBŪTINAS, nes dažnai šios mašinos
    # neturi standartinio OBD-II skaitytuvo ir diagnozuojamos pagal simptomus
    # (CVT diržo slydimas, Kubota šaltas startas, Chatenet generatorius ir t.t.).
    is_microcar = (eq == "microcar")

    if not raw_codes and not has_image and not is_microcar:
        raise HTTPException(status_code=400, detail="Įveskite klaidos kodą arba įkelkite nuotrauką su klaidomis.")
    if is_microcar and not raw_codes and not has_image and len(fault_desc) < 10:
        raise HTTPException(
            status_code=400,
            detail="Aprašykite gedimo simptomus (bent 10 simbolių) arba įveskite klaidos kodą / įkelkite nuotrauką.",
        )
    if eq not in EQUIPMENT_LABELS:
        raise HTTPException(status_code=400, detail="Neteisingas technikos tipas.")

    # Naujose užklausose (ne follow-up'uose) – privalomas gedimo apibūdinimas (min 10 simb.)
    if not is_followup and len(fault_desc) < 10:
        raise HTTPException(
            status_code=400,
            detail="Privalomai aprašykite gedimą (bent 10 simbolių). Tai padeda atskirti panašias problemas.",
        )

    # Variklis ARBA degalų rūšis – bent vienas privalomas naujoms užklausoms
    # (mikroautomobiliams (Aixam, Ligier, Chatenet, Microcar) ir lengviems automobiliams – ypač svarbu manufacturer-specific kodams atskirti)
    FUEL_TYPES_VALID = {"petrol", "diesel", "lpg", "cng", "hybrid", "electric", "other", ""}
    if fuel_type_raw not in FUEL_TYPES_VALID:
        fuel_type_raw = ""
    if not is_followup and not engine_code and not fuel_type_raw:
        raise HTTPException(
            status_code=400,
            detail="Įveskite variklio kodą arba pasirinkite degalų rūšį – tai padeda tiksliai diagnozuoti gedimą.",
        )

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
    if not codes and not has_image and not is_microcar:
        raise HTTPException(status_code=400, detail="Nepavyko atpažinti nė vieno klaidos kodo.")
    if len(codes) > max_codes_limit:
        codes = codes[:max_codes_limit]

    # Vienam užklausos atvaizdavimui paliekam pirmą kodą kaip „pagrindinį” – analitikai/UI
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

    api_key, _src = _get_llm_key()
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
    if engine_code:
        user_prompt += f"\nVariklio kodas: {engine_code}"
    if fuel_type_raw:
        fuel_label = {
            "petrol": "Benzinas",
            "diesel": "Dyzelis",
            "lpg": "Dujos (LPG)",
            "cng": "Dujos (CNG)",
            "hybrid": "Hibridas",
            "electric": "Elektra",
            "other": "Kita",
        }.get(fuel_type_raw, fuel_type_raw)
        user_prompt += f"\nDegalų rūšis: {fuel_label}"
    if vin_raw:
        if is_real_vin:
            user_prompt += f"\nVIN (17 simb., naudokite tik vidiniam tikslinimui, neminėkite atsakyme): {vin_raw}"
        else:
            user_prompt += f"\nSerijinis numeris: {vin_raw}"
    if fault_desc:
        user_prompt += f"\nKliento aprašyti simptomai: {fault_desc}"
    if additional_info:
        user_prompt += (
            "\n\n🔄🔴 KLIENTO PATIKSLINIMAS (PRIORITETAS – PRIVALOMA RIMTAI ATSIŽVELGTI):\n"
            f"\"\"\"{additional_info}\"\"\"\n\n"
            "PRIVALOMA elgsena pagal KLIENTO PATIKSLINIMO TAISYKLĘ sistemos prompt'e:\n"
            "• NIEKADA NEATMESKITE šio patikslinimo kaip 'skenerio klaidos' ar 'neteisingo aprašymo'.\n"
            "• Jei šis patikslinimas NESUTAMPA su jūsų pirmine interpretacija – TAI YRA STIPRUS SIGNALAS,\n"
            "  kad pirminė interpretacija galėjo būti neteisinga. PERRINKITE galimą interpretaciją iš\n"
            "  manufacturer-specific kodo galimybių, kuri ATITINKA šį patikslinimą.\n"
            "• PERRAŠYKITE analizę pagal naują info. NETEISINKITE senos interpretacijos.\n"
            "• Pradėkite skiltį '## Klaidos paaiškinimas' žodžiais: 'Atsižvelgdamas į jūsų patikslintą\n"
            "  informaciją (...) – patikslintas paaiškinimas:' (jei reikia keisti interpretaciją)\n"
            "  arba 'Jūsų pateiktas patikslinimas patvirtina pirminę diagnozę:' (jei buvo teisinga).\n"
            "• Jei patikslinta info pašalino dviprasmybę – DiaGO_META: needs_clarification: no.\n"
            "• Jei vis dar reikia info – needs_clarification: yes su KITU klausimu (ne tuo pačiu)."
        )
    if req.previous_analysis:
        user_prompt += (
            f"\n\n📜 ANKSTESNĖ ANALIZĖ (kontekstui, neperkartoti aklai – patobulinkit atsižvelgiant į naują info):\n"
            f"{req.previous_analysis[:3000]}"
        )
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

    # === MICROCAR KB LOOKUP (curated TF-IDF paieška) ===
    # Mikroautomobiliams (Aixam, Ligier, Microcar, Chatenet, JDM ir kt.) – pirma
    # patikrinam vidinę 57 įrašų žinių bazę su Lietuvos remonto kainomis. Jei rasti
    # įrašai su pasitikėjimu >= medium (>=0.40) – įdedame juos kaip „PATIKRINTĄ ŠALTINĮ”
    # į AI prompt'ą. AI privalo juos naudoti kaip pirminį tiesos šaltinį.
    microcar_kb_hits = []  # default – tuščia, jei KB neveikė ar nieko nerado
    if eq == "microcar" and (fault_desc or codes):
        try:
            # Bandom kelis importo kelius – priklauso nuo deployment struktūros:
            # 1) diago_backend.microcar.microcar_diag (jei repo turi diago_backend/ aplankas)
            # 2) microcar.microcar_diag (jei microcar/ yra tame pačiame lygyje kaip server.py)
            try:
                from diago_backend.microcar.microcar_diag import search_microcar_issues
            except ImportError:
                from microcar.microcar_diag import search_microcar_issues
            # veh = "Aixam City S8 2017" – išskaidom į make/year
            veh_parts = (veh or "").split()
            kb_make = veh_parts[0] if veh_parts else ""
            kb_year = None
            for tok in veh_parts:
                if tok.isdigit() and 1990 <= int(tok) <= 2030:
                    kb_year = int(tok)
                    break
            kb_query_text = " ".join(filter(None, [fault_desc, additional_info, " ".join(codes)]))
            kb_results = search_microcar_issues(
                {
                    "make": kb_make,
                    "model": "",
                    "year": kb_year,
                    "engine_type": engine_code or "",
                },
                kb_query_text,
                top_k=3,
            )
            # Imam tik tuos, kurių pasitikėjimas >= "medium" (score >= 0.40)
            kb_useful = [r for r in kb_results if r.get("score", 0) >= 0.40]
            if kb_useful:
                logger.info("🛵 microcar KB: rado %d įrašų (top score=%.2f, query='%s')",
                            len(kb_useful), kb_useful[0]["score"], kb_query_text[:80])
                kb_block = "\n\n🟢🟢🟢 MICROCAR KB – PATIKRINTAS ŠALTINIS (PRIVALOMA NAUDOTI):\n"
                kb_block += (
                    "DiaGO vidinė mikroautomobilių žinių bazė (curated iš Aixam/Ligier serviso vadovų, "
                    "lietuviškų forumų ir techninių šaltinių) rado šiuos atitikimus kliento simptomams. "
                    "Šie duomenys yra PATIKRINTI ir turi pirmenybę prieš jūsų bendras LLM žinias. "
                    "PRIVALOMAI naudokite juos kaip pagrindinį priežasčių ir kainų šaltinį atsakyme:\n\n"
                )
                for i, r in enumerate(kb_useful, 1):
                    kb_block += (
                        f"--- Atitikimas #{i} (pasitikėjimas: {r['confidence']}, score={r['score']:.2f}) ---\n"
                        f"ID: {r['id']}\n"
                        f"Kategorija: {r['category']}\n"
                        f"Tikėtina priežastis: {r['possible_cause']}\n"
                        f"Rekomenduojami žingsniai (su kainomis LT):\n{r['solution']}\n\n"
                    )
                kb_block += (
                    "INSTRUKCIJOS AI:\n"
                    "1) Atsakyme aiškiai paminėkite, kad analizė remiasi DiaGO mikroautomobilių KB.\n"
                    "2) Skiltyje „Galima priežastis” naudokite KB rastas priežastis (NE savo spėjimus).\n"
                    "3) Skiltyje „Rekomendacijos” PRIVALOMAI nurodykite kainų intervalą iš KB (€).\n"
                    "4) Jei rasti keli atitikimai – išvardinkite juos pagal tikimybę.\n"
                    "5) Galite pridėti savo bendras pastabas, BET KB info yra autoritetingas šaltinis."
                )
                user_prompt += kb_block
                # Atskirai grąžinsim atsakyme – kad UI parodytų „🛵 DiaGO KB rado X atitikimų"
                microcar_kb_hits = kb_useful
            else:
                logger.info("🛵 microcar KB: nieko nerasta (geriausias score < 0.40, query='%s')",
                            kb_query_text[:80])
                microcar_kb_hits = []
        except Exception as kb_exc:
            logger.warning("Microcar KB lookup failed (non-blocking): %s", kb_exc)

    # === BARE NUMERIC KODŲ DETEKCIJA (anti-haliucinacijos sustiprinimas) ===
    # Jei vartotojas įvedė bare numeric kodą (pvz., "3297", "5003", "522506") IR technika yra
    # NE lengvasis automobilis (kuriam taikomas OBD-II SAE J2012 standartas), tada įjungiam GRIEŽTĄ
    # taisyklę – AI negali spėti šio kodo reikšmės iš generinių OBD-II analogijų.
    # Tai sprendžia problemą, kai pvz. Case IH Puma 210 kodas 3297 buvo neteisingai aiškintas
    # kaip "alkūninio veleno daviklis" (tariamai P3297), o realiai tai CNH EST kodas
    # "Rail pressure positive deviation high".
    NON_OBD_EQUIPMENT = {"agriculture", "construction", "warehouse", "truck", "microcar"}
    import re as _re
    has_bare_numeric_code = any(
        _re.match(r'^\d{3,7}(\.\d+)?$', c) for c in codes
    ) if codes else False
    if has_bare_numeric_code and eq in NON_OBD_EQUIPMENT and not has_image and not additional_info and not fault_desc:
        user_prompt += (
            "\n\n🔴🔴🔴 KRITIŠKAI SVARBU – BARE NUMERIC KODO ATVEJIS (KOMPAKTIŠKAS ATSAKYMAS):\n"
            f"Vartotojas įvedė skaitmeninį kodą BE raidinio prefikso (P/B/C/U) ir BE SPN.FMI taško. "
            f"Technikos tipas: {eq_label} (NE lengvasis automobilis – OBD-II SAE J2012 NETAIKOMAS). "
            "Be nuotraukos ir gamintojo aprašymo iš EST/SA/ET – PRIVALOMA pateikti KOMPAKTIŠKĄ atsakymą:\n\n"
            "ATSAKYMO STRUKTŪRA – PRIVALOMA TIKSLIAI (NIEKO DAUGIAU, NIEKO MAŽIAU):\n\n"
            "## ⚠️ Šis kodas reikalauja gamintojo dokumentacijos\n"
            "[Vienas pastraipa, 3–4 sakiniai: paaiškinkite, kad kodas yra gamintojo vidinis DTC ir reikia EST/SA/ET arba nuotraukos.]\n\n"
            "## Galimos pažeistos sistemos (orientacinis sąrašas)\n"
            "[Vienas pastraipa + 3–5 punktų sąrašas. Tikėtinos sritys pagal kodo diapazoną ir technikos tipą. PABRĖŽKITE 'orientacinis, ne diagnozė'.]\n\n"
            "## Rekomendacijos\n"
            "[Trumpas punktų sąrašas, 3–4 punktai: (1) patikrinti EST/SA/ET, (2) įkelti nuotrauką į DiaGO, (3) įvesti gamintojo aprašymą lauke 'Patikslinti', (4) NEPIRKTI detalių prieš gaunant tikslų aprašymą.]\n\n"
            "🚫 GRIEŽTAI DRAUDŽIAMOS sekcijos (NIEKADA NEKARTOKITE TURINIO):\n"
            "❌ NEKURKITE atskiros '## Klaidos paaiškinimas' sekcijos – jos turinys jau yra '## ⚠️ Šis kodas reikalauja...'\n"
            "❌ NEKURKITE atskiros '## Galima priežastis' sekcijos – konkrečios priežastys negali būti įvardintos be aprašymo\n"
            "❌ NEKURKITE '## Ar saugu važiuoti?' sekcijos – be tikrojo gedimo žinojimo to atsakyti negalima\n"
            "❌ NEKARTOKITE 'Klaidos kodas 3297 be raidinio prefikso yra...' sakinio kelis kartus skirtinguose blokuose\n"
            "❌ NEKARTOKITE rekomendacijų apie EST/SA/ET ir nuotrauką kelis kartus\n\n"
            "✅ TIKSLAS: trumpas, švarus, NESIKARTOJANTIS atsakymas su 3 sekcijomis tik. Niekur neturi būti to paties teksto du kartus.\n"
            "✅ DiaGO_META: severity = 'info', needs_clarification: 'yes', clarification_question = "
            "'Kokie simptomai? Ar pavyko gauti kodo aprašymą iš EST? Galite įkelti skenerio ekrano nuotrauką?'\n\n"
            "Jei NESILAIKYSITE šios struktūros – klientui atrodys, kad sistema nesutvarkyta, o jūsų atsakymas spam'inis. "
            "JŪS NETURITE DIAGNOZUOTI KODO – TIK PRIMINTI, KAIP GAUTI TIKSLŲ APRAŠYMĄ."
        )

    sid = (req.session_id or "err-default").strip() or "err-default"

    # GEMINI MODELIO PASIRINKIMAS:
    # Nemokama Google AI Studio kvota:
    #   • Gemini 2.5 Pro:   ~25–100 užklausų/dieną (LABAI mažai produkciniam naudojimui)
    #   • Gemini 2.5 Flash: 1500 užklausų/dieną + 15 req/min (priimtina)
    # Todėl PIRMINĖ analizė taip pat naudoja Flash (kokybės skirtumas mūsų diagnostiniam
    # prompt'ui yra minimalus, bet kvota 15-60× didesnė).
    # Pro liksta tik ataskaitos viduje, kai bus mokama kvota.
    model_name = "gemini-2.5-flash"

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=sid,
            system_message=ERROR_ANALYZER_PROMPT,
        ).with_model("gemini", model_name).with_params(temperature=0.0, top_p=1)

        # Sukuriam UserMessage – su nuotrauka, jei pateikta
        if has_image:
            try:
                msg = UserMessage(text=user_prompt, file_contents=[ImageContent(image_base64=img_b64)])
            except Exception as ie:
                logger.exception("ImageContent failure")
                raise HTTPException(status_code=400, detail=f"Nepavyko apdoroti nuotraukos: {str(ie)[:120]}")
        else:
            msg = UserMessage(text=user_prompt)

        analysis = await _send_with_retry(chat, msg)
        logger.info("🤖 check-error model=%s is_followup=%s has_image=%s code=%s", model_name, is_followup, has_image, raw_codes[:60])

        # Ištraukiam ir pašalinam DiaGO_META bloką
        analysis, known_codes, unknown_codes_meta, severity_map, needs_clarification, clarification_question = _parse_diago_meta(analysis or "")

        # 🛵 MICROCAR KB banner – kad vartotojas (ir admin) aiškiai matytų,
        # kada vidinė žinių bazė tikrai veikė ir kokius atitikimus rado.
        if microcar_kb_hits:
            ids = ", ".join(h["id"] for h in microcar_kb_hits[:3])
            top_score = microcar_kb_hits[0]["score"]
            kb_banner = (
                f"> 🛵 **DiaGO mikroautomobilių KB:** rasti {len(microcar_kb_hits)} "
                f"atitikim{'as' if len(microcar_kb_hits)==1 else 'ai'} "
                f"({ids}, top pasitikėjimas: {top_score:.0%}). "
                f"Žemiau pateikti duomenys remiasi šia patikrinta baze + AI analize.\n\n"
            )
            analysis = kb_banner + (analysis or "")

        # FAIL-SAFE: Jei AI grąžino TIK DiaGO_META (analizė tuščia po stripping'o), pakartojam
        # užklausą su aiškia instrukcija pateikti PILNĄ analizę. Tai apsauga nuo Gemini glitch'ų,
        # kai modelis kartais pamiršta išvest pagrindinį turinį.
        if len((analysis or "").strip()) < 60:
            logger.warning("⚠️  Tuščia analizė po META stripping (len=%d). Retry'inu su nauja instrukcija.", len(analysis or ""))
            try:
                retry_msg = UserMessage(text=(
                    user_prompt
                    + "\n\n🔴 SVARBU: ANKSTESNIS atsakymas buvo tuščias arba turėjo TIK DiaGO_META bloką. "
                    + "Šį kartą PRIVALOMA pateikti PILNĄ analizę su skiltimis:\n"
                    + "## Klaidos paaiškinimas (PRIVALOMA)\n"
                    + "## Galima priežastis (PRIVALOMA)\n"
                    + "## Rekomendacijos (PRIVALOMA)\n\n"
                    + "Skiltys turi turėti turinį (bent po 80 žodžių). DiaGO_META blokas yra TIK PAPILDOMAS metaduomenims, "
                    + "PAGRINDINIS ATSAKYMAS yra tos 3 skiltys virš jo."
                ))
                analysis2 = await chat.send_message(retry_msg)
                analysis2, k2, u2, sev2, nc2, cq2 = _parse_diago_meta(analysis2 or "")
                if len((analysis2 or "").strip()) >= 60:
                    analysis = analysis2
                    if k2: known_codes = k2
                    if u2: unknown_codes_meta = u2
                    if sev2: severity_map = sev2
                    needs_clarification = needs_clarification or nc2
                    if cq2: clarification_question = cq2
                    logger.info("✅ Retry pavyko – gauta pilna analizė (len=%d)", len(analysis))
                else:
                    # Net retry'as nepadėjo – grąžinam aiškią klaidą su default tekstu
                    logger.error("❌ Retry irgi grąžino tuščią analizę. Grąžinam fallback tekstą.")
                    analysis = (
                        "## Klaidos paaiškinimas\n\n"
                        f"Apgailestaujame – DiaGO šiuo metu negalėjo suformuoti detalios analizės kodui **{raw_codes}**. "
                        "Tai gali būti dėl AI modelio laikinos problemos arba labai retos klaidos kodo.\n\n"
                        "## Galima priežastis\n\n"
                        "Be papildomos analizės sunku tiksliai nurodyti priežastį. Rekomenduojame:\n\n"
                        "## Rekomendacijos\n\n"
                        "• Bandykite paspausti 'Analizuoti iš naujo' su papildoma informacija (variklio kodu, simptomais).\n"
                        "• Jei problema kartojasi – susisiekite per kontaktų puslapį, ir mes pagelbėsime asmeniškai.\n"
                        "• **Atsiprašome už nepatogumus** – sistema yra BETA režime ir mes ją nuolat tobuliname."
                    )
            except Exception:
                logger.exception("Retry nepavyko – paliekam pradinį (tuščią) atsakymą")

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

                # Sukuriame report_id PRIEŠ saugant error_checks, kad galėtume susieti
                report_id_out = None
                if user:
                    try:
                        import secrets as _secrets
                        report_id_out = _secrets.token_urlsafe(12)  # ~16 simbolių, unikalus
                    except Exception:
                        report_id_out = None

                # Įrašome kiekvieną kodą atskirai analitikai
                # SAUGOM PILNĄ kliento info (ne tik metaduomenis) – kad admin matytų,
                # ką klientas suvedė į paiešką. Tai galioja IR neregistruotiems vartotojams.
                # Nuotraukos NESAUGOM (per didelis dydis + privatumo problema), bet saugom
                # kodų sąrašą, KURĮ ATPAŽINOME iš nuotraukos.
                visitor_id_save = (req.visitor_id or "").strip()[:64] or None
                ip_raw = request.client.host if request.client else ""
                ip_save = _hash_ip(ip_raw) if ip_raw else None
                # Saugom tik PASKUTINIUS 4 VIN simbolius pilnam audit, kad pilnas VIN nebūtų DB
                vin_last4 = vin_raw[-4:] if vin_raw and len(vin_raw) >= 4 else None
                # Atpažinti kodai iš nuotraukos – tik jei has_image
                image_recognized_codes = (known_codes_list + unknown_codes_list) if has_image else None

                docs = []
                # Mikroautomobiliams be kodo (tik aprašymas/nuotrauka) – įrašom 1 placeholder įrašą,
                # kad admin matytų užklausą. Naudojame kodą "[BE_KODO]".
                codes_to_save = codes if codes else ["[BE_KODO]"]
                for c in codes_to_save:
                    docs.append({
                        "session_id": sid,
                        "user_id": user.get("user_id") if user else None,
                        "user_email": user.get("email") if user else None,
                        "visitor_id": visitor_id_save,  # neregistruotų vartotojų sekimas
                        "ip_hash": ip_save,
                        "report_id": report_id_out,  # susieta su ataskaita (jei yra)
                        "error_code": c,
                        "equipment": eq,
                        "equipment_label": eq_label,
                        "vehicle_info": veh[:200] if veh else None,
                        # PILNA kliento info (admin peržiūrai)
                        "engine_code": engine_code if engine_code else None,
                        "fuel_type": fuel_type_raw if fuel_type_raw else None,
                        "vin_provided": bool(vin_raw),
                        "vin_last4": vin_last4,  # tik paskutiniai 4 simb. saugumui
                        "is_vin": is_real_vin,
                        "fault_description": fault_desc[:500] if fault_desc else None,
                        "fault_description_provided": bool(fault_desc),
                        "additional_info": additional_info[:1000] if additional_info else None,
                        "had_image": has_image,
                        "image_recognized_codes": image_recognized_codes,
                        "is_followup": is_followup,
                        "is_unknown_code": (c == "[BE_KODO]") or (c in unknown_set),
                        "is_no_code": (c == "[BE_KODO]"),  # mikroautomobilio simptomų užklausa
                        "batch_size": len(codes_to_save),
                        "created_at": now,
                    })
                if docs:
                    await db.error_checks.insert_many(docs)

                # Saugome PILNĄ ataskaitą VISIEMS – tiek prisijungusiems, tiek anonimams
                # (ankščiau buvo saugoma tik prisijungusiems → admin nematė anoniminių užklausų).
                # Anonimams nuoroda neviešinama (nes user_id=None), bet admin tiek atskirai mato visas.
                if report_id_out:
                    try:
                        expires_at = now + timedelta(days=14)
                        await db.error_reports.insert_one({
                            "report_id": report_id_out,
                            "user_id": user.get("user_id") if user else None,
                            "user_email": user.get("email") if user else None,
                            "is_anonymous": user is None,
                            "visitor_id": visitor_id_save,
                            "analysis": analysis,
                            "codes": codes,
                            "known_codes": known_codes_list,
                            "unknown_codes": unknown_codes_list,
                            "severity_map": {c: severity_map.get(c, "info") for c in known_codes_list},
                            "equipment_type": eq,
                            "equipment_label": eq_label,
                            "vehicle_info": veh[:200] if veh else None,
                            "fault_description": fault_desc[:500] if fault_desc else None,
                            "vin_provided": bool(vin_raw),
                            "had_image": has_image,
                            "search_query": search_q,
                            "google_search_url": gs,
                            "google_images_url": gi,
                            "deducted_units": deducted,
                            "created_at": now,
                            "expires_at": expires_at,
                        })
                    except Exception:
                        logger.exception("error_reports save failed")
                        report_id_out = None

                # Kvotos atskaitymas tik už atpažintus kodus IR tik jei tai NE follow-up
                # (follow-up'as – nemokamas patikslinimas tos pačios analizės)
                if deducted > 0 and not is_followup:
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
                elif is_followup:
                    # Follow-up'as – kvota neliečiama
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
                            "is_followup": True,
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
                            "is_followup": True,
                            "not_charged": True,
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
            report_id=report_id_out if 'report_id_out' in locals() else None,
            report_expires_at=(expires_at.isoformat() if 'expires_at' in locals() and report_id_out else None),
            needs_clarification=needs_clarification,
            clarification_question=clarification_question,
            is_followup=is_followup,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error check failure")
        raise HTTPException(status_code=502, detail=_friendly_llm_error(e, context="Analizė nepavyko"))


# ============================
# USER REPORTS – istorija ir vieša peržiūra
# ============================

@api_router.get("/auth/history")
async def user_history(limit: int = 50, authorization: str | None = Header(default=None)):
    """Prisijungusio vartotojo paskutinės klaidų patikros (rodomos paskyroje)."""
    user = await _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Reikia prisijungti.")
    db = _get_db()
    if db is None:
        return {"items": []}
    cur = db.error_reports.find(
        {"user_id": user["user_id"]},
        {
            "_id": 0,
            "report_id": 1,
            "codes": 1,
            "known_codes": 1,
            "unknown_codes": 1,
            "severity_map": 1,
            "equipment_label": 1,
            "vehicle_info": 1,
            "fault_description": 1,
            "had_image": 1,
            "deducted_units": 1,
            "created_at": 1,
            "expires_at": 1,
        },
    ).sort("created_at", -1).limit(max(1, min(limit, 200)))
    items = await cur.to_list(200)
    # Konvertuojam datetime į ISO string su Z suffix'u (UTC)
    now = datetime.now(timezone.utc)
    for it in items:
        ea = it.get("expires_at")
        if isinstance(ea, datetime):
            if ea.tzinfo is None:
                ea = ea.replace(tzinfo=timezone.utc)
            it["expires_at"] = _iso_utc(ea)
            days_left = max(0, int((ea - now).total_seconds() / 86400))
            it["days_left"] = days_left
            it["expired"] = ea < now
        if isinstance(it.get("created_at"), datetime):
            it["created_at"] = _iso_utc(it["created_at"])
    return {"items": items}


@api_router.get("/reports/{report_id}")
async def public_report_view(report_id: str):
    """Vieša ataskaitos peržiūra. Galioja 14 d. (TTL trina automatiškai)."""
    report_id = (report_id or "").strip()
    if not report_id or len(report_id) > 64:
        raise HTTPException(status_code=400, detail="Neteisinga ataskaitos nuoroda.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    doc = await db.error_reports.find_one({"report_id": report_id}, {"_id": 0})
    if not doc:
        raise HTTPException(
            status_code=410,
            detail="Ataskaitos nuoroda nebegalioja arba neegzistuoja. Nuorodos galioja 14 dienų nuo sukūrimo.",
        )
    # Dėl saugumo nepateikiam vartotojo email
    doc.pop("user_email", None)
    doc.pop("user_id", None)
    # Konvertuojam datetime (MongoDB grąžina naive – padarom aware UTC)
    for k in ("created_at", "expires_at"):
        v = doc.get(k)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            doc[k] = v.isoformat()
    return doc


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


@api_router.get("/admin/llm-test")
async def admin_llm_test(authorization: str | None = Header(default=None)):
    """Diagnostikos endpoint'as – patikrina, ar Gemini raktas veikia.
    Padaro paprasčiausią užklausą ('ping') ir grąžina rezultatą.
    Naudojama Render aplinkos testavimui be reikalo deginti AI kvotos.
    """
    _require_admin(authorization)
    api_key, src = _get_llm_key()
    out = {
        "key_source": src,
        "key_present": bool(api_key),
        "key_preview": (api_key[:6] + "..." + api_key[-4:]) if api_key and len(api_key) > 12 else None,
        "gemini_env_set": bool(os.environ.get("GEMINI_API_KEY")),
        "emergent_env_set": bool(os.environ.get("EMERGENT_LLM_KEY")),
        "model_tested": "gemini-2.5-flash",
        "ok": False,
        "reply": None,
        "error": None,
    }
    if not api_key:
        out["error"] = "Nei GEMINI_API_KEY, nei EMERGENT_LLM_KEY nenustatytas Render aplinkoje."
        return out
    try:
        test_chat = LlmChat(
            api_key=api_key,
            session_id="admin-llm-test",
            system_message="Tu esi diagnostikos asistentas. Atsakyk vienu žodžiu.",
        ).with_model("gemini", "gemini-2.5-flash")
        reply = await test_chat.send_message(UserMessage(text="Atsakyk vienu žodžiu: 'OK'"))
        out["ok"] = True
        out["reply"] = (reply or "")[:200]
    except Exception as e:
        logger.exception("LLM test failed")
        out["error"] = _friendly_llm_error(e, context="LLM testas nepavyko")
        out["error_raw"] = str(e)[:600]
    return out


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

    # Registruoti vartotojai pagal tipą (B2C/B2B)
    private_users = await db.users.count_documents({"type": "private"})
    business_users = await db.users.count_documents({"type": "business"})
    total_registered_users = await db.users.count_documents({})

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
            "private_users": private_users,
            "business_users": business_users,
            "total_registered_users": total_registered_users,
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
    for r in rows:
        if isinstance(r.get("last_seen"), datetime):
            r["last_seen"] = _iso_utc(r["last_seen"])
    return {"items": rows}


@api_router.get("/admin/error-checks-recent")
async def admin_error_checks_recent(limit: int = 50, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        return {"items": [], "db_offline": True}
    cur = db.error_checks.find({}, {"_id": 0}).sort("created_at", -1).limit(max(1, min(limit, 200)))
    rows = await cur.to_list(200)
    # Konvertuojam datetime į UTC ISO su Z suffix'u, kad JS atvaizduotų vartotojo laiko zonoje
    for r in rows:
        if isinstance(r.get("created_at"), datetime):
            r["created_at"] = _iso_utc(r["created_at"])
    return {"items": rows}


@api_router.get("/admin/error-check-detail")
async def admin_error_check_detail(
    session_id: str | None = None,
    visitor_id: str | None = None,
    user_email: str | None = None,
    created_at: str | None = None,
    authorization: str | None = Header(default=None),
):
    """Grąžina visus tos pačios paieškos kodus (pagal session_id + created_at) su pilna kliento info.
    
    Logika: viena paieška gali turėti kelis kodus (batch). Identifikuojam ją pagal session_id ir laiką
    (±5 min) – grąžinam visus susijusius dokumentus + susietą error_report (jei yra) su pilna analize.
    """
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB offline")

    query: dict = {}
    if session_id:
        query["session_id"] = session_id
    if visitor_id:
        query["visitor_id"] = visitor_id
    if user_email:
        query["user_email"] = user_email

    # Laiko langas: ±5 min
    if created_at:
        try:
            ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            query["created_at"] = {"$gte": ts - timedelta(minutes=5), "$lte": ts + timedelta(minutes=5)}
        except Exception:
            pass

    if not query:
        raise HTTPException(status_code=400, detail="Reikia bent session_id, visitor_id arba user_email.")

    cur = db.error_checks.find(query, {"_id": 0}).sort("created_at", 1).limit(50)
    items = await cur.to_list(50)
    for r in items:
        if isinstance(r.get("created_at"), datetime):
            r["created_at"] = _iso_utc(r["created_at"])

    # Surandam ataskaitą (jei yra report_id)
    report = None
    report_id = None
    for it in items:
        if it.get("report_id"):
            report_id = it["report_id"]
            break
    if report_id:
        rdoc = await db.error_reports.find_one({"report_id": report_id}, {"_id": 0})
        if rdoc:
            if isinstance(rdoc.get("created_at"), datetime):
                rdoc["created_at"] = _iso_utc(rdoc["created_at"])
            if isinstance(rdoc.get("expires_at"), datetime):
                rdoc["expires_at"] = _iso_utc(rdoc["expires_at"])
            report = rdoc

    return {"checks": items, "report": report, "report_id": report_id}


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
# Lietuviški „stop words” – nešalinami iš n-grams analizės
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
    """Grąžina kategoriją pagal raktažodžius. „Kita” jei nė viena nesuveikia."""
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
        api_key, _src = _get_llm_key()
        if api_key:
            try:
                # Imam top 50 unikalių pirmų žinučių
                sample_questions = [items[0] for _, items in top_questions_raw[:50] if items]
                prompt = (
                    f"Pateikiu sąrašą {len(sample_questions)} klientų klausimų DiaGO konsultantui per "
                    f"paskutines {days} dienų. Trumpai (4-6 sakiniais) apibendrink, ko klientai DAŽNIAUSIAI klausė ir "
                    f"kokios yra pagrindinės temos. Atsakyk LIETUVIŲ kalba, dalykiškai. Pradėk frazę „Per paskutines {days} dienų klientai dažniausiai...\”.\n\n"
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
            summary = "LLM raktas (GEMINI_API_KEY arba EMERGENT_LLM_KEY) nenustatytas."

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
    marketing_email: bool = False  # Sutikimas gauti informaciją el. paštu
    marketing_phone: bool = False  # Sutikimas gauti informaciją telefonu (SMS/skambučiu)


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
    company_email: str | None = None  # privalomas verslo paskyrai (sąskaitoms / korespondencijai)
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
        "type": None,
        "profile": {},
        "created_at": now,
        "last_login": now,
        "checks_count": 0,
        "blocked": False,
        # Marketing sutikimai (gautas registracijos metu)
        "marketing_email": bool(req.marketing_email),
        "marketing_phone": bool(req.marketing_phone),
        "marketing_consents_at": now,
    })
    token = _make_user_token(user_id, email)
    return UserResponse(token=token, email=email, user_id=user_id, has_profile=False)


@api_router.post("/auth/resend-verification")
async def auth_resend_verification(req: dict, background_tasks: BackgroundTasks):
    """Pakartotinai siunčia patvirtinimo laišką."""
    email = (req.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Įveskite el. paštą.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    user = await db.users.find_one({"email": email})
    if not user:
        # Neatskleidžiam, ar egzistuoja (saugumas)
        return {"ok": True, "message": "Jei toks el. paštas yra registruotas ir nepatvirtintas – ką tik išsiuntėme naują patvirtinimo nuorodą."}
    if user.get("email_verified"):
        return {"ok": True, "already_verified": True, "message": "Šis el. paštas jau patvirtintas. Galite prisijungti."}

    # Sukuriam naują tokeną (anuliuojam senąjį)
    new_token = secrets.token_urlsafe(32)
    new_expires = datetime.now(timezone.utc) + timedelta(hours=48)
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"verification_token": new_token, "verification_expires_at": new_expires}},
    )
    name = (user.get("profile") or {}).get("first_name") or ""
    subject, html_body, plain_body = _build_verification_email(email, new_token, name=name)
    background_tasks.add_task(_send_email, email, subject, html_body, plain_body)
    return {"ok": True, "message": "Patvirtinimo laišką išsiuntėme. Patikrinkite savo pašto dėžutę (taip pat ir SPAM aplanką)."}


@api_router.get("/auth/verify-email")
async def auth_verify_email(token: str | None = None):
    """Patvirtina el. paštą pagal token'ą iš laiško nuorodos."""
    token = (token or "").strip()
    if not token or len(token) < 16:
        raise HTTPException(status_code=400, detail="Neteisinga patvirtinimo nuoroda.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    user = await db.users.find_one({"verification_token": token})
    if not user:
        raise HTTPException(status_code=410, detail="Patvirtinimo nuoroda nebegalioja arba jau buvo panaudota. Jei dar neprisijungėte, prašome prisijungti – galbūt el. paštas jau patvirtintas.")

    exp = user.get("verification_expires_at")
    if isinstance(exp, datetime):
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=410, detail="Patvirtinimo nuorodos galiojimas baigėsi (48 val.). Užklausykite naujos.")

    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "email_verified": True,
                "verified_at": datetime.now(timezone.utc),
            },
            "$unset": {"verification_token": "", "verification_expires_at": ""},
        },
    )
    return {"ok": True, "email": user["email"], "message": "El. paštas sėkmingai patvirtintas! Dabar galite prisijungti."}


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

    # Blokavimo patikrinimas
    if user.get("blocked"):
        block_reason = user.get("block_reason") or ""
        msg = "Jūsų paskyra užblokuota. Susisiekite su administratoriumi: jt@diago.lt"
        if block_reason:
            msg = f"Jūsų paskyra užblokuota. Priežastis: {block_reason}. Susisiekite: jt@diago.lt"
        raise HTTPException(status_code=403, detail=msg)

    # El. pašto patvirtinimas NEBEBLOKUOJA prisijungimo (admin patvirtina rankiniu būdu).
    # Indikatorius "📧 Nepatvirtintas" matomas admin panelėje, leidžiant administratoriui
    # patvirtinti arba užblokuoti vartotoją.

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


# ============================
# Paskyros ištrynimas (savitarna) – Option A: reikalingas slaptažodis
# ============================
class DeleteAccountRequest(BaseModel):
    password: str


@api_router.delete("/auth/me")
async def auth_delete_me(req: DeleteAccountRequest, authorization: str | None = Header(default=None)):
    """Vartotojas ištrina savo paskyrą po slaptažodžio patvirtinimo.

    Veiksmas:
      1. Patvirtinam sesiją (token).
      2. Patikrinam slaptažodį.
      3. Anonimizuojam susijusius `error_checks` (user_id -> null), kad statistika ir
         istorija (visitor_id pagrindu) liktų, bet asmuo nebebūtų susiejamas.
      4. Ištrinam `error_reports`, `renewal_requests` (asmeniniai duomenys).
      5. Ištrinam vartotoją iš `users`.
    """
    user = await _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Nepatvirtinta sesija.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")

    pw = (req.password or "").strip()
    if not pw:
        raise HTTPException(status_code=400, detail="Įveskite slaptažodį.")

    user_id = user.get("user_id")
    email = user.get("email", "")
    if not user_id:
        raise HTTPException(status_code=500, detail="Vidinė klaida – paskyra neturi ID.")

    # _get_current_user grąžina dokumentą be password_hash/salt (saugumo sumetimais).
    # Slaptažodžio patikrai turim atskirai užklausti.
    full_user = await db.users.find_one(
        {"user_id": user_id},
        {"password_hash": 1, "password_salt": 1},
    )
    if not full_user:
        raise HTTPException(status_code=401, detail="Paskyra nerasta.")

    # Tikrinam slaptažodį
    if not _user_verify_password(pw, full_user.get("password_salt", ""), full_user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Neteisingas slaptažodis.")

    summary: dict = {}

    # 1. Anonimizuojam error_checks (statistika lieka, asmuo atsiejamas)
    try:
        r = await db.error_checks.update_many(
            {"user_id": user_id},
            {"$set": {"user_id": None, "anonymized_at": datetime.now(timezone.utc)}},
        )
        summary["error_checks_anonymized"] = r.modified_count
    except Exception:
        logger.exception("auth_delete_me: nepavyko anonimizuoti error_checks")
        summary["error_checks_anonymized"] = -1

    # 2. Trinam error_reports (jie turi asmeninius duomenis – kontaktus, transporto info)
    try:
        r = await db.error_reports.delete_many({"user_id": user_id})
        summary["error_reports_deleted"] = r.deleted_count
    except Exception:
        logger.exception("auth_delete_me: nepavyko ištrinti error_reports")
        summary["error_reports_deleted"] = -1

    # 3. Trinam renewal_requests
    try:
        r = await db.renewal_requests.delete_many({"user_id": user_id})
        summary["renewal_requests_deleted"] = r.deleted_count
    except Exception:
        logger.exception("auth_delete_me: nepavyko ištrinti renewal_requests")
        summary["renewal_requests_deleted"] = -1

    # 4. Trinam patį vartotoją
    try:
        r = await db.users.delete_one({"user_id": user_id})
        summary["users_deleted"] = r.deleted_count
    except Exception:
        logger.exception("auth_delete_me: nepavyko ištrinti vartotojo")
        raise HTTPException(status_code=500, detail="Nepavyko ištrinti paskyros. Susisiekite su admin'u.")

    logger.info("🗑  Vartotojas SAVANORIŠKAI ištrynė paskyrą: %s (%s). Suvestinė: %s", email, user_id, summary)

    return {"ok": True, "summary": summary, "email": email}


@api_router.put("/auth/profile")
async def auth_update_profile(req: ProfileUpdateRequest, authorization: str | None = Header(default=None)):
    user = await _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Nepatvirtinta sesija.")
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")

    # Nustatom tipą
    new_type = req.type if req.type is not None else user.get("type")
    if new_type not in ("private", "business"):
        raise HTTPException(status_code=400, detail="Pasirinkite vartotojo tipą (privatus arba verslo).")

    # Helper: gauti reikšmę iš request arba esamo profilio
    existing_profile = (user.get("profile") or {})
    def _get(field):
        v = getattr(req, field, None)
        if v is None:
            v = existing_profile.get(field, "")
        return (v or "").strip()

    # Privalomi laukai pagal tipą
    errors = []
    if new_type == "private":
        if not _get("first_name"):
            errors.append("Vardas yra privalomas.")
        if not _get("last_name"):
            errors.append("Pavardė yra privaloma.")
        if not _get("phone"):
            errors.append("Telefono numeris yra privalomas.")
    else:  # business
        if not _get("company_name"):
            errors.append("Įmonės pavadinimas yra privalomas.")
        if not _get("company_code"):
            errors.append("Įmonės kodas yra privalomas.")
        if not _get("vat_code"):
            errors.append("PVM kodas yra privalomas.")
        if not _get("address"):
            errors.append("Adresas yra privalomas.")
        ce = _get("company_email")
        if not ce:
            errors.append("Įmonės el. paštas yra privalomas.")
        elif not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", ce):
            errors.append("Neteisingas įmonės el. pašto formatas.")
        if not _get("phone"):
            errors.append("Telefono numeris yra privalomas.")

    if errors:
        raise HTTPException(status_code=400, detail=" ".join(errors))

    update = {"type": new_type}

    profile_fields = {
        "first_name": req.first_name, "last_name": req.last_name, "phone": req.phone,
        "company_name": req.company_name, "company_code": req.company_code, "vat_code": req.vat_code,
        "address": req.address, "company_email": req.company_email,
        "city": req.city, "country": req.country,
        "contact_person": req.contact_person,
    }
    for k, v in profile_fields.items():
        if v is not None:
            update[f"profile.{k}"] = (v or "").strip()[:200]
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
        # Konvertuojam datetime į UTC ISO su Z suffix
        for k in ("created_at", "last_login", "updated_at", "subscription_updated_at",
                  "subscription_renews_at", "verification_expires_at", "verified_at",
                  "blocked_at"):
            if isinstance(u.get(k), datetime):
                u[k] = _iso_utc(u[k])

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


class AdminBlockUserRequest(BaseModel):
    user_id: str
    blocked: bool
    reason: str | None = None


class AdminVerifyUserRequest(BaseModel):
    user_id: str
    verified: bool = True


@api_router.post("/admin/users/verify-email")
async def admin_users_verify(req: AdminVerifyUserRequest, authorization: str | None = Header(default=None)):
    """Rankinis el. pašto patvirtinimas / atšaukimas administracinis veiksmas.
    Admin'as gali pažymėti vartotojo el. paštą kaip patvirtintą (verified=True) arba grąžinti į nepatvirtintą būseną.
    """
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    update = {"email_verified": bool(req.verified)}
    if req.verified:
        update["verified_at"] = datetime.now(timezone.utc)
        update["verified_by_admin"] = True
    res = await db.users.update_one(
        {"user_id": req.user_id},
        {"$set": update, "$unset": {"verification_token": "", "verification_expires_at": ""} if req.verified else {}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vartotojas nerastas.")
    return {"ok": True, "email_verified": bool(req.verified)}


@api_router.get("/admin/test-smtp")
async def admin_test_smtp(to: str | None = None, authorization: str | None = Header(default=None)):
    """Diagnostinis endpoint'as: parodo SMTP konfigūraciją ir bando siųsti testinį laišką.
    Naudojimas (su admin token):
      GET /api/admin/test-smtp           – tik info, ar SMTP env nustatyti
      GET /api/admin/test-smtp?to=jt@diago.lt  – ir bando išsiųsti testinį laišką
    """
    _require_admin(authorization)
    cfg = _smtp_config()
    info = {
        "smtp_configured": cfg is not None,
        "smtp_host": (os.environ.get("SMTP_HOST") or "(NENUSTATYTA)"),
        "smtp_port": os.environ.get("SMTP_PORT") or "(NENUSTATYTA)",
        "smtp_user": os.environ.get("SMTP_USER") or "(NENUSTATYTA)",
        "smtp_password_set": bool(os.environ.get("SMTP_PASSWORD")),
        "smtp_password_length": len(os.environ.get("SMTP_PASSWORD") or ""),
        "smtp_use_ssl": os.environ.get("SMTP_USE_SSL") or "false",
        "smtp_from_name": os.environ.get("SMTP_FROM_NAME") or "DiaGO",
        "aiosmtplib_installed": aiosmtplib is not None,
        "dnspython_installed": dns is not None,
        "public_site_url": _public_site_url(),
    }
    if not cfg:
        info["test_send"] = "PRALEISTA – SMTP_HOST/USER/PASSWORD nenustatyti Render.com Environment'e"
        return info
    if not to:
        info["test_send"] = "PRALEISTA – nenurodytas ?to=email parametras"
        return info

    target = to.strip()
    subject = "DiaGO SMTP testinis laiškas"
    html = f"<p>Sveiki!</p><p>Tai testinis laiškas iš DiaGO backend.</p><p>Jei jį gavote – SMTP konfigūracija veikia ✓</p><p style='color:#888;font-size:11px;'>UTC: {datetime.now(timezone.utc).isoformat()}</p>"
    plain = f"DiaGO SMTP testinis laiškas. Jei gavote – konfigūracija veikia.\nUTC: {datetime.now(timezone.utc).isoformat()}"

    # Bandome siųsti TIESIOGIAI (be _send_email helper'io), kad gautume tikslią klaidą
    if aiosmtplib is None:
        info["test_send"] = "✗ aiosmtplib biblioteka neįdiegta"
        info["test_send_ok"] = False
        return info

    msg = EmailMessage()
    msg["From"] = f"{cfg['from_name']} <{cfg['user']}>"
    msg["To"] = target
    msg["Subject"] = subject
    msg.set_content(plain)
    msg.add_alternative(html, subtype="html")

    error_detail = None
    try:
        if cfg["use_ssl"]:
            await aiosmtplib.send(msg, hostname=cfg["host"], port=cfg["port"],
                username=cfg["user"], password=cfg["password"],
                use_tls=True, timeout=10)
        else:
            await aiosmtplib.send(msg, hostname=cfg["host"], port=cfg["port"],
                username=cfg["user"], password=cfg["password"],
                start_tls=True, timeout=10)
        info["test_send"] = f"✓ Sėkmingai išsiųsta į {target}"
        info["test_send_ok"] = True
    except Exception as e:
        error_detail = f"{type(e).__name__}: {str(e)[:400]}"
        info["test_send"] = f"✗ KLAIDA: {error_detail}"
        info["test_send_ok"] = False
        info["error_class"] = type(e).__name__
        info["error_message"] = str(e)[:600]

    # Papildomai - bandom alternatyvius portus, jei pirmas nepavyko (trumpesnis timeout 6s)
    if not info.get("test_send_ok"):
        info["fallback_tests"] = []
        for fallback_port, fallback_ssl in [(465, True), (25, False), (2525, False)]:
            if fallback_port == cfg["port"]:
                continue
            try:
                if fallback_ssl:
                    await aiosmtplib.send(msg, hostname=cfg["host"], port=fallback_port,
                        username=cfg["user"], password=cfg["password"],
                        use_tls=True, timeout=6)
                else:
                    await aiosmtplib.send(msg, hostname=cfg["host"], port=fallback_port,
                        username=cfg["user"], password=cfg["password"],
                        start_tls=True, timeout=6)
                info["fallback_tests"].append(f"✓ Port {fallback_port} ({'SSL' if fallback_ssl else 'STARTTLS'}): VEIKIA – nurodykite SMTP_PORT={fallback_port}" + (f", SMTP_USE_SSL=true" if fallback_ssl else ""))
            except Exception as fe:
                info["fallback_tests"].append(f"✗ Port {fallback_port}: {type(fe).__name__}: {str(fe)[:120]}")
    return info


@api_router.post("/admin/users/block")
async def admin_users_block(req: AdminBlockUserRequest, authorization: str | None = Header(default=None)):
    """Užblokuoja arba atblokuoja vartotoją (vartotojas negali prisijungti, bet duomenys lieka)."""
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    update = {
        "blocked": bool(req.blocked),
        "blocked_at": datetime.now(timezone.utc) if req.blocked else None,
    }
    if req.blocked:
        update["block_reason"] = (req.reason or "").strip()[:300]
    else:
        update["block_reason"] = ""
    res = await db.users.update_one({"user_id": req.user_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vartotojas nerastas.")
    return {"ok": True, "blocked": bool(req.blocked)}


class AdminDeleteUserRequest(BaseModel):
    user_id: str
    confirm_email: str  # vartotojas turi patvirtinti email'ą kaip apsaugą nuo netyčinio trynimo


@api_router.post("/admin/users/delete")
async def admin_users_delete(req: AdminDeleteUserRequest, authorization: str | None = Header(default=None)):
    """Visiškai ištrina vartotoją ir visus jo duomenis (negrįžtamai).
    Reikalauja patvirtinti vartotojo email'ą (kad nebūtų netyčia ištrintas).
    """
    _require_admin(authorization)
    db = _get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="DB nepasiekiama.")
    user = await db.users.find_one({"user_id": req.user_id}, {"email": 1, "user_id": 1})
    if not user:
        raise HTTPException(status_code=404, detail="Vartotojas nerastas.")
    if (req.confirm_email or "").strip().lower() != user["email"].strip().lower():
        raise HTTPException(status_code=400, detail="Patvirtinimo el. paštas nesutampa su vartotojo el. paštu.")

    # Ištrinam visus susijusius duomenis
    user_id = user["user_id"]
    email = user["email"]
    deleted_counts = {}

    try:
        r = await db.users.delete_one({"user_id": user_id})
        deleted_counts["users"] = r.deleted_count
    except Exception as e:
        logger.exception("Klaida trinant users: %s", e)

    try:
        r = await db.error_reports.delete_many({"user_id": user_id})
        deleted_counts["error_reports"] = r.deleted_count
    except Exception:
        pass

    try:
        r = await db.renewal_requests.delete_many({"user_id": user_id})
        deleted_counts["renewal_requests"] = r.deleted_count
    except Exception:
        pass

    # error_checks gali būti susiję per visitor_id arba user_id – trinam tik su user_id
    try:
        r = await db.error_checks.delete_many({"user_id": user_id})
        deleted_counts["error_checks"] = r.deleted_count
    except Exception:
        pass

    logger.info("🗑  Vartotojas ištrintas: %s (%s). Pašalinta: %s", email, user_id, deleted_counts)
    return {"ok": True, "deleted": deleted_counts, "email": email}


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
        # Vartotojo ataskaitos – auto-trynimas pagal expires_at lauką (14 d. nuo sukūrimo)
        await db.error_reports.create_index(
            "expires_at",
            expireAfterSeconds=0,  # =0 reiškia: trinti, kai expires_at praeina
            name="reports_ttl",
        )
        await db.error_reports.create_index("report_id", unique=True, name="reports_unique_id")
        await db.error_reports.create_index([("user_id", 1), ("created_at", -1)], name="reports_user_idx")
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


def _get_llm_key() -> tuple[str, str]:
    """Grąžina (raktas, šaltinis). 
    Pirmenybė: GEMINI_API_KEY (tikras Google AI Studio raktas) > EMERGENT_LLM_KEY (universalus per Emergent).
    Tai leidžia vartotojui užsikrauti SAVO Gemini kvotą ir nepriklausyti nuo bendrų kreditų.
    """
    g = (os.environ.get("GEMINI_API_KEY") or "").strip()
    if g and not g.startswith("sk-emergent"):  # tikras Google key
        # LiteLLM auto-aptinka šį env var natyviai per Gemini provider
        os.environ["GEMINI_API_KEY"] = g
        return g, "gemini-direct"
    e = (os.environ.get("EMERGENT_LLM_KEY") or "").strip()
    if e:
        return e, "emergent"
    return "", "none"


def _is_transient_llm_error(e: Exception) -> bool:
    """Patikrina, ar klaida yra LAIKINA (verta retry) – Gemini overload, rate limit ir t.t."""
    raw = str(e).lower()
    transient_markers = [
        "503", "overloaded", "high demand", "experiencing high",
        "unavailable", "deadline", "timeout", "timed out",
        "429", "rate limit", "resource_exhausted",
        "internal error", "internal_server_error", "5xx",
        "spikes in demand",
    ]
    return any(m in raw for m in transient_markers)


def _is_quota_error(e: Exception) -> bool:
    """Konkretus quota / rate limit klaidos požymis (429 / RESOURCE_EXHAUSTED)."""
    raw = str(e).lower()
    return ("429" in raw or "resource_exhausted" in raw or "quota" in raw
            or "rate limit" in raw or "quota_exceeded" in raw)


async def _send_with_retry(chat, msg, max_retries: int = 2, base_delay: float = 2.5,
                           enable_emergent_fallback: bool = True,
                           chat_factory=None):
    """Siunčia žinutę su automatiniu pakartojimu ir Emergent LLM fallback'u kvotos išnaudojimo atveju.

    Args:
        chat_factory: opcionali callable(api_key: str) -> chat, kuri leidžia sukurti
                      naują chat objektą su alternatyviu raktu (Emergent fallback).
                      Jei None – fallback nevykdomas.
    """
    import asyncio as _asyncio

    async def _try_emergent_fallback(orig_exc: Exception):
        """Jei Gemini kvota išnaudota IR turime EMERGENT_LLM_KEY – bandom su juo."""
        if not (enable_emergent_fallback and chat_factory is not None):
            return None
        emergent_key = (os.environ.get("EMERGENT_LLM_KEY") or "").strip()
        if not emergent_key:
            return None
        logger.warning("🔄 Gemini kvota išnaudota → jungiu Emergent LLM fallback")
        try:
            fb_chat = chat_factory(emergent_key)
            return await fb_chat.send_message(msg)
        except Exception as fbe:
            logger.warning("Emergent fallback taip pat nepavyko: %s", str(fbe)[:200])
            return None

    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return await chat.send_message(msg)
        except Exception as e:
            last_exc = e
            # ⚡ Kvotos klaida – nedelsiant į Emergent (nešvaistom retries į išnaudotą Gemini)
            if _is_quota_error(e):
                fb = await _try_emergent_fallback(e)
                if fb is not None:
                    return fb
                raise
            if not _is_transient_llm_error(e) or attempt >= max_retries:
                # Paskutinis šansas – gal Emergent padės (jei tai transient bet ne quota)
                fb = await _try_emergent_fallback(e)
                if fb is not None:
                    return fb
                raise
            delay = base_delay * (2 ** attempt)  # 2.5s → 5s → 10s
            logger.warning("⏳ Gemini transient klaida (bandymas %d/%d): %s. Pakartoju po %.1fs",
                           attempt + 1, max_retries + 1, str(e)[:120], delay)
            await _asyncio.sleep(delay)
    if last_exc:
        raise last_exc
    raise RuntimeError("Nepavyko atlikti LLM užklausos po pakartojimų.")


def _friendly_llm_error(e: Exception, context: str = "Analizė nepavyko") -> str:
    """Konvertuoja techninę LLM klaidą į vartotojui suprantamą žinutę su konkrečiu sprendimu.
    Tai SUPER svarbu produkcijoje, nes vartotojas mato tik 1 eilutę.
    """
    raw = str(e)
    low = raw.lower()
    # Bandom išgauti error JSON iš litellm exception teksto
    import re as _re
    msg_match = _re.search(r'"message"\s*:\s*"([^"]{5,400})"', raw)
    code_match = _re.search(r'"code"\s*:\s*(\d{3})', raw)
    status_match = _re.search(r'"status"\s*:\s*"([A-Z_]+)"', raw)
    inner_msg = msg_match.group(1) if msg_match else ""
    inner_code = code_match.group(1) if code_match else ""
    inner_status = status_match.group(1) if status_match else ""

    # === Konkretūs scenarijai ===
    if "api_key_invalid" in low or "api key not valid" in low or inner_status == "INVALID_ARGUMENT" and "api key" in (inner_msg or "").lower():
        return (f"{context}: Gemini API raktas yra neteisingas. Patikrinkite GEMINI_API_KEY reikšmę Render → Environment "
                f"(turi būti iš https://aistudio.google.com/app/apikey, prasidedantis 'AIza...').")
    if "permission_denied" in low or inner_status == "PERMISSION_DENIED":
        return (f"{context}: Gemini API neturi leidimo. Įsitikinkite, kad raktas yra įjungtas Google Cloud/AI Studio "
                f"projektui ir 'Generative Language API' yra aktyvuotas.")
    if "quota" in low or "429" in raw or inner_status in ("RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"):
        return (f"{context}: Gemini API kvota išnaudota (15 RPM / 1500 per dieną nemokamame plane). "
                f"Palaukite 1 min. arba įjunkite mokamą planą Google AI Studio.")
    if "model" in low and ("not found" in low or "not exist" in low or "404" in raw):
        return (f"{context}: Gemini modelis 'gemini-2.5-flash' nepasiekiamas su jūsų raktu. "
                f"Patikrinkite, ar raktas turi prieigą prie naujausių modelių, arba parašykite mums.")
    if "safety" in low or "blocked" in low or "content_filter" in low:
        return (f"{context}: Gemini saugumo filtras blokavo užklausą. Pabandykite be paveikslo arba performuluokite.")
    if "image" in low and ("too large" in low or "size" in low):
        return (f"{context}: Nuotrauka per didelė. Sumažinkite iki <4 MB ir bandykite dar kartą.")
    if "deadline" in low or "timeout" in low:
        return (f"{context}: Gemini neatsakė laiku (timeout). Bandykite dar kartą po kelių sekundžių.")

    # === Bendras fallback su MAX info, kad galėtume diagnozuoti ===
    snippet = (inner_msg or raw)[:400].replace("\n", " ").strip()
    if inner_code or inner_status:
        return f"{context} (Gemini {inner_code or inner_status}): {snippet}"
    return f"{context}: {snippet}"



@app.on_event("startup")
async def startup():
    logger.info("DiaGO API starting up...")
    _key, _src = _get_llm_key()
    if not _key:
        logger.warning("⚠️  Nei GEMINI_API_KEY, nei EMERGENT_LLM_KEY nenustatytas! AI funkcijos neveiks.")
    else:
        logger.info("✅ LLM raktas iš: %s", _src)
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
