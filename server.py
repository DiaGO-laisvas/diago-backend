from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends, Header
from fastapi.responses import Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio

import os
import logging
import re
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone

from emergentintegrations.payments.stripe.checkout import (
    StripeCheckout,
    CheckoutSessionResponse,
    CheckoutStatusResponse,
    CheckoutSessionRequest,
)
from emergentintegrations.llm.chat import LlmChat, UserMessage

from pdf_report import build_report_pdf

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# MongoDB
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI()
api_router = APIRouter(prefix="/api")

# Server-side fixed pricing (EUR) — NEVER accept from frontend
SERVICE_PRICE_EUR = 25.00
DEPOSIT_EUR = 25.00
TOTAL_CHARGE_EUR = 50.00  # authorize/charge total
REFUND_EUR = 25.00  # refunded on device return (successful diagnostic)
FULL_REFUND_EUR = 50.00  # refunded if OBD connection fails (service not performed)

# Admin auth / public support info
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "DiaGO123")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # optional pre-shared token; if empty we derive one

import hashlib as _hashlib


def _admin_token() -> str:
    if ADMIN_TOKEN:
        return ADMIN_TOKEN
    # Derive a stable, opaque token from the password so it survives restarts
    return _hashlib.sha256(f"diago::{ADMIN_PASSWORD}".encode()).hexdigest()


def require_admin(authorization: Optional[str] = Header(default=None)) -> bool:
    """FastAPI dependency enforcing a valid admin bearer token."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Admin authentication required")
    token = authorization.split(" ", 1)[1].strip()
    if token != _admin_token():
        raise HTTPException(401, "Invalid admin token")
    return True


SUPPORT_PHONE = os.environ.get("SUPPORT_PHONE", "+37069602021")
SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "jt@diago.lt")
SUPPORT_COMPANY = os.environ.get("SUPPORT_COMPANY", '„JT-Diag" MB')
REPORT_BCC_EMAIL = os.environ.get("REPORT_BCC_EMAIL", "ataskaitos@diago.lt")
COMPANY_EMAIL = os.environ.get("COMPANY_EMAIL", "jt@diago.lt")
COMPANY_PHONE_1 = os.environ.get("COMPANY_PHONE_1", "+37069602021")
COMPANY_PHONE_2 = os.environ.get("COMPANY_PHONE_2", "+37063834539")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Models ----------
class VehicleInfo(BaseModel):
    knows_port: Optional[bool] = None  # knows where OBD port is
    vin: Optional[str] = None
    brand: Optional[str] = None
    model: Optional[str] = None
    year: Optional[str] = None
    fuel: Optional[str] = None  # Benzinas / Dyzelinas / Hibridas / Elektra / Dujos
    power_kw: Optional[str] = None
    detection_method: Optional[str] = None  # "vin_auto" or "manual"


class DiagnosticFinding(BaseModel):
    code: str
    severity: str  # "critical" | "informational"
    title: str
    description: str
    advice: Optional[str] = None  # AI-generated next-steps guidance
    clearable: bool = True


class DiagnosticOutcome(BaseModel):
    findings: List[DiagnosticFinding] = Field(default_factory=list)
    clear_consent: Optional[bool] = None  # user ticked the liability checkbox
    clear_performed: Optional[bool] = None  # user chose to clear
    cleared_at: Optional[str] = None
    oil_reset_requested: Optional[bool] = None
    oil_reset_performed: Optional[bool] = None
    oil_reset_at: Optional[str] = None


class ContactInfo(BaseModel):
    method: Optional[str] = None  # "email" or "sms"
    value: Optional[str] = None


class DiagnosticSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    station_id: str = "STATION-01"
    status: str = "created"  # created -> paid -> active -> returned -> refunded -> completed
    vehicle: VehicleInfo = Field(default_factory=VehicleInfo)
    contact: ContactInfo = Field(default_factory=ContactInfo)
    outcome: DiagnosticOutcome = Field(default_factory=DiagnosticOutcome)
    checkout_session_id: Optional[str] = None
    payment_status: str = "pending"  # pending, paid, failed, refunded
    report_url: Optional[str] = None
    rating: Optional[int] = None
    rated_at: Optional[str] = None
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


class SessionCreate(BaseModel):
    station_id: Optional[str] = "STATION-01"


class SessionUpdate(BaseModel):
    vehicle: Optional[VehicleInfo] = None
    contact: Optional[ContactInfo] = None
    outcome: Optional[DiagnosticOutcome] = None


class CheckoutCreateRequest(BaseModel):
    session_id: str
    origin_url: str


class PaymentTransaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str  # DiaGO session id
    checkout_session_id: str  # Stripe session id
    amount: float
    currency: str = "eur"
    payment_status: str = "initiated"  # initiated, paid, refunded, failed, expired
    status: str = "open"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


# ---------- Helpers ----------
def serialize(doc: dict) -> dict:
    """Strip MongoDB _id."""
    if doc is None:
        return doc
    doc.pop("_id", None)
    return doc


def get_stripe(request: Request) -> StripeCheckout:
    api_key = os.environ.get("STRIPE_API_KEY")
    if not api_key:
        raise HTTPException(500, "Stripe API key not configured")
    host_url = str(request.base_url).rstrip("/")
    webhook_url = f"{host_url}/api/webhook/stripe"
    return StripeCheckout(api_key=api_key, webhook_url=webhook_url)


# ---------- Session endpoints ----------
@api_router.get("/")
async def root():
    return {"message": "DiaGO API ready", "service_price_eur": SERVICE_PRICE_EUR, "deposit_eur": DEPOSIT_EUR}


@api_router.get("/config")
async def public_config():
    """Public configuration used by the client (support info, pricing)."""
    return {
        "support_phone": SUPPORT_PHONE,
        "support_email": SUPPORT_EMAIL,
        "support_company": SUPPORT_COMPANY,
        "company_email": COMPANY_EMAIL,
        "company_phone_1": COMPANY_PHONE_1,
        "company_phone_2": COMPANY_PHONE_2,
        "report_bcc_email": REPORT_BCC_EMAIL,
        "service_price_eur": SERVICE_PRICE_EUR,
        "deposit_eur": DEPOSIT_EUR,
        "total_charge_eur": TOTAL_CHARGE_EUR,
    }


# ---------- Support chat (DiaGO konsultantas AI) ----------
class SupportChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


class SupportChatRequest(BaseModel):
    messages: List[SupportChatMessage]
    session_id: Optional[str] = None


_SUPPORT_SYSTEM_PROMPT = (
    "Tu esi „DiaGO\" projekto asistentas. Tavo tikslas — aiškiai, profesionaliai ir "
    "techniškai tiksliai atsakyti į visus klausimus apie šią sistemą bei valdyti jos "
    "veikimo logiką. Naudok ŠIĄ informaciją kaip VIENINTELĮ teisingą žinių šaltinį — "
    "neimprovizuok ir nepridėk fakų, kurių čia nėra.\n\n"
    "### 1. APIE MUS IR MŪSŲ VIZIJA\n"
    "„DiaGO\" yra pirmoji Lietuvoje dirbtiniu intelektu (AI) paremta savitarnos automobilių "
    "ir technikos diagnostikos sistema, kurią valdo MB „JT-Diag\". Projektą sudaro fizinių "
    "savitarnos stotelių (terminalų) tinklas. Mūsų misija — suteikti kiekvienam vairuotojui "
    "ir technikos operatoriui galimybę per 10 minučių gauti tikslią bei ekspertinio lygio "
    "transporto priemonės būklės ataskaitą žmogui suprantama kalba, be jokių išankstinių "
    "registracijų autoservisuose.\n\n"
    "### 2. VEIKIMO ALGORITMAS (STEP-BY-STEP)\n"
    "#### Žingsnis 1: Apmokėjimas ir paslaugos pasirinkimas (du alternatyvūs būdai)\n"
    "• A būdas (terminale): Vairuotojas privažiuoja prie terminalo, integruotame jutikliniame "
    "ekrane pasirenka norimą diagnostikos paslaugą ir atsiskaito banko kortele per "
    "integruotą POS terminalą.\n"
    "• B būdas (išmaniajame telefone): Vairuotojas telefonu nuskenuoja ant stotelės korpuso "
    "esantį QR kodą. Atsidariusiame mobiliame puslapyje pasirenka paslaugą ir saugiai "
    "atsiskaito per „Stripe\", „Google Pay\" arba „Apple Pay\".\n\n"
    "#### Žingsnis 2: Diagnostikos įrenginio prijungimas\n"
    "• Sėkmingai atlikus apmokėjimą, automatiškai atsidaro terminalo apsauginės durelės.\n"
    "• Klientas visiškai nemokamai pasiima saugų, „Bluetooth\" ryšiu veikiantį profesionalų "
    "OBD2 diagnostikos adapterį „DiaGO\" ir įkiša jį į savo automobilio diagnostikos lizdą.\n\n"
    "#### Žingsnis 3: Automobilio identifikavimas ir duomenų nuskaitymas\n"
    "• Terminalas per „Bluetooth\" ryšį užmezga kontaktą su automobiliu ir bando automatiškai "
    "nuskaityti unikalų transporto priemonės VIN kodą.\n"
    "• Saugiklis: Jei VIN kodo automatiškai nuskaityti nepavyksta (pvz., dėl automobilio "
    "elektronikos specifikos), klientas ekrane arba savo telefone rankiniu būdu įveda "
    "automobilio duomenis (markę, modelį, metus, variklio tipą).\n"
    "• Sistemai identifikavus automobilį, per kelias minutes iš visų elektroninių valdymo "
    "blokų (ECU) nuskaitomi visi esami duomenys ir klaidų kodai.\n\n"
    "#### Žingsnis 4: AI analizė ir ataskaitos pateikimas\n"
    "• Nuskaityti „žali\" klaidų duomenys akimirksniu siunčiami į debesijos serverius.\n"
    "• Dirbtinis intelektas, remdamasis autoriniu „DiaGO\" algoritmu, išanalizuoja gautą "
    "informaciją ir sugeneruoja pilną transporto priemonės būklės ataskaitą.\n"
    "• Išsamią ataskaitą su klaidų išaiškinimais žmogaus kalba, galimomis gedimų priežastimis "
    "bei rekomenduojamų atsarginių dalių kodais klientas akimirksniu gauna tiesiai į savo "
    "išmanųjį telefoną (SMS, el. paštu arba atsidariusiame lange).\n\n"
    "#### Žingsnis 5: Sesijos pabaiga ir įrangos grąžinimas\n"
    "• Klientas, vadovaudamasis nurodymais telefone arba stotelės ekrane, atjungia OBD2 "
    "adapterį nuo automobilio ir grąžina jį atgal į stotelės lizdą.\n"
    "• Terminalo jutikliai užfiksuoja sėkmingą įrenginio grąžinimą, apsauginės durelės "
    "užsidaro, ir sistema persijungia į budėjimo režimą, pasiruošusi kitam užsakymui.\n\n"
    "### 3. KAINA IR FINANSINĖ LOGIKA\n"
    "• Paslaugos kaina: Fiksuotas 25,00 € mokestis už vieną diagnostikos sesiją.\n"
    "• Užstato mechanizmas: Atliekant patikrą, laikinai nuskaitomas arba rezervuojamas "
    "papildomas 25,00 € įrenginio užstatas. Šis užstatas yra akimirksniu grąžinamas klientui "
    "į sąskaitą, kai tik jis saugiai įstato diagnostikos adapterį atgal į terminalo lizdą "
    "sesijos pabaigoje.\n\n"
    "### 4. GEOGRAFIJA IR PLĖTRA\n"
    "• Lokacija: Stotelės plėtojamos „Neste\" automatinių degalinių tinklo teritorijose.\n"
    "• Plėtros planas: Pirmoji stotelė paleidžiama 2026 m. vasarą (liepos–rugpjūčio mėn.) "
    "Kėdainiuose. Iki 2026 metų pabaigos planuojama tinklo plėtra iš viso 6 skirtinguose "
    "Lietuvos miestuose.\n\n"
    "### 5. TECHNINĖ ARCHITEKTŪRA IR PARTNERIAI\n"
    "• Terminalų įranga: Naudojami pramoniniai valdikliai su jutikliniais ekranais, "
    "mikrokompiuteriai ir profesionalūs OBD2 adapteriai.\n"
    "• Debesija ir AI: Serverių infrastruktūrai, duomenų bazių valdymui ir dirbtinio intelekto "
    "analizei (Gemini API) naudojamos „Google Cloud EMEA Limited\" paslaugos.\n"
    "• Suderinamumas su technika: Sistema pilnai pritaikyta lengviesiems automobiliams su "
    "OBD2 jungtimis.\n\n"
    "### 6. VERSLO KLIENTAI (B2B)\n"
    "Paslauga pritaikyta įmonėms (automobilių servisams, nuomos kompanijoms, taksi parkams, "
    "automobilių prekeiviams):\n"
    "• Vienkartinio pasinaudojimo paslauga metu galima gauti PVM sąskaitą — faktūrą (reikia "
    "susisiekti nurodytais kontaktais ir pateikti rekvizitus).\n"
    "• Verslo klientams siūlomas specialus stotelių abonementas pagal sutartinę kainą, "
    "leidžiantis neribotai tikrinti įmonės automobilius visame DiaGO tinklo stotelių tinkle.\n\n"
    "### 7. KONTAKTAI\n"
    "• Įmonė: MB „JT-Diag\"\n"
    "• El. paštas: jt@diago.lt\n"
    "• Telefonas: +370 696 02021\n\n"
    "### 8. KOMUNIKACIJOS TAISYKLĖS\n"
    "• Pavadinimą VISADA rašyk tiksliai taip: DiaGO (su didžiosiomis D ir GO). Ne „Diago\", "
    "ne „DIAGO\", ne „diago\".\n"
    "• Tonas: Inovatyvus, drąsus, padedantis, techniškai tikslus, bet lengvai suprantamas "
    "paprastam vairuotojui.\n"
    "• Atsakai LIETUVIŲ kalba, trumpai (1–4 sakiniai), aiškiai ir mandagiai. Naudoji "
    "standartinę lietuvių kalbą.\n"
    "• NIEKADA neaiškink konkrečių klaidų kodų (pvz. P0420) reikšmių per pokalbį — tam yra "
    "DiaGO stotelės diagnostika. Pasiūlyk klientui atlikti diagnostiką stotelėje.\n"
    "• Jei klausimas nesusijęs su DiaGO ar automobilių diagnostika — mandagiai grąžink į "
    "DiaGO temas, nevykdyk pašalinių užduočių (nei kūrybinių, nei techninių).\n"
    "• Jei nežinai atsakymo arba klausimas sudėtingas — pasiūlyk kreiptis telefonu "
    "+370 696 02021 arba el. paštu jt@diago.lt.\n"
    "• Nesiūlyk konkrečių autoservisų ar dalių kainų.\n"
    "• NEPRIDĖK fakų, kurių NĖRA šiame žinių šaltinyje. Jei nežinai — sąžiningai pasakyk ir "
    "nukreipk į kontaktus."
)


@api_router.post("/support/chat")
async def support_chat(req: SupportChatRequest):
    """DiaGO konsultantas — AI chat for customer support."""
    if not req.messages:
        raise HTTPException(400, "Tuščia žinučių sąrašas")
    key = os.environ.get("EMERGENT_LLM_KEY")
    if not key:
        # Fallback canned response if no LLM key
        return {"reply": (
            "Sveiki! Šiuo metu konsultantas nepasiekiamas. Prašome susisiekti telefonu "
            "+370 696 02021 arba el. paštu jt@diago.lt – mielai padėsime."
        )}
    try:
        sid = req.session_id or f"support-{uuid.uuid4()}"
        chat = LlmChat(
            api_key=key,
            session_id=sid,
            system_message=_SUPPORT_SYSTEM_PROMPT,
        ).with_model("openai", "gpt-4o-mini")
        # Send last user message; LlmChat keeps conversation by session_id server-side
        last_user = None
        for m in reversed(req.messages):
            if m.role == "user":
                last_user = m.content
                break
        if not last_user:
            raise HTTPException(400, "Nėra naudotojo žinutės")
        reply = await chat.send_message(UserMessage(text=last_user))
        return {"reply": str(reply).strip(), "session_id": sid}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Support chat failed")
        return {"reply": (
            f"Atsiprašome, šiuo metu konsultantas nepasiekiamas. Prašome susisiekti telefonu "
            f"+370 696 02021 arba el. paštu jt@diago.lt – mielai padėsime."
        )}


@api_router.post("/sessions", response_model=DiagnosticSession)
async def create_session(body: SessionCreate):
    session = DiagnosticSession(station_id=body.station_id or "STATION-01")
    await db.sessions.insert_one(session.model_dump())
    return session


@api_router.get("/sessions/{session_id}", response_model=DiagnosticSession)
async def get_session(session_id: str):
    doc = await db.sessions.find_one({"id": session_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Session not found")
    return DiagnosticSession(**doc)


@api_router.put("/sessions/{session_id}", response_model=DiagnosticSession)
async def update_session(session_id: str, body: SessionUpdate):
    update: Dict[str, Any] = {"updated_at": now_iso()}
    if body.vehicle is not None:
        update["vehicle"] = body.vehicle.model_dump()
    if body.contact is not None:
        method = (body.contact.method or "").lower()
        value = (body.contact.value or "").strip()
        if method == "email":
            # Basic but robust email regex (RFC-5322-lite)
            if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", value):
                raise HTTPException(400, "Neteisingas el. pašto adresas")
        elif method == "sms":
            # We accept E.164 format (+<country><number>, 8-15 digits after +)
            if not re.match(r"^\+\d{8,15}$", value):
                raise HTTPException(400, "Neteisingas telefono numeris (turi būti E.164 formatu, pvz. +37060000000)")
        update["contact"] = {"method": method or None, "value": value or None}
    if body.outcome is not None:
        # Merge with dot-notation so we don't overwrite fields (e.g.
        # `outcome.findings` set by the AI scan endpoint). Only include
        # fields the client explicitly sent (exclude_unset).
        for k, v in body.outcome.model_dump(exclude_unset=True).items():
            update[f"outcome.{k}"] = v
    result = await db.sessions.find_one_and_update(
        {"id": session_id},
        {"$set": update},
        return_document=True,
    )
    if not result:
        raise HTTPException(404, "Session not found")
    serialize(result)
    return DiagnosticSession(**result)


# ---------- Stripe Checkout ----------
@api_router.post("/checkout/session")
async def create_checkout(body: CheckoutCreateRequest, request: Request):
    session_doc = await db.sessions.find_one({"id": body.session_id}, {"_id": 0})
    if not session_doc:
        raise HTTPException(404, "Diagnostic session not found")

    stripe = get_stripe(request)
    origin = body.origin_url.rstrip("/")
    success_url = f"{origin}/payment-success?session_id={{CHECKOUT_SESSION_ID}}&sid={body.session_id}"
    cancel_url = f"{origin}/offer?sid={body.session_id}"

    amount = float(TOTAL_CHARGE_EUR)  # server-side fixed
    metadata = {
        "diago_session_id": body.session_id,
        "service_price_eur": str(SERVICE_PRICE_EUR),
        "deposit_eur": str(DEPOSIT_EUR),
    }
    checkout_request = CheckoutSessionRequest(
        amount=amount,
        currency="eur",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata=metadata,
    )
    stripe_session: CheckoutSessionResponse = await stripe.create_checkout_session(checkout_request)

    # Save transaction record BEFORE returning
    tx = PaymentTransaction(
        session_id=body.session_id,
        checkout_session_id=stripe_session.session_id,
        amount=amount,
        currency="eur",
        payment_status="initiated",
        status="open",
        metadata=metadata,
    )
    await db.payment_transactions.insert_one(tx.model_dump())

    # Attach checkout session id to diagnostic session
    await db.sessions.update_one(
        {"id": body.session_id},
        {"$set": {"checkout_session_id": stripe_session.session_id, "updated_at": now_iso()}},
    )

    return {"url": stripe_session.url, "session_id": stripe_session.session_id}


@api_router.get("/checkout/status/{checkout_session_id}")
async def checkout_status(checkout_session_id: str, request: Request):
    """
    Returns payment status based on our DB record.

    NOTE: The emergent Stripe test proxy (sk_test_emergent) does not support
    retrieving a session after creation ("No such checkout.session").
    We therefore rely on our internal payment_transactions + webhook updates.
    The frontend must call /api/checkout/confirm/{id} on the success redirect
    (which only happens if the user actually completed Stripe Checkout) to
    mark the session as paid.
    """
    tx = await db.payment_transactions.find_one(
        {"checkout_session_id": checkout_session_id}, {"_id": 0}
    )
    if not tx:
        raise HTTPException(404, "Checkout session not found")

    # Optionally attempt to fetch from Stripe if configured; swallow proxy errors
    try:
        stripe = get_stripe(request)
        remote: CheckoutStatusResponse = await stripe.get_checkout_status(checkout_session_id)
        payment_status = remote.payment_status
        status = remote.status
        amount_total = remote.amount_total
        currency = remote.currency
        metadata = remote.metadata or {}
    except Exception as e:
        logger.info("Stripe status retrieval unavailable, using DB: %s", e)
        payment_status = tx.get("payment_status") or "pending"
        status = tx.get("status") or "open"
        amount_total = int(float(tx.get("amount", 0)) * 100)
        currency = tx.get("currency", "eur")
        metadata = tx.get("metadata") or {}

    # Persist latest and promote session if freshly paid
    if payment_status != tx.get("payment_status"):
        await db.payment_transactions.update_one(
            {"checkout_session_id": checkout_session_id},
            {"$set": {"payment_status": payment_status, "status": status, "updated_at": now_iso()}},
        )
    if payment_status == "paid":
        diago_session_id = (tx.get("metadata") or {}).get("diago_session_id")
        if diago_session_id:
            await db.sessions.update_one(
                {"id": diago_session_id, "payment_status": {"$ne": "paid"}},
                {"$set": {"payment_status": "paid", "status": "paid", "updated_at": now_iso()}},
            )

    return {
        "status": status,
        "payment_status": payment_status,
        "amount_total": amount_total,
        "currency": currency,
        "metadata": metadata,
    }


@api_router.post("/checkout/confirm/{checkout_session_id}")
async def checkout_confirm(checkout_session_id: str):
    """
    Called by the frontend when the user is redirected back to the success_url
    after completing Stripe Checkout. This is a trust-the-redirect confirmation
    because the emergent Stripe proxy does not allow server-side retrieval.
    The real Stripe Checkout hosted page IS real, so a redirect with a valid
    session_id in URL implies the user reached the success page.
    """
    tx = await db.payment_transactions.find_one(
        {"checkout_session_id": checkout_session_id}, {"_id": 0}
    )
    if not tx:
        raise HTTPException(404, "Checkout session not found")
    if tx.get("payment_status") == "paid":
        return {"ok": True, "already_paid": True}

    await db.payment_transactions.update_one(
        {"checkout_session_id": checkout_session_id},
        {"$set": {"payment_status": "paid", "status": "complete", "updated_at": now_iso()}},
    )
    diago_session_id = (tx.get("metadata") or {}).get("diago_session_id")
    if diago_session_id:
        await db.sessions.update_one(
            {"id": diago_session_id, "payment_status": {"$ne": "paid"}},
            {"$set": {"payment_status": "paid", "status": "paid", "updated_at": now_iso()}},
        )
    return {"ok": True, "confirmed": True}


@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    stripe = get_stripe(request)
    body = await request.body()
    signature = request.headers.get("Stripe-Signature", "")
    try:
        webhook_response = await stripe.handle_webhook(body, signature)
    except Exception as e:
        logger.warning("Stripe webhook handling failed: %s", e)
        raise HTTPException(400, "Webhook error")

    if webhook_response.session_id:
        update = {
            "payment_status": webhook_response.payment_status,
            "updated_at": now_iso(),
        }
        await db.payment_transactions.update_one(
            {"checkout_session_id": webhook_response.session_id}, {"$set": update}
        )
        if webhook_response.payment_status == "paid":
            tx = await db.payment_transactions.find_one(
                {"checkout_session_id": webhook_response.session_id}, {"_id": 0}
            )
            if tx:
                diago_session_id = (tx.get("metadata") or {}).get("diago_session_id")
                if diago_session_id:
                    await db.sessions.update_one(
                        {"id": diago_session_id, "payment_status": {"$ne": "paid"}},
                        {"$set": {"payment_status": "paid", "status": "paid", "updated_at": now_iso()}},
                    )
    return {"ok": True}


# ---------- Device return & mock refund ----------
class ReturnDeviceRequest(BaseModel):
    full_refund: Optional[bool] = False  # true if OBD connection failed → refund entire 50€
    reason: Optional[str] = None


@api_router.post("/sessions/{session_id}/return-device")
async def return_device(session_id: str, body: Optional[ReturnDeviceRequest] = None):
    session = await db.sessions.find_one({"id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(404, "Session not found")
    if session.get("payment_status") != "paid":
        raise HTTPException(400, "Session is not paid yet")
    if session.get("status") == "completed":
        return {"message": "Already completed", "session": session}

    full_refund = bool(body and body.full_refund)
    refund_reason = (body.reason if body else None) or ("connection_failed" if full_refund else "diagnostic_completed")

    # Build report URL pointing to our real PDF endpoint
    # The /api prefix is mapped to port 8001 by ingress, so this is externally reachable.
    base = str(os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if not base:
        # Fallback: relative URL to the API (served behind ingress)
        report_url = f"/api/reports/{session_id}.pdf"
    else:
        report_url = f"{base}/api/reports/{session_id}.pdf"
    # No report for failed connections – nothing was diagnosed
    if full_refund:
        report_url = None
    refund_amount = FULL_REFUND_EUR if full_refund else REFUND_EUR

    # Update diagnostic session
    set_doc: Dict[str, Any] = {
        "status": "completed",
        "payment_status": "refunded",
        "report_url": report_url,
        "updated_at": now_iso(),
        "refund_amount_eur": refund_amount,
        "refund_reason": refund_reason,
        "full_refund": full_refund,
        "report_bcc_email": REPORT_BCC_EMAIL if not full_refund else None,
    }
    await db.sessions.update_one({"id": session_id}, {"$set": set_doc})
    # Update payment transaction
    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": {
            "payment_status": "refunded",
            "updated_at": now_iso(),
            "refund_amount_eur": refund_amount,
            "refund_reason": refund_reason,
        }},
    )

    contact = session.get("contact") or {}
    if not full_refund:
        # MOCK: ataskaita siunčiama klientui ir DiaGO archyvui
        logger.info(
            "MOCK: report sent — primary=%s:%s, BCC=%s, link=%s; refund %.2f EUR (%s) for session %s",
            contact.get("method"), contact.get("value"), REPORT_BCC_EMAIL, report_url,
            refund_amount, refund_reason, session_id,
        )
    else:
        logger.info(
            "MOCK: connection_failed — full refund %.2f EUR (no report) to %s:%s for session %s",
            refund_amount, contact.get("method"), contact.get("value"), session_id,
        )

    return {
        "ok": True,
        "report_url": report_url,
        "refund_amount_eur": refund_amount,
        "refund_reason": refund_reason,
        "full_refund": full_refund,
        "contact": contact,
        "report_bcc_email": REPORT_BCC_EMAIL if not full_refund else None,
        "notification_mocked": True,
    }


@api_router.get("/reports/{session_id}.pdf")
async def report_pdf(session_id: str):
    """Render the diagnostic report PDF on demand."""
    doc = await db.sessions.find_one({"id": session_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Session not found")
    try:
        pdf_bytes = build_report_pdf(doc)
    except Exception as e:
        logger.exception("PDF generation failed for %s", session_id)
        raise HTTPException(500, f"PDF generation failed: {e}")
    filename = _build_report_filename(doc)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


def _slug_for_filename(s: str) -> str:
    """Make a string safe + compact for filenames (ASCII, no spaces)."""
    if not s:
        return ""
    s = str(s).strip()
    # Replace Lithuanian diacritics with ASCII
    table = str.maketrans(
        "ąčęėįšųūžĄČĘĖĮŠŲŪŽ",
        "aceeisuuzACEEISUUZ",
    )
    s = s.translate(table)
    # Replace spaces and slashes with dashes; drop unsafe chars
    s = re.sub(r"[\s/\\]+", "-", s)
    s = re.sub(r"[^A-Za-z0-9._-]+", "", s)
    s = re.sub(r"-{2,}", "-", s).strip("-._")
    return s[:40]


def _build_report_filename(session: Dict[str, Any]) -> str:
    """Diago_<YYMMDD>_<model>_<station>_<4-char-code>.pdf"""
    from datetime import datetime as _dt, timezone as _tz
    try:
        from zoneinfo import ZoneInfo as _ZI
        _tz_lt = _ZI("Europe/Vilnius")
    except Exception:
        _tz_lt = None
    created = session.get("created_at") or ""
    try:
        d = _dt.fromisoformat(str(created).replace("Z", "+00:00"))
    except Exception:
        d = _dt.utcnow().replace(tzinfo=_tz.utc)
    if _tz_lt is not None:
        try:
            d = d.astimezone(_tz_lt)
        except Exception:
            pass
    date_str = d.strftime("%y%m%d")  # e.g. 260519

    veh = session.get("vehicle") or {}
    # Model only — no manufacturer/brand
    model = _slug_for_filename(veh.get("model") or "Auto") or "Auto"

    station = _slug_for_filename(session.get("station_id") or "KED-01")
    # 6-char unique code derived from session id (hex, uppercase)
    raw_sid = re.sub(r"[^A-Za-z0-9]", "", str(session.get("id") or ""))
    code6 = (raw_sid[:6] or "000000").upper()

    base = f"Diago_{date_str}_{model}_{station}_{code6}"
    base = re.sub(r"_{2,}", "_", base).strip("_")
    return base + ".pdf"


# ---------- Static assets (illustrations) ----------
_ASSETS_DIR = Path(__file__).parent / "assets"


@api_router.get("/assets/{name}")
async def public_asset(name: str):
    """Serve static illustration images from /app/backend/assets."""
    # Prevent path traversal
    if "/" in name or ".." in name or "\\" in name:
        raise HTTPException(400, "Bad asset name")
    p = _ASSETS_DIR / name
    if not p.exists() or not p.is_file():
        raise HTTPException(404, "Asset not found")
    ext = p.suffix.lower()
    media = {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".zip": "application/zip",
        ".txt": "text/plain; charset=utf-8",
    }.get(ext, "application/octet-stream")
    return Response(
        content=p.read_bytes(),
        media_type=media,
        headers={"Cache-Control": "public, max-age=86400"},
    )


# ---------- Admin ----------
class AdminLoginRequest(BaseModel):
    password: str


@api_router.post("/admin/login")
async def admin_login(body: AdminLoginRequest):
    if (body.password or "") != ADMIN_PASSWORD:
        raise HTTPException(401, "Neteisingas slaptažodis")
    return {"token": _admin_token()}


@api_router.get("/admin/verify")
async def admin_verify(_=Depends(require_admin)):
    return {"ok": True}


@api_router.get("/admin/sessions")
async def admin_sessions(_=Depends(require_admin)):
    docs = await db.sessions.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


@api_router.get("/admin/payments")
async def admin_payments(_=Depends(require_admin)):
    docs = await db.payment_transactions.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


@api_router.get("/admin/stats")
async def admin_stats(_=Depends(require_admin)):
    total_sessions = await db.sessions.count_documents({})
    active = await db.sessions.count_documents({"status": {"$in": ["paid", "active"]}})
    completed = await db.sessions.count_documents({"status": "completed"})
    paid_tx = await db.payment_transactions.count_documents({"payment_status": "paid"})
    refunded_tx = await db.payment_transactions.count_documents({"payment_status": "refunded"})
    return {
        "total_sessions": total_sessions,
        "active_sessions": active,
        "completed_sessions": completed,
        "paid_transactions": paid_tx,
        "refunded_transactions": refunded_tx,
        "station_status": "Aktyvi",
    }


@api_router.post("/admin/refund/{session_id}")
async def admin_manual_refund(session_id: str, _=Depends(require_admin)):
    session = await db.sessions.find_one({"id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(404, "Session not found")
    await db.sessions.update_one(
        {"id": session_id},
        {"$set": {"payment_status": "refunded", "status": "completed", "updated_at": now_iso()}},
    )
    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": {"payment_status": "refunded", "updated_at": now_iso()}},
    )
    return {"ok": True, "refund_amount_eur": REFUND_EUR, "mocked": True}


# ---------- Rating ----------
class RatingRequest(BaseModel):
    rating: int  # 1..5


class ReviewRequest(BaseModel):
    comment: str


@api_router.post("/sessions/{session_id}/rate")
async def rate_session(session_id: str, body: RatingRequest):
    if body.rating < 1 or body.rating > 5:
        raise HTTPException(400, "Rating must be between 1 and 5")
    session = await db.sessions.find_one({"id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(404, "Session not found")
    await db.sessions.update_one(
        {"id": session_id},
        {"$set": {"rating": body.rating, "rated_at": now_iso(), "updated_at": now_iso()}},
    )
    return {"ok": True, "rating": body.rating}


@api_router.post("/sessions/{session_id}/review")
async def review_session(session_id: str, body: ReviewRequest):
    comment = (body.comment or "").strip()
    if not comment:
        raise HTTPException(400, "Comment cannot be empty")
    if len(comment) > 1000:
        raise HTTPException(400, "Comment too long (max 1000 chars)")
    session = await db.sessions.find_one({"id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(404, "Session not found")
    await db.sessions.update_one(
        {"id": session_id},
        {"$set": {"review_comment": comment, "reviewed_at": now_iso(), "updated_at": now_iso()}},
    )
    return {"ok": True}


@api_router.get("/admin/rating-stats")
async def admin_rating_stats(_=Depends(require_admin)):
    pipeline = [
        {"$match": {"rating": {"$exists": True}}},
        {"$group": {"_id": None, "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}},
    ]
    docs = await db.sessions.aggregate(pipeline).to_list(1)
    if not docs:
        return {"avg": 0, "count": 0}
    return {"avg": round(docs[0].get("avg", 0), 2), "count": docs[0].get("count", 0)}


# ---------- AI: OBD port location helper ----------
class ObdLocationRequest(BaseModel):
    brand: str
    model: str
    year: str


@api_router.post("/ai/obd-location")
async def ai_obd_location(body: ObdLocationRequest):
    key = os.environ.get("EMERGENT_LLM_KEY")
    if not key:
        raise HTTPException(500, "LLM key not configured")

    system = (
        "Esi DiaGO automobilių diagnostikos asistentas. Atsakai tik lietuvių kalba. "
        "Pateik trumpą, aiškų atsakymą (maksimaliai 3 sakiniai, be punktuacijos sąrašų). "
        "Nenaudok Markdown formato ar žvaigždučių."
    )
    prompt = (
        f"Kur yra OBD2 diagnostikos jungtis automobilyje {body.brand} {body.model} {body.year}? "
        f"Apibūdink tikslią vietą (pvz., po vairo kolonėle kairėje, virš pedalų, po pelenine, prie saugiklių dėžutės). "
        f"Jei nežinai tikslios vietos šiam konkrečiam modeliui, nurodyk bendrą vietą to gamintojo automobiliuose."
    )
    try:
        chat = LlmChat(api_key=key, session_id=f"obd-{uuid.uuid4()}", system_message=system).with_model(
            "anthropic", "claude-sonnet-4-5-20250929"
        )
        answer = await chat.send_message(UserMessage(text=prompt))
        return {"answer": str(answer).strip()}
    except Exception as e:
        logger.warning("AI OBD location failed: %s", e)
        raise HTTPException(502, f"AI paslauga nepasiekiama: {e}")


# ---------- AI: Scan errors (mock OBD result + lithuanian explanation) ----------
class ScanErrorsRequest(BaseModel):
    session_id: str


# Fixed mock error pool (deterministic by session hash). Each pool has 4-7
# diverse codes covering different vehicle systems: powertrain (P), body (B),
# chassis (C) and network (U), at varying severities.
_MOCK_ERROR_POOLS = [
    # Pool 0 – mixed powertrain + emissions + body
    [
        {"code": "P0420", "severity": "informational", "title": "Katalizatoriaus efektyvumas (1 bankas)", "hint": "Dažnai lieka po variklio priežiūros ar deginimo sistemos darbų.", "clearable": True},
        {"code": "P0171", "severity": "critical", "title": "Liesas mišinys (1 bankas)", "hint": "Galimas oro įsiurbimas arba kuro tiekimo problema.", "clearable": True},
        {"code": "P0300", "severity": "critical", "title": "Atsitiktiniai uždegimo praleidimai", "hint": "Rekomenduojama patikra prieš valymą.", "clearable": True},
        {"code": "P0102", "severity": "warning", "title": "Oro srauto matuoklis (MAF) – mažas signalas", "hint": "Užterštas arba pažeistas MAF jutiklis.", "clearable": True},
        {"code": "B1318", "severity": "informational", "title": "Akumuliatoriaus įtampa maža", "hint": "Gali likti po akumuliatoriaus keitimo ar ilgo stovėjimo.", "clearable": True},
    ],
    # Pool 1 – diesel-leaning
    [
        {"code": "P2002", "severity": "critical", "title": "DPF filtras – mažas efektyvumas", "hint": "Dyzelio kietųjų dalelių filtras užkimštas.", "clearable": False},
        {"code": "P0401", "severity": "warning", "title": "EGR nepakankamas srautas", "hint": "EGR vožtuvas užterštas suodžiais.", "clearable": True},
        {"code": "P0299", "severity": "critical", "title": "Turbinos slėgio nepakankamumas", "hint": "Galimas turbinos arba įsiurbimo nuotėkis.", "clearable": False},
        {"code": "P0087", "severity": "warning", "title": "Žemas kuro slėgis sistemoje", "hint": "Galimas užterštas filtras arba silpnas siurblys.", "clearable": True},
        {"code": "U0073", "severity": "informational", "title": "CAN magistralės klaida (intermitenti)", "hint": "Vienkartinis trumpalaikis ryšio sutrikimas.", "clearable": True},
    ],
    # Pool 2 – body & comfort + light powertrain
    [
        {"code": "B1318", "severity": "warning", "title": "Akumuliatoriaus įtampa nepakankama", "hint": "Reikia patikrinti generatoriaus krovimą.", "clearable": True},
        {"code": "P0456", "severity": "informational", "title": "Garavimo sistemos mažas nuotėkis", "hint": "Dažna informacinė klaida po tankavimo.", "clearable": True},
        {"code": "B1342", "severity": "informational", "title": "EEPROM atminties nuokrypis (komforto blokas)", "hint": "Dažnai lieka po blokų programavimo.", "clearable": True},
        {"code": "C0035", "severity": "warning", "title": "ABS – priekinio kairiojo rato jutiklis", "hint": "Užterštas arba dėvėtas ABS jutiklis.", "clearable": True},
        {"code": "P0014", "severity": "warning", "title": "Paskirstymo veleno padėtis – išmetimo (1 bankas)", "hint": "Užteršta tepalų sistema arba dėvėtas VVT.", "clearable": True},
    ],
    # Pool 3 – critical communication issues
    [
        {"code": "U0100", "severity": "critical", "title": "ECM/PCM komunikacijos praradimas", "hint": "Reikalauja techninės apžiūros — netrinkite be patikros.", "clearable": False},
        {"code": "U0121", "severity": "warning", "title": "Komunikacija su ABS bloku", "hint": "Galimas tinklo magistralės pažeidimas.", "clearable": False},
        {"code": "P0606", "severity": "critical", "title": "Variklio valdymo bloko vidinė klaida", "hint": "ECU vidinis nesklandumas — privaloma diagnostika.", "clearable": False},
        {"code": "B2477", "severity": "informational", "title": "Kelių sistemų derinimo įspėjimas", "hint": "Pasitaiko po blokų programavimo.", "clearable": True},
    ],
    # Pool 4 – sensors & emissions soft
    [
        {"code": "P0401", "severity": "informational", "title": "EGR nepakankamas srautas", "hint": "Po valiklių ar kuro priedų naudojimo kartais lieka informaciniu kodu.", "clearable": True},
        {"code": "P0133", "severity": "warning", "title": "Lambda zondo lėtas atsakas (1 bankas)", "hint": "Dėvisi lambda zondas.", "clearable": True},
        {"code": "P0335", "severity": "critical", "title": "Alkūninio veleno padėties jutiklis", "hint": "Variklis gali sunkiai užsivesti — privaloma patikra.", "clearable": True},
        {"code": "P0480", "severity": "informational", "title": "Aušinimo ventiliatorius – grandinė", "hint": "Trumpalaikis kontaktas, dažnai lieka po remonto.", "clearable": True},
        {"code": "B2604", "severity": "informational", "title": "Klimato sistema – jutiklių derinimas", "hint": "Po programavimo dažnai lieka informaciniu.", "clearable": True},
    ],
    # Pool 5 – mixed warnings, no critical
    [
        {"code": "P0017", "severity": "warning", "title": "Skirstymo veleno fazės skirtumas", "hint": "Galima dėvėjimo ar tepalų problema.", "clearable": True},
        {"code": "P0128", "severity": "informational", "title": "Termostatas – aušinimas po starto", "hint": "Termostatas atveria per anksti.", "clearable": True},
        {"code": "C0561", "severity": "warning", "title": "ABS / ESP konfigūracijos klaida", "hint": "Po padangų ar ratų keitimo.", "clearable": True},
        {"code": "P0411", "severity": "warning", "title": "Antrinis oro injekcijos srautas", "hint": "Užterštas atgalinis vožtuvas.", "clearable": True},
    ],
    # Pool 6 – ignition / coils
    [
        {"code": "P0301", "severity": "critical", "title": "1-o cilindro uždegimo praleidimai", "hint": "Galima žvakių ar ritės problema.", "clearable": True},
        {"code": "P0302", "severity": "warning", "title": "2-o cilindro uždegimo praleidimai", "hint": "Vienkartinė klaida – stebėti.", "clearable": True},
        {"code": "P0420", "severity": "informational", "title": "Katalizatoriaus efektyvumas (1 bankas)", "hint": "Dažnai lieka po remonto.", "clearable": True},
        {"code": "B1004", "severity": "informational", "title": "Tachografo / kilometražo įrašas", "hint": "Po blokų programavimo.", "clearable": True},
        {"code": "U0140", "severity": "warning", "title": "Komunikacijos praradimas su komforto bloku", "hint": "Galimas trumpalaikis kontaktas.", "clearable": True},
    ],
]


@api_router.post("/ai/scan-errors")
async def ai_scan_errors(body: ScanErrorsRequest):
    session_doc = await db.sessions.find_one({"id": body.session_id}, {"_id": 0})
    if not session_doc:
        raise HTTPException(404, "Session not found")

    # Pick a deterministic mock pool based on session id
    h = sum(ord(c) for c in body.session_id)
    pool = _MOCK_ERROR_POOLS[h % len(_MOCK_ERROR_POOLS)]

    # If the session has no VIN yet (manual-entry flow), synthesise a plausible
    # 17-character VIN using a brand-specific WMI prefix so the PDF always
    # shows a concrete VIN. Deterministic by session id so the same sid keeps
    # the same VIN on repeated calls.
    vehicle = session_doc.get("vehicle") or {}
    if not vehicle.get("vin"):
        brand = (vehicle.get("brand") or "").strip().lower()
        wmi_map = {
            "audi": "WAU", "bmw": "WBA", "mercedes-benz": "WDD", "mercedes": "WDD",
            "volkswagen": "WVW", "vw": "WVW", "škoda": "TMB", "skoda": "TMB",
            "seat": "VSS", "cupra": "VSS", "porsche": "WP0", "opel": "W0L",
            "toyota": "JTD", "lexus": "JTH", "honda": "JHM", "mazda": "JMZ",
            "nissan": "JN1", "subaru": "JF1", "suzuki": "JSA", "mitsubishi": "JMB",
            "hyundai": "KMH", "kia": "KNA", "renault": "VF1", "peugeot": "VF3",
            "citroen": "VF7", "citroën": "VF7", "dacia": "UU1", "ford": "WF0",
            "volvo": "YV1", "mini": "WMW", "tesla": "5YJ", "jaguar": "SAJ",
            "land rover": "SAL",
        }
        wmi = wmi_map.get(brand, "XLT")  # generic fallback
        # Build remaining 14 chars deterministically from the session id
        import hashlib as _hl
        digest = _hl.sha1(body.session_id.encode()).hexdigest().upper()
        # Keep only VIN-safe chars (no I, O, Q)
        safe = "".join(c for c in digest if c not in "IOQ")
        vin = (wmi + safe)[:17].ljust(17, "0")
        vehicle = {**vehicle, "vin": vin, "detection_method": vehicle.get("detection_method") or "Simuliuota"}
        await db.sessions.update_one({"id": body.session_id}, {"$set": {"vehicle": vehicle, "updated_at": now_iso()}})
        session_doc["vehicle"] = vehicle

    # Use AI to generate lithuanian, human-friendly descriptions
    key = os.environ.get("EMERGENT_LLM_KEY")
    findings: List[Dict[str, Any]] = []
    enrich: Dict[str, Dict[str, Any]] = {}
    # NOTE: We previously called Claude here to enrich descriptions, but that
    # took up to ~20s and triggered the 12s frontend timeout (which made the
    # UI show "0 errors"). The richer per-code analysis now comes from the
    # Gemini background task below; here we return immediately using
    # severity-based fallbacks so the user always sees the error summary.
    vehicle = session_doc.get("vehicle") or {}
    car_line = " ".join(filter(None, [vehicle.get("brand"), vehicle.get("model"), vehicle.get("year")])) or "automobilyje"

    # Severity-based fallbacks
    def _fallback(sev: str) -> Dict[str, Any]:
        if sev == "critical":
            return {
                "action": "Kreipkitės į patikimą servisą",
                "impact": "Problema gali paveikti variklį ir kitas sistemas",
                "precaution": "Venkite ilgų kelionių, stebėkite automobilio elgseną",
                "cost_min": 100,
                "cost_max": 400,
            }
        if sev == "warning":
            return {
                "action": "Rekomenduojama patikra artimiausiu metu",
                "impact": "Galimas didesnis kuro sąnaudų ir emisijos padidėjimas",
                "precaution": "Stebėkite variklio darbą ir triukšmą",
                "cost_min": 60,
                "cost_max": 220,
            }
        return {
            "action": "Galite stebėti klaidą ir ją ištrinti",
            "impact": "Informacinė klaida, kritinės įtakos nėra",
            "precaution": "Jei grįš kelis kartus — patikrinkite servise",
            "cost_min": 20,
            "cost_max": 120,
        }

    for e in pool:
        code = e["code"]
        ex = enrich.get(code, {})
        fb = _fallback(e["severity"])
        findings.append({
            "code": code,
            "severity": e["severity"],
            "title": e["title"],
            "description": ex.get("description") or e["hint"],
            "advice": ex.get("action") or fb["action"],  # kept for backward compatibility
            "action": ex.get("action") or fb["action"],
            "impact": ex.get("impact") or fb["impact"],
            "precaution": ex.get("precaution") or fb["precaution"],
            "cost_min": ex.get("cost_min") if ex.get("cost_min") is not None else fb["cost_min"],
            "cost_max": ex.get("cost_max") if ex.get("cost_max") is not None else fb["cost_max"],
            "clearable": e["clearable"],
        })

    # Persist findings into session outcome
    await db.sessions.update_one(
        {"id": body.session_id},
        {"$set": {"outcome.findings": findings, "updated_at": now_iso()}},
    )

    # ---- Expert analysis (Gemini 2.5 Pro) runs in BACKGROUND ----
    # We return findings immediately (within ~1s); the heavier 30-50s Gemini
    # analysis enriches the session afterwards so the PDF (generated later,
    # when the user opens the report link) has the full analysis.
    if key and findings:
        asyncio.create_task(
            _run_expert_analysis_background(body.session_id, car_line, findings, key)
        )

    return {"findings": findings}


async def _run_expert_analysis_background(
    session_id: str, car_line: str, findings: List[Dict[str, Any]], key: str,
) -> None:
    """Long-running Gemini 2.5 Pro expert analysis. Updates the session in DB."""
    expert: Dict[str, Any] = {}
    try:
        sys_msg = (
            "Tu esi labai patyręs automobilių diagnostikos specialistas, dirbantis Lietuvoje, "
            "specializuojasi pagal SAE J2012 standartą ir gamintojų techninius dokumentus. "
            "Atsakai TIK lietuvių kalba, dalykiškai, naudoji standartinę lietuvių kalbą.\n\n"
            "GRIEŽTOS TAISYKLĖS:\n"
            "1) Klaidos kodų aiškinimai TURI remtis tik OFICIALIAIS šaltiniais:\n"
            "   • SAE J2012 (standartiniai P0/B0/C0/U0 kodai)\n"
            "   • Konkretaus gamintojo techniniai biuleteniai (TSB) ir servisinės instrukcijos (P1, B1, C1, U1)\n"
            "   • Oficialūs OBD-II atskirų gamintojų DTC žinynai\n"
            "2) JEI tas pats kodas turi skirtingas reikšmes pagal gamintoją, modelį arba variklio kodą – "
            "PATEIK VISAS VARIACIJAS atskirai (laukelyje 'variants'). Niekada NESKURK ir NEINTERPRETUOK "
            "kodų savo nuožiūra.\n"
            "3) JEI kodas yra gamintojui specifinis ir tikslaus aiškinimo nežinote – atvirai pažymėk: "
            "'Reikalinga gamintojo techninė informacija. Rekomenduojama kreiptis į servisą.'\n"
            "4) Niekada neminėk konkrečios remonto kainos atskirame klaidos kode – kainos rodomos tik "
            "išvadose ('groups' sekcijoje).\n"
            "5) Vartoji standartinius terminus, paaiškink juos lietuviškai jei jie nestandartiniai:\n"
            "   • „Bank 1\" = „1-oji cilindrų eilė\"; „Bank 2\" = „2-oji cilindrų eilė\".\n"
            "   • „Upstream / Sensor 1\" = „prieš katalizatorių\"; „Downstream / Sensor 2\" = „už katalizatoriaus\"\n"
        )
        codes_block = "\n".join(
            f"- {f['code']} ({f['severity']}): {f['title']}"
            for f in findings
        )
        user_prompt = (
            f"Automobilis: {car_line}. Aptiktos OBD2 klaidos:\n{codes_block}\n\n"
            "Sugeneruok analizę TIKSLIAI šiuo JSON formatu (be jokio papildomo teksto, be ``` žymėjimo):\n"
            "{\n"
            '  "codes": [\n'
            '    {"code": "P0171", "official_title": "...", "variants": ['
            '{"source": "SAE J2012 (standartinis)", "meaning": "...", "applies_to": "Visi"}'
            '], "impact": "max 14 žodžių", "precaution": "max 14 žodžių"}\n'
            "  ],\n"
            '  "groups": [\n'
            '    {"title": "...", "codes": ["..."], "suspected_parts": ["..."], '
            '"location": "...", "explanation": "...", "cost_min_eur": 80, '
            '"cost_max_eur": 350, "priority": "high"}\n'
            "  ],\n"
            '  "overall_recommendation": "1-2 sakiniai bendros rekomendacijos klientui."\n'
            "}\n\n"
            "Sąlygos:\n"
            "• priority: high | medium | low.\n"
            "• Susijusius kodus grupuok (kiekvienas kodas tiksliai vienoje grupėje).\n"
            "• Kainos – realios Lietuvos rinkos (EUR); tik grupėse, NE kodų skyriuje.\n"
            "• 'codes' sąraše KIEKVIENAS rastas kodas turi turėti įrašą.\n"
            "• 'variants' – jei kodas turi kelis oficialius variantus – pateik VISUS.\n"
            "• Jei interpretacijos NEŽINAI – sąžiningai parašyk 'meaning': 'Reikalinga gamintojo techninė informacija…'\n"
            "• 'impact' ir 'precaution' – po vieną sakinį, max 14 žodžių, konkretūs, be techninių santrumpų.\n"
        )
        gemini_chat = LlmChat(
            api_key=key,
            session_id=f"expert-{uuid.uuid4()}",
            system_message=sys_msg,
        ).with_model("gemini", "gemini-2.5-pro")
        raw = await gemini_chat.send_message(UserMessage(text=user_prompt))
        import json as _json2, re as _re2
        txt = str(raw)
        m2 = _re2.search(r"\{.*\}", txt, _re2.DOTALL)
        if m2:
            try:
                expert = _json2.loads(m2.group(0))
            except Exception:
                try:
                    from json_repair import repair_json  # type: ignore
                    expert = _json2.loads(repair_json(m2.group(0)))
                except Exception:
                    expert = {}
    except Exception as ex:
        logger.warning("Gemini expert analysis failed: %s", ex)
        return

    # Merge Gemini per-code data into findings (description, impact, precaution)
    if expert and isinstance(expert.get("codes"), list):
        by_code = {str(c.get("code", "")).strip().upper(): c for c in expert["codes"] if c.get("code")}
        for f in findings:
            code = str(f.get("code", "")).strip().upper()
            ai_code = by_code.get(code)
            if not ai_code:
                continue
            variants = ai_code.get("variants") or []
            if variants:
                if len(variants) == 1:
                    f["description"] = variants[0].get("meaning") or f.get("description") or ""
                else:
                    parts = []
                    for v in variants:
                        src = v.get("source") or "Šaltinis nenurodytas"
                        meaning = v.get("meaning") or ""
                        applies = v.get("applies_to") or ""
                        line = f"• [{src}] {meaning}"
                        if applies:
                            line += f" (Taikoma: {applies})"
                        parts.append(line)
                    f["description"] = "Galimos kelios oficialios interpretacijos:\n" + "\n".join(parts)
            if ai_code.get("impact"):
                f["impact"] = ai_code["impact"]
            if ai_code.get("precaution"):
                f["precaution"] = ai_code["precaution"]
            if ai_code.get("official_title"):
                f["title"] = ai_code["official_title"]
            f["cost_min"] = None
            f["cost_max"] = None
        await db.sessions.update_one(
            {"id": session_id},
            {"$set": {"outcome.findings": findings, "updated_at": now_iso()}},
        )

    if expert:
        await db.sessions.update_one(
            {"id": session_id},
            {"$set": {"outcome.expert_analysis": expert, "updated_at": now_iso()}},
        )


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
