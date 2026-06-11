"""
DiaGO Microcar diagnostikos modulis
====================================

Tikslas: leisti vartotojui įvesti laisva natūralia kalba savo simptomus
(LT/EN/FR/DE) ir pagal mašinos profilį (markė, modelis, metai, variklis) gauti
surūšiuotą tikėtinų problemų sąrašą su pasitikėjimo balais (confidence score).

Architektūra
------------
1) **CarProfile**         – kliento mašinos duomenys (in).
2) **DiagnosticIssue**    – vienas KB įrašas (out + KB).
3) **SearchResult**       – paieškos rezultatas su balais (out).
4) **MicrocarKB**         – žinių bazės wrapper'is (load + search).
5) **search_microcar_issues** – aukšto lygio API funkcija
   (priima dict + tekstą, grąžina dict sąrašą).

Scoring formulė
---------------
final_score = 0.55 * text_similarity   # TF-IDF kosinusinis panašumas
            + 0.30 * profile_match     # exact make/engine match
            + 0.10 * keyword_boost     # tiesioginio raktažodžio buvimas
            + 0.05 * recency_prior     # naujesnis kodas šiek tiek aukščiau

Atskirai apskaičiuotas `confidence`:
    - 0.0..0.4  → low      (mažai duomenų sutapimo)
    - 0.4..0.7  → medium   (panašu, bet reikia patikslinti)
    - 0.7..1.0  → high     (didelis sutapimas)

Priklausomybės
--------------
- Python 3.10+
- scikit-learn (jau yra DiaGO requirements.txt)
- Be SQL — visa KB iš JSON failo (lengva editavimui per admin UI vėliau).
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# sklearn TF-IDF + cosine: stabilus ir greitas, jokio AI nereikia
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# ----------------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------------

@dataclass
class CarProfile:
    """Kliento mašinos profilis."""
    make: str = ""                 # "Aixam", "Ligier", "Chatenet", "Microcar"
    model: str = ""                # "City S8", "JS50", "M.GO"
    year: int | None = None        # 2018
    engine_type: str = ""          # "Kubota" | "Lombardini" | "Yanmar" | "DCi" | "Electric"

    def normalised(self) -> "CarProfile":
        return CarProfile(
            make=_norm(self.make),
            model=_norm(self.model),
            year=self.year,
            engine_type=_norm(self.engine_type),
        )


@dataclass
class DiagnosticIssue:
    """Vienas žinių bazės įrašas."""
    id: str
    category: str
    title: str
    applies_to: dict[str, Any]
    symptoms_lt: list[str] = field(default_factory=list)
    symptoms_en: list[str] = field(default_factory=list)
    symptoms_fr: list[str] = field(default_factory=list)
    symptoms_de: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    possible_cause_lt: str = ""
    solution_lt: str = ""
    severity: str = "info"          # "info" | "warning" | "critical"
    labor_hours: float = 0.0

    @property
    def search_corpus(self) -> str:
        """Visas tekstas, kuris bus indeksuojamas TF-IDF'u."""
        parts: list[str] = [
            self.title,
            self.category,
            *self.symptoms_lt,
            *self.symptoms_en,
            *self.symptoms_fr,
            *self.symptoms_de,
            *self.keywords,
            self.possible_cause_lt,
        ]
        return _norm(" ".join(parts))


@dataclass
class SearchResult:
    """Paieškos rezultato struktūra."""
    issue: DiagnosticIssue
    score: float                   # 0..1, agreguotas
    text_similarity: float          # 0..1, TF-IDF cosine
    profile_match: float            # 0..1, mašinos profilio atitikimas
    keyword_hits: list[str]         # rasti raktažodžiai
    confidence: str                 # "low" | "medium" | "high"
    explanation: str                # žmogui suprantamas paaiškinimas

    def to_dict(self) -> dict:
        d = {
            "id": self.issue.id,
            "title": self.issue.title,
            "category": self.issue.category,
            "severity": self.issue.severity,
            "score": round(self.score, 4),
            "confidence": self.confidence,
            "text_similarity": round(self.text_similarity, 4),
            "profile_match": round(self.profile_match, 4),
            "keyword_hits": self.keyword_hits,
            "explanation": self.explanation,
            "possible_cause": self.issue.possible_cause_lt,
            "solution": self.issue.solution_lt,
            "labor_hours": self.issue.labor_hours,
        }
        return d


# ----------------------------------------------------------------------------
# Text normalisation helpers (LT, EN, FR, DE)
# ----------------------------------------------------------------------------

# Lietuviški specialūs simboliai → ASCII (kad „dirzas" sutaptų su „dirŽas")
_LT_MAP = str.maketrans({
    "ą": "a", "č": "c", "ę": "e", "ė": "e", "į": "i",
    "š": "s", "ų": "u", "ū": "u", "ž": "z",
    "Ą": "a", "Č": "c", "Ę": "e", "Ė": "e", "Į": "i",
    "Š": "s", "Ų": "u", "Ū": "u", "Ž": "z",
})


def _norm(text: str) -> str:
    """Normalizuoja tekstą:
       1) lower-case
       2) LT/FR/DE diakritikai → ASCII
       3) NFD Unicode dekompozicija (visiems likusiems)
       4) ne-žodžio simboliai → tarpas
       5) kelis tarpus → vieną
    """
    if not text:
        return ""
    s = text.lower().translate(_LT_MAP)
    # NFKD dekompozicija ir ASCII (pagriebia ž→z, ñ→n, ü→u, ç→c ir t.t.)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


# Lengva LT „stemming"-like normalizacija (paima 5–6 simb. šaknį)
# Tai padeda sutapdinti "barska"/"barškėjimas"/"barskejo" → "barsk"
_LT_SUFFIX_RE = re.compile(
    r"(uoja|uojo|uojam|uojate|uoti|ojant|ojama|imas|ymas|tojas|"
    r"ejimas|ejimo|ejimas|ai|ą|us|os|ės|is|ai|ę|us|u)$"
)


def _stem_lt(token: str) -> str:
    """Labai paprastas LT „stemmer'is" – nuima dažniausias galūnes.
    Pakanka prototipui; tikram production'ui ateityje galima naudoti
    `lt-stem` arba `pymorphy3`.
    """
    if len(token) <= 4:
        return token
    return _LT_SUFFIX_RE.sub("", token)


def _tokenize(text: str) -> list[str]:
    """Tokenize + LT stemming (taikome ir kitoms kalboms – nepakenkia)."""
    return [_stem_lt(t) for t in _norm(text).split() if t]


# ----------------------------------------------------------------------------
# Knowledge base
# ----------------------------------------------------------------------------

class MicrocarKB:
    """Žinių bazė + TF-IDF indeksas.

    Iškart paskaičiuoja TF-IDF matricą inicializacijos metu, todėl
    paieška yra greita (~ms vienai užklausai net su 1000 įrašų).
    """

    def __init__(self, issues: list[DiagnosticIssue]):
        self.issues: list[DiagnosticIssue] = issues
        # char_wb n-gramai padeda sutapdinti mišrias kalbas ir rašybos klaidas
        self._vec = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=1,
            sublinear_tf=True,
            lowercase=False,           # mes jau normalizavom
        )
        corpus = [issue.search_corpus for issue in issues]
        self._matrix = self._vec.fit_transform(corpus) if corpus else None

    # ---------- Loading ----------
    @classmethod
    def from_json(cls, path: str | Path) -> "MicrocarKB":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        issues = [DiagnosticIssue(**row) for row in data]
        return cls(issues)

    @classmethod
    def default(cls) -> "MicrocarKB":
        """Įkrauna seed JSON'us iš paketo aplanko – tiek pradinius 7 detaliuosius,
        tiek išplėstinius TOP 50 įrašus (kompaktiškas formatas, jei egzistuoja).
        """
        base = Path(__file__).parent
        issues: list[DiagnosticIssue] = []

        seed = base / "microcar_seed.json"
        if seed.exists():
            for row in json.loads(seed.read_text(encoding="utf-8")):
                issues.append(DiagnosticIssue(**row))

        top50 = base / "microcar_top50.json"
        if top50.exists():
            for row in json.loads(top50.read_text(encoding="utf-8")):
                issues.append(cls._convert_top50_row(row))

        return cls(issues)

    @staticmethod
    def _convert_top50_row(row: dict) -> DiagnosticIssue:
        """Konvertuoja TOP-50 kompaktišką formatą į standartinį `DiagnosticIssue`.
        TOP-50 formatas:
            {"id":"MC-001","category":"...","make":"Aixam,Ligier",
             "engine":"Kubota,Lombardini","symptom":"...","cause":"...",
             "price_eur_min":80,"price_eur_max":160,"labor_h":1.5,"severity":"warning"}
        """
        makes = [m.strip() for m in (row.get("make") or "").split(",") if m.strip()]
        engines = [e.strip() for e in (row.get("engine") or "").split(",") if e.strip()]
        symptom = (row.get("symptom") or "").strip()
        cause = (row.get("cause") or "").strip()
        pmin = int(row.get("price_eur_min", 0) or 0)
        pmax = int(row.get("price_eur_max", 0) or 0)
        labor = float(row.get("labor_h", 0) or 0)

        # Skaldymas į atskirus simptomus pagal ; arba ,
        sym_list = [s.strip() for s in re.split(r"[;,]", symptom) if s.strip()]

        # Sprendimo žingsniai – iš priežasties pavaršliojami trumpame žingsnyje
        solution = (
            f"1) Patikrinkite simptomus pagal aprašymą: {symptom}.\n"
            f"2) Tikėtina priežastis: {cause}.\n"
            f"3) Orientacinė remonto kaina Lietuvoje: **{pmin}–{pmax} €** "
            f"(darbo laikas ~{labor:.1f} val.).\n"
            f"4) Rekomenduojama atlikti diagnostiką ir patvirtinti gedimą prieš keičiant detales."
        )

        title_short = (cause[:80] + "…") if len(cause) > 80 else cause

        return DiagnosticIssue(
            id=row.get("id", ""),
            category=row.get("category", ""),
            title=title_short or symptom[:80],
            applies_to={
                "makes": makes,
                "engines": engines,
                "year_from": 2000,
                "year_to": 2026,
            },
            symptoms_lt=sym_list,
            symptoms_en=[],
            symptoms_fr=[],
            symptoms_de=[],
            keywords=[],
            possible_cause_lt=cause,
            solution_lt=solution,
            severity=row.get("severity", "info"),
            labor_hours=labor,
        )

    # ---------- Search core ----------
    def search(
        self,
        car: CarProfile,
        user_text: str,
        top_k: int = 5,
        min_score: float = 0.05,
    ) -> list[SearchResult]:
        """Pagrindinis paieškos metodas.

        Žingsniai:
            1) Normalizuoja vartotojo tekstą.
            2) Konvertuoja į TF-IDF vektorių.
            3) Apskaičiuoja kosinusinį panašumą su visais KB įrašais.
            4) Pagal mašinos profilį padidina (boost) sutampančius įrašus.
            5) Aptinka tikslius raktažodžių sutapimus → papildomas boost.
            6) Rūšiuoja, grąžina top_k.
        """
        if not self.issues or self._matrix is None:
            return []

        user_norm = _norm(user_text)
        if not user_norm:
            return []

        # TF-IDF kosinusinis panašumas
        u_vec = self._vec.transform([user_norm])
        sims: list[float] = cosine_similarity(u_vec, self._matrix)[0].tolist()

        car_n = car.normalised()
        user_tokens = set(_tokenize(user_text))

        results: list[SearchResult] = []
        for i, issue in enumerate(self.issues):
            text_sim = float(sims[i])
            prof_match = _profile_match_score(car_n, issue)

            # Tiesioginiai raktažodžių sutapimai (svarbu LT žargonui)
            kw_hits = [
                kw for kw in (issue.keywords or [])
                if _stem_lt(_norm(kw)) in user_tokens
                or _norm(kw) in user_norm
            ]
            kw_boost = min(0.25, 0.07 * len(kw_hits))  # max 0.25 per query

            # Recency – naujesni metų diapazonai šiek tiek aukščiau
            year_to = (issue.applies_to or {}).get("year_to", 2026)
            recency = min(1.0, max(0.0, (year_to - 2010) / 16.0)) * 0.05

            final = (
                0.55 * text_sim
                + 0.30 * prof_match
                + kw_boost
                + recency
            )

            # filtruojam triukšmą
            if final < min_score:
                continue

            results.append(SearchResult(
                issue=issue,
                score=round(final, 4),
                text_similarity=text_sim,
                profile_match=prof_match,
                keyword_hits=kw_hits,
                confidence=_confidence_band(final),
                explanation=_build_explanation(text_sim, prof_match, kw_hits, car_n, issue),
            ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]


# ----------------------------------------------------------------------------
# Helper functions for scoring
# ----------------------------------------------------------------------------

def _profile_match_score(car: CarProfile, issue: DiagnosticIssue) -> float:
    """Apskaičiuoja, kiek mašinos profilis atitinka KB įrašą.
       0.0  → visiškai netaikytina (kita markė ir kitas variklis).
       0.5  → atitinka tik markę arba tik variklį.
       1.0  → atitinka ir markę, ir variklį (ir metai patenka į intervalą).
    """
    applies = issue.applies_to or {}
    makes = {_norm(m) for m in applies.get("makes", [])}
    engines = {_norm(e) for e in applies.get("engines", [])}
    yf = int(applies.get("year_from", 1990))
    yt = int(applies.get("year_to", 2030))

    has_make = car.make and car.make in makes
    has_engine = car.engine_type and car.engine_type in engines
    year_ok = (car.year is None) or (yf <= int(car.year) <= yt)

    if not has_make and not has_engine:
        return 0.0
    if not year_ok:
        # KB konkrečiai sako, kad metų diapazonas netinka – stipri redukcija
        return 0.15
    if has_make and has_engine:
        return 1.0
    return 0.55  # tik vienas atitinka


def _confidence_band(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def _build_explanation(
    text_sim: float,
    prof_match: float,
    kw_hits: list[str],
    car: CarProfile,
    issue: DiagnosticIssue,
) -> str:
    """Trumpas paaiškinimas vartotojui, kodėl būtent šis įrašas grąžintas."""
    parts: list[str] = []
    if prof_match >= 0.9:
        parts.append(f"profilis atitinka tiksliai ({car.make.title()} + {car.engine_type.title()})")
    elif prof_match >= 0.4:
        parts.append("profilis atitinka iš dalies")
    else:
        parts.append("profilis nesutampa, bet simptomai panašūs")

    if kw_hits:
        parts.append(f"rasti raktažodžiai: {', '.join(kw_hits[:4])}")
    if text_sim >= 0.35:
        parts.append("aprašymas labai panašus į žinomus simptomus")
    elif text_sim >= 0.15:
        parts.append("aprašymas iš dalies sutampa")

    return "; ".join(parts).capitalize() + "."


# ----------------------------------------------------------------------------
# High-level API
# ----------------------------------------------------------------------------

# Singleton'as – KB pakraunama vieną kartą per procesą (greičiau).
_KB_SINGLETON: MicrocarKB | None = None


def _get_kb() -> MicrocarKB:
    global _KB_SINGLETON
    if _KB_SINGLETON is None:
        _KB_SINGLETON = MicrocarKB.default()
    return _KB_SINGLETON


def search_microcar_issues(
    client_car_info: dict | CarProfile,
    user_description_text: str,
    top_k: int = 5,
) -> list[dict]:
    """**Pagrindinis viešasis API**.

    Args:
        client_car_info: dict su raktais ``make``, ``model``, ``year``,
                         ``engine_type`` ARBA :class:`CarProfile` objektas.
        user_description_text: laisva tekstinė vartotojo simptomų aprašymas
                               (LT/EN/FR/DE arba mišriai).
        top_k: kiek top rezultatų grąžinti (default 5).

    Returns:
        Surūšiuotas problemų sąrašas, kiekvienas elementas yra dict:

        ```python
        {
            "id": "MC-001",
            "title": "CVT diržo dėvėjimasis / slydimas",
            "category": "Transmission/CVT",
            "severity": "warning",
            "score": 0.78,
            "confidence": "high",
            "text_similarity": 0.41,
            "profile_match": 1.0,
            "keyword_hits": ["dirzas", "buksuoja"],
            "explanation": "Profilis atitinka tiksliai ...",
            "possible_cause": "...",
            "solution": "...",
            "labor_hours": 1.5,
        }
        ```
    """
    if isinstance(client_car_info, dict):
        car = CarProfile(
            make=client_car_info.get("make", ""),
            model=client_car_info.get("model", ""),
            year=client_car_info.get("year"),
            engine_type=client_car_info.get("engine_type", ""),
        )
    else:
        car = client_car_info

    kb = _get_kb()
    results = kb.search(car, user_description_text, top_k=top_k)
    return [r.to_dict() for r in results]
