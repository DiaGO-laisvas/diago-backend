"""DiaGO Microcar diagnostikos demo.

Paleidimas:
    cd /app
    python3 -m diago_backend.microcar.microcar_demo

Arba (jei norite paleisti tiesiogiai iš aplanko):
    cd /app/diago_backend/microcar
    PYTHONPATH=/app python3 microcar_demo.py
"""
from __future__ import annotations

import json
import sys

try:
    # paleidžiama kaip paketo modulis (`python -m diago_backend.microcar.microcar_demo`)
    from .microcar_diag import search_microcar_issues
except ImportError:
    # paleidžiama tiesiai
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
    from diago_backend.microcar.microcar_diag import search_microcar_issues


# ---------------------------------------------------------------------------
# Demo užklausos – realios mikroautomobilių problemos LT/EN/mišriai
# ---------------------------------------------------------------------------

TEST_QUERIES: list[dict] = [
    {
        "name": "Aixam Kubota – CVT slydimas (LT, su rašybos klaida)",
        "car": {"make": "Aixam", "model": "City S8", "year": 2017, "engine_type": "Kubota"},
        "text": "buksuoja dirzas, vaziuoja letai ikalneje, sukiai auga o greitis ne",
    },
    {
        "name": "Ligier Lombardini – ECU trikdys (LT)",
        "car": {"make": "Ligier", "model": "JS50", "year": 2015, "engine_type": "Lombardini"},
        "text": "kartais užsiveda, kartais ne. užgęsta važiuojant, užsidega Check Engine",
    },
    {
        "name": "Chatenet – generatorius (mišri LT/EN)",
        "car": {"make": "Chatenet", "model": "CH26", "year": 2014, "engine_type": "Yanmar"},
        "text": "battery drains overnight, blanksta zibintai vaziuojant, akumuliatoriaus lempute uzsidega",
    },
    {
        "name": "Microcar – Kubota šaltas start (LT, įprasta klientų kalba)",
        "car": {"make": "Microcar", "model": "M.GO", "year": 2016, "engine_type": "Kubota"},
        "text": "nesikuria saltas, ilgai sukasi starteris, vakar dar uzsivede normaliai",
    },
    {
        "name": "Aixam – pakaba barška (LT, paprastas vartotojas)",
        "car": {"make": "Aixam", "model": "Crossover", "year": 2019, "engine_type": "Kubota"},
        "text": "barska priekyje vaziuojant per duobutes, kazkas kalena",
    },
    {
        "name": "Aixam e-Coupe – elektrinis (LT)",
        "car": {"make": "Aixam", "model": "e-Coupe", "year": 2021, "engine_type": "Electric"},
        "text": "nesikrauna iki galo, rodo mazesni nuotoli, krovimo klaida ekrane",
    },
    {
        "name": "Prancūziška užklausa be aiškios markės",
        "car": {"make": "", "model": "", "year": 2018, "engine_type": "Lombardini"},
        "text": "calage moteur en roulant, voyant moteur clignote, démarre par intermittence",
    },
    {
        "name": "Vokiška užklausa (DE) – overheat",
        "car": {"make": "Ligier", "model": "X-Too", "year": 2020, "engine_type": "Yanmar"},
        "text": "yanmar überhitzt am berg, kühlerlüfter dreht nicht, temperatur rot",
    },
]


def main() -> None:
    print("=" * 72)
    print("DiaGO Microcar diagnostikos demo (TF-IDF + profilio scoring)")
    print("=" * 72)

    for i, q in enumerate(TEST_QUERIES, 1):
        print(f"\n[{i}] {q['name']}")
        print(f"    Profilis: {q['car']}")
        print(f"    Klientas: \"{q['text']}\"")

        results = search_microcar_issues(q["car"], q["text"], top_k=3)
        if not results:
            print("    ❌ Nieko nerasta (mažas pasitikėjimas).")
            continue

        for j, r in enumerate(results, 1):
            badge = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(r["confidence"], "⚪")
            print(
                f"    {j}. {badge} [{r['confidence']:6}] score={r['score']:.3f} "
                f"(text={r['text_similarity']:.2f}, profile={r['profile_match']:.2f}) "
                f"| {r['id']} — {r['title']}"
            )
            print(f"       → {r['explanation']}")
            if r["keyword_hits"]:
                print(f"       raktažodžiai: {r['keyword_hits']}")

    print("\n" + "=" * 72)
    print("JSON pavyzdys (pirmas rezultatas iš pirmos užklausos):")
    print("=" * 72)
    sample = search_microcar_issues(TEST_QUERIES[0]["car"], TEST_QUERIES[0]["text"], top_k=1)
    print(json.dumps(sample, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
