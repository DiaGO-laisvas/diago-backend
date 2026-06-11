"""DiaGO Microcar diagnostikos modulis (L6e/L7e: Aixam, Ligier, Chatenet, Microcar).

Modulinė struktūra:
    microcar_diag.py    – pagrindinė logika (KB + paieška + scoring)
    microcar_seed.json  – seed duomenys (žinių bazės pradinis užpildymas)
    microcar_demo.py    – paleidžiamas pavyzdys

Naudojimas iš FastAPI:
    from diago_backend.microcar.microcar_diag import search_microcar_issues
    results = search_microcar_issues(car_info, user_text)
"""
from .microcar_diag import (
    search_microcar_issues,
    MicrocarKB,
    CarProfile,
    DiagnosticIssue,
    SearchResult,
)

__all__ = [
    "search_microcar_issues",
    "MicrocarKB",
    "CarProfile",
    "DiagnosticIssue",
    "SearchResult",
]
