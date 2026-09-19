"""pwcheck - password strength evaluation for backend services and CLIs.

Typical use inside an API handler::

    from pwcheck import evaluate

    result = evaluate(form["password"], user_inputs=[form["email"], "acme-corp"])
    if not result.is_acceptable:
        return 400, {"errors": result.warnings, "hints": result.suggestions}

The module never logs, stores or transmits the password it is given.
"""

from .core import (
    IDEAL_LENGTH,
    MIN_LENGTH,
    SCORE_LABELS,
    Penalty,
    Requirement,
    Result,
    evaluate,
)

__all__ = [
    "evaluate",
    "Result",
    "Requirement",
    "Penalty",
    "SCORE_LABELS",
    "MIN_LENGTH",
    "IDEAL_LENGTH",
]

__version__ = "1.0.0"
