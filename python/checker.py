#!/usr/bin/env python3
"""Password strength checker - command line interface.

Examples
--------
Interactive (input is hidden, never echoed, never stored)::

    ./checker.py

Pipe from another process, e.g. a generator or a vault::

    pwgen -s 20 1 | ./checker.py --stdin --json

Gate a script on a policy (exit code 1 when the password is too weak)::

    ./checker.py --stdin --min-score 3 --quiet < candidate.txt

Security note
-------------
Passing a password as a command-line argument is supported for convenience but
is *not* safe on a shared machine: argv is visible to every local process and is
usually written to the shell history. The CLI warns when you do it. Prefer the
interactive prompt or ``--stdin``.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import List, Optional

# Allow running the script directly from a checkout without installing.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwcheck import SCORE_LABELS, evaluate  # noqa: E402
from pwcheck.core import Result  # noqa: E402

# ANSI colours, one per score band (0-4).
_BAND_COLOURS = ("\033[91m", "\033[91m", "\033[93m", "\033[92m", "\033[96m")
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

METER_WIDTH = 24


def _supports_colour(stream) -> bool:
    """Colour only when writing to a real terminal that has not opted out."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _render(result: Result, *, colour: bool, verbose: bool) -> str:
    """Build the human-readable report."""

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    band = _BAND_COLOURS[result.score]
    filled = round(METER_WIDTH * (result.score + 1) / len(SCORE_LABELS))
    meter = paint("█" * filled, band) + paint("░" * (METER_WIDTH - filled), _DIM)

    lines = [
        "",
        f"  {meter}  {paint(result.label.upper(), band + _BOLD)}",
        "",
        f"  Length           {result.length}",
        f"  Entropy          {result.entropy_bits:.1f} bits "
        f"{paint(f'(raw {result.raw_entropy_bits:.1f}, pool {result.pool_size})', _DIM)}",
        f"  Offline crack    {result.crack_time_display}",
        "",
    ]

    lines.append("  Requirements")
    for requirement in result.requirements:
        mark = paint("✓", _BAND_COLOURS[3]) if requirement.met else paint("✗", _BAND_COLOURS[0])
        label = requirement.label if requirement.met else paint(requirement.label, _DIM)
        lines.append(f"    {mark} {label}")

    if result.warnings:
        lines += ["", "  Warnings"]
        lines += [f"    ! {w}" for w in result.warnings]

    if result.suggestions:
        lines += ["", "  Suggestions"]
        lines += [f"    → {s}" for s in result.suggestions]

    if verbose and result.penalties:
        lines += ["", "  Entropy deductions"]
        lines += [f"    -{p.bits:6.2f} bits  {p.label}" for p in result.penalties]

    lines.append("")
    return "\n".join(lines)


def _read_password(args: argparse.Namespace) -> Optional[str]:
    """Resolve the password from argv, stdin or an interactive prompt."""
    if args.password is not None:
        print(
            "warning: passing a password as an argument exposes it to other "
            "local processes and your shell history; prefer --stdin.",
            file=sys.stderr,
        )
        return args.password

    if args.stdin:
        # Strip only the trailing newline the shell adds - not other
        # whitespace, which may legitimately be part of a passphrase.
        data = sys.stdin.readline()
        return data[:-1] if data.endswith("\n") else data

    if not sys.stdin.isatty():
        print("error: no terminal available; use --stdin.", file=sys.stderr)
        return None

    try:
        password = getpass.getpass("Password (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        print("\naborted.", file=sys.stderr)
        return None

    if args.confirm:
        again = getpass.getpass("Confirm: ")
        if again != password:
            print("error: passwords do not match.", file=sys.stderr)
            return None
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checker.py",
        description="Evaluate password strength (entropy + pattern analysis).",
        epilog="Exit status: 0 if the password meets --min-score, 1 if not, 2 on usage error.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "password",
        nargs="?",
        help="password to check (INSECURE on shared machines; prefer --stdin)",
    )
    source.add_argument(
        "--stdin", action="store_true", help="read the password from standard input"
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="prompt twice and require the two entries to match",
    )
    parser.add_argument(
        "-u",
        "--user-input",
        action="append",
        default=[],
        metavar="TEXT",
        help="context an attacker would try first (username, email, company); repeatable",
    )
    parser.add_argument("--json", action="store_true", help="emit the full result as JSON")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="print nothing; use the exit status only"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show the per-pattern entropy deductions"
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=2,
        choices=range(0, 5),
        metavar="0-4",
        help="minimum acceptable score for a zero exit status (default: 2)",
    )
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    password = _read_password(args)
    if password is None:
        return 2

    result = evaluate(password, user_inputs=args.user_input)
    # Drop the reference promptly; it is not a security guarantee in a GC'd
    # runtime, but it keeps the value out of later frames and tracebacks.
    del password

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    elif not args.quiet:
        colour = _supports_colour(sys.stdout) and not args.no_color
        print(_render(result, colour=colour, verbose=args.verbose))

    return 0 if result.score >= args.min_score else 1


if __name__ == "__main__":
    sys.exit(main())
