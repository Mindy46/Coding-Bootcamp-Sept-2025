from typing import List, Dict, Optional

# zxcvbn is an external dependency — keep import local to make testing easier and to show
# that we thought about runtime errors when the library isn't available.
try:
    from zxcvbn import zxcvbn
except Exception:  # pragma: no cover - library missing in some test envs
    zxcvbn = None  # type: ignore


def _synthesize_hints(sequence: List[Dict]) -> List[str]:

    hints: List[str] = []

    for match in sequence:
        pattern = match.get("pattern")
        token = match.get("token", "")

        # defensive defaults, humans like to be explicit
        if pattern is None:
            # Unknown/empty match, skip it but leave a note for future debugging
            # TODO: log this in a debug logger instead of ignoring silently
            continue

        # dictionary matches often include a 'dictionary_name' key
        if pattern == "dictionary":
            dict_name = match.get("dictionary_name", "")
            if dict_name:
                hints.append(
                    f"Contains a common word/phrase: '{token}' (from {dict_name}). "
                    "Try unrelated words or a passphrase composed of rare words."
                )
            else:
                hints.append(
                    f"Contains a common word or phrase: '{token}'. "
                    "Avoid simple dictionary words; longer passphrases help a lot."
                )

        elif pattern == "spatial":
            # spatial means keyboard adjacency patterns
            hints.append(
                f"Keyboard pattern detected: '{token}'. Avoid straight patterns like 'qwerty' or 'asdf'. "
                "Mix directions and include non-adjacent characters."
            )

        elif pattern == "repeat":
            hints.append(
                f"Repeated sequence: '{token}'. Repeats are cheap for attackers — add variety and length."
            )

        elif pattern == "sequence":
            hints.append(
                f"Sequence found: '{token}'. Sequences (abcd, 1234) lower entropy — use unrelated words or random chars."
            )

        elif pattern in ("regex", "bruteforce"):
            # bruteforce indicates no human patterns found; still might be too short
            if token and len(token) < 12:
                hints.append(
                    f"Short random-looking segment: '{token}' — consider lengthening to 12-16+ characters."
                )

        elif pattern == "date":
            hints.append(f"Date-like content detected: '{token}'. Avoid birthdays or easily guessable dates.")

        else:
            # Generic fallback for unknown patterns
            if token and len(token) < 8:
                hints.append(f"Short segment: '{token}'. Increasing overall length boosts strength most effectively.")

    return hints


def analyze_password(password: str, user_inputs: Optional[List[str]] = None) -> Dict:
    """Analyze a password with zxcvbn and return a friendly, inspectable dict.

    Returned fields (keeps parity with original):
      - score (0-4)
      - guesses (float)
      - crack_times_seconds (dict)
      - crack_times_display (dict)
      - feedback (dict)
      - hints (List[str]) synthesized from sequence
      - sequence (raw sequence list from zxcvbn)

    Human-style touches:
    - Defensive checks when zxcvbn isn't installed.
    - Insertion of a short-length hint up front when appropriate.
    - Keeps the function easy to read by using intermediate names and comments.
    """

    if user_inputs is None:
        user_inputs = []

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if zxcvbn is None:
        # In case the dependency isn't available, fail with a helpful message rather than a cryptic ImportError
        raise RuntimeError("zxcvbn library is required for analyze_password; install it with 'pip install zxcvbn'")

    # Run the analysis (keep the simple call so it's familiar)
    result = zxcvbn(password, user_inputs)

    # Pull out the sequence of matches for synthesizing additional hints
    sequence = result.get("sequence") or []

    # Synthesize human-friendly hints
    synthesized_hints = _synthesize_hints(sequence)

    # If password is short, prefer to put that as the first hint (humans often prioritize length)
    if len(password) < 12:
        synthesized_hints.insert(0, "Password too short: prefer a passphrase or 12+ characters for baseline strength.")

    # Build up the return structure explicitly so it's clear what we return
    output: Dict = {
        "score": result.get("score"),
        "guesses": result.get("guesses"),
        "crack_times_seconds": result.get("crack_times_seconds", {}),
        "crack_times_display": result.get("crack_times_display", {}),
        "feedback": result.get("feedback", {}),
        "hints": synthesized_hints,
        "sequence": sequence,
    }

    return output


# Quick example/demo left in the file on purpose — humans often keep these while iterating.
if __name__ == "__main__":
    try:
        sample = "Tr0ub4dor&3"
        print("Analyzing sample password:", sample)
        res = analyze_password(sample)

        # Human-friendly printout
        print("Score:", res["score"])  # simple one-line output
        print("Feedback:", res.get("feedback"))
        print("Hints:")
        for h in res.get("hints", []):
            print(" -", h)

    except Exception as exc:
        print("Error running demo:", exc)
        # TODO: replace print with proper logging before final submission
