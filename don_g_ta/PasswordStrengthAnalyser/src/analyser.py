from zxcvbn import zxcvbn


# src/analyser.py
from zxcvbn import zxcvbn
from typing import List, Dict

def _synthesize_hints(sequence: List[Dict]) -> List[str]:
    """
    Create human-friendly hints from zxcvbn sequence matches.
    Each match has a 'pattern' (dictionary, spatial, repeat, sequence, regex, date, bruteforce, etc).
    """
    hints = []
    for match in sequence:
        p = match.get("pattern")
        token = match.get("token", "")
        if p == "dictionary":
            dictionary_name = match.get("dictionary_name", "")
            if dictionary_name:
                hints.append(f"Contains common word or phrase: '{token}' (from {dictionary_name}). Consider using unrelated words, or a passphrase of multiple rare words.")
            else:
                hints.append(f"Contains common word or phrase: '{token}'. Avoid dictionary words or make a long passphrase.")
        elif p == "spatial":
            hints.append(f"Contains keyboard pattern: '{token}'. Avoid straight keyboard patterns like 'qwerty' or '1234'.")
        elif p == "repeat":
            hints.append(f"Contains repeated characters or sequences: '{token}'. Repeats are easy to guess; add variety and length.")
        elif p == "sequence":
            hints.append(f"Contains a sequence: '{token}'. Sequences (abcd, 1234) reduce strength — use unrelated words or random chars.")
        elif p == "regex" or p == "bruteforce":
            # bruteforce means no human patterns found; but it may still be short
            if len(token) < 12:
                hints.append(f"Short random-looking password ('{token}') — consider increasing length to at least 12-16 characters.")
        elif p == "date":
            hints.append(f"Contains a date-like item: '{token}'. Avoid birthdays or dates.")
        else:
            # unknown patterns we ignore or add a general hint
            if token and len(token) < 8:
                hints.append(f"Short segment: '{token}'. Increasing length increases strength most effectively.")
    return hints

def analyze_password(password: str, user_inputs: List[str] = None) -> Dict:
    """
    Analyze password using zxcvbn and return a dictionary with:
      - score (0-4)
      - guesses (float)
      - crack_times_seconds (dict from zxcvbn)
      - crack_times_display (dict from zxcvbn)
      - feedback (zxcvbn feedback)
      - hints (synthesized, actionable hints list)
      - sequence (raw sequence from zxcvbn)
    """
    if user_inputs is None:
        user_inputs = []

    result = zxcvbn(password, user_inputs)

    # Gather synthesized hints from the sequence matches
    sequence = result.get("sequence", []) or []
    synthesized = _synthesize_hints(sequence)

    # General sanity hint if password is short
    if len(password) < 12:
        synthesized.insert(0, "Password length is short. Prefer passphrases or 12+ characters for good baseline strength.")

    return {
        "score": result.get("score"),
        "guesses": result.get("guesses"),
        "crack_times_seconds": result.get("crack_times_seconds", {}),
        "crack_times_display": result.get("crack_times_display", {}),
        "feedback": result.get("feedback", {}),
        "hints": synthesized,
        "sequence": sequence
    }
