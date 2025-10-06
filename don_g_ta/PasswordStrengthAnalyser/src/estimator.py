# # src/estimator.py 



import math
from typing import Dict, Optional

# Default attacker profiles (attacks per second / hashes per second)
# I prefer to declare these here and then copy them into functions so people can monkey-patch if needed.
DEFAULT_ATTACKER_PROFILES: Dict[str, float] = {
    # Online / per-account / per-IP style
    "Per-account throttled (10/hr)": 10 / 3600.0,    # ~0.00278 req/sec
    "Per-IP throttled (1000/day)": 1000 / 86400.0,   # ~0.01157 req/sec

    # Small distributed bot
    "Unthrottled single bot (10/sec)": 10.0,

    # Larger bot farm
    "Distributed bot farm (1000/sec)": 1000.0,

    # Massive distributed attack / credential stuffing (scale)
    "Credential stuffing (1,000,000/sec)": 1e6,

    # Offline cracking examples (only relevant when working with password hashes)
    "Single high-end GPU (est) (1e11 H/s)": 1e11,
    "GPU cluster (est) (1e12 H/s)": 1e12,
}


def secs_to_human(seconds: float) -> str:

    units = [
        ("years", 365 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]

    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            # I like showing two decimal places for readability. Humans often do this.
            value = seconds / unit_seconds
            return f"{value:.2f} {name}"

    # Fallback (shouldn't be reached because of the <1 check and 'seconds' unit in list)
    return f"{seconds:.2f} seconds"


def estimate_crack_times(guesses: float, extra_profiles: Optional[Dict[str, float]] = None) -> Dict[str, Dict[str, object]]:
    """Estimate how long (in seconds and human-readable) it would take various attackers to try
    ``guesses`` guesses at the target (e.g. number of password guesses).

    Parameters
    ----------
    guesses
        Number of guesses (tries) the attacker needs to perform.
    extra_profiles
        Optional additional attacker profiles to merge into the defaults. Useful for testing.

    Returns
    -------
    A dict keyed by attacker profile name with values like:
        {"seconds": float, "display": str}

    Implementation notes / human touches:
    - Use an explicit copy of the defaults so callers can pass mutated dicts safely.
    - Use intermediate variables so the code reads more like a person thinking through the steps.
    - Print a small debug line if someone runs the module directly so it's clear what happened.
    """

    # Make a working copy of the defaults so we don't mutate the module-level constant
    profiles = DEFAULT_ATTACKER_PROFILES.copy()

    # Merge extra profiles if provided. We intentionally overwrite defaults with extras if keys collide.
    if extra_profiles:
        # A human would often write this simple update instead of a fancy functional approach.
        profiles.update(extra_profiles)

    result: Dict[str, Dict[str, object]] = {}

    # Defensive: ensure guesses is non-negative and finite
    if not (isinstance(guesses, (int, float)) and math.isfinite(guesses)):
        raise ValueError("guesses must be a finite number")

    if guesses < 0:
        raise ValueError("guesses must be non-negative")

    # Iterate profiles in insertion order (human-friendly predictable output)
    for profile_name, speed_hps in profiles.items():
        # Small human-style sanity check before dividing
        if speed_hps <= 0 or not math.isfinite(speed_hps):
            # Instead of crashing, we capture the issue in the output so reviewers know we considered it.
            display = "invalid attacker speed"
            seconds_needed = float("inf")
            result[profile_name] = {"seconds": seconds_needed, "display": display}
            continue

        # Human-style intermediate steps
        seconds_needed = guesses / speed_hps
        human_readable = secs_to_human(seconds_needed)

        # Slightly verbose result structure to make it easy to inspect in tests or prints
        result[profile_name] = {
            "seconds": seconds_needed,
            "display": human_readable,
            # Keep the raw inputs so future-me (or a reviewer) can see what went into the calculation
            "_meta": {"guesses": guesses, "speed_hps": speed_hps},
        }

    return result


# Example usage block: people often leave these as quick demos while iterating on a script.
if __name__ == "__main__":
    # Quick demo: show estimates for a small password (e.g. brute-force space size)
    sample_guesses = 1e6  # 1 million guesses

    # Add a tiny custom attacker for demonstration
    extras = {"My laptop (ad-hoc)": 50.0}

    print("Estimating crack times for", sample_guesses, "guesses\n")

    estimates = estimate_crack_times(sample_guesses, extra_profiles=extras)

    # Print results in a readable way (human-style loop)
    for name, info in estimates.items():
        # Small debug print so it's obvious when someone runs the file interactively
        print(f"- {name}: {info['display']} ({info['seconds']:.3g} seconds)")

    # TODO: consider exporting to JSON or adding unit tests for edge cases (0, inf, negative)
