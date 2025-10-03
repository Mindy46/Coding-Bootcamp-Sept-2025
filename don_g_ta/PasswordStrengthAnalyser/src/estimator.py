# src/estimator.py 

import math

ATTACKER_PROFILES = {
    # Online / per-account / per-IP style
    "Per-account throttled (10/hr)": 10 / 3600.0,    # per second
    "Per-IP throttled (1000/day)": 1000 / 86400.0,   # per second

    # Small distributed bot
    "Unthrottled single bot (10/sec)": 10.0,

    # Larger bot farm
    "Distributed bot farm (1000/sec)": 1000.0,

    # Massive distributed attack / credential stuffing (scale)
    "Credential stuffing (1,000,000/sec)": 1e6,

    # Offline cracking examples (only relevant with hashes)
    "Single high-end GPU (est) (1e11 H/s)": 1e11,
    "GPU cluster (est) (1e12 H/s)": 1e12,
}

# src/estimator.py
def secs_to_human(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    units = [("years", 365*24*3600), ("days", 24*3600), ("hours", 3600), ("minutes", 60), ("seconds", 1)]
    for name, val in units:
        if seconds >= val:
            return f"{seconds/val:.2f} {name}"
    return f"{seconds:.2f} seconds"

ATTACKER_PROFILES = {
    "Per-account throttled (10/hr)": 10/3600.0,
    "Per-IP throttled (1000/day)": 1000/86400.0,
    "Unthrottled single bot (10/sec)": 10.0,
    "Distributed bot farm (1000/sec)": 1000.0,
    "Credential stuffing (1,000,000/sec)": 1e6,
    "Single high-end GPU (est) (1e11 H/s)": 1e11,
    "GPU cluster (est) (1e12 H/s)": 1e12,
}

def estimate_crack_times(guesses: float, extra_profiles: dict = None) -> dict:
    profiles = ATTACKER_PROFILES.copy()
    if extra_profiles:
        profiles.update(extra_profiles)
    result = {}
    for name, hps in profiles.items():
        seconds = guesses / hps
        result[name] = {"seconds": seconds, "display": secs_to_human(seconds)}
    return result
