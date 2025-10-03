import PySimpleGUI as sg
import pyperclip
import re
from .analyser import analyze_password
from .generator import generate_random
from .estimator import estimate_crack_times  # adjust as needed

# --- Fonts ---
FONT = ("Arial", 12)
TITLE_FONT = ("Arial", 14, "bold")

# --- Helper: human-readable time ---
def secs_to_human(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    units = [("years", 365*24*3600), ("days", 24*3600), ("hours", 3600), ("minutes", 60), ("seconds", 1)]
    for name, val in units:
        if seconds >= val:
            return f"{seconds/val:.2f} {name}"
    return f"{seconds:.2f} seconds"

# --- Deterministic password feedback ---
COMMON_WORDS = {
    "password", "admin", "letmein", "welcome", "qwerty", "abc123", "iloveyou",
    "123456", "12345678", "football", "monkey", "dragon"
}
SYMBOL_RE = re.compile(r"[!@#$%^&*(),.?\":{}|<>_\-+=\\/\[\];'`]")

def get_password_feedback(password: str) -> list:
    hints = []
    if not password:
        hints.append("Password is empty — enter a password to analyze.")
        return hints

    pw = password.strip()
    L = len(pw)

    # Length
    if L < 8:
        hints.append("Very short — aim for at least 12 characters or a 4+ word passphrase.")
    elif 8 <= L < 12:
        hints.append("Short — consider 12+ characters for better strength.")
    else:
        hints.append(f"Length: {L} characters — good.")

    # Case
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_lower = bool(re.search(r"[a-z]", pw))
    if not has_upper and not has_lower:
        hints.append("No letters — include mixed-case letters.")
    elif not has_upper:
        hints.append("No uppercase letters — add at least one (A-Z).")
    elif not has_lower:
        hints.append("No lowercase letters — add at least one (a-z).")
    else:
        hints.append("Mixed case: contains both upper and lower case.")

    # Digits
    has_digit = bool(re.search(r"\d", pw))
    if not has_digit:
        hints.append("No digits — add numbers (0-9).")
    else:
        hints.append("Contains digits.")

    # Symbols
    has_symbol = bool(SYMBOL_RE.search(pw))
    if not has_symbol:
        hints.append("No symbols — add one or more symbols (e.g., !@#$%) for extra strength.")
    else:
        hints.append("Contains symbol(s).")

    # Dictionary words
    lowered = pw.lower()
    found_common = [w for w in COMMON_WORDS if w in lowered]
    if found_common:
        hints.append(f"Avoid common words or phrases like: {', '.join(found_common)}.")

    # Repeated chars/patterns
    if re.search(r"(.)\1\1", pw):
        hints.append("Contains repeated characters (e.g., 'aaa') — avoid long repeats.")
    if re.search(r"(..+)\1", pw):
        hints.append("Contains repeated substring patterns — avoid simple repeats.")

    # Trailing symbols
    m = re.search(r"([!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]{2,})\s*$", pw)
    if m and L < 12:
        hints.append("Ends with a short run of symbols — add length elsewhere.")
    elif m and L >= 12:
        hints.append("Ends with symbols — fine when password is long enough.")

    # Multi-word passphrase
    words_like = re.findall(r"[A-Za-z]{3,}", pw)
    if len(words_like) >= 3 and L >= 16:
        hints.append("Looks like a multi-word passphrase — good for memorability and strength.")

    # Cleanup duplicates
    seen = set()
    out = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out

# --- Format feedback for GUI ---
def format_feedback(feedback: dict, hints: list) -> str:
    parts = []

    # Analyzer warning
    warning = feedback.get("warning") if feedback else None
    if warning:
        parts.append("Warning: " + warning)

    # Analyzer suggestions
    suggestions = feedback.get("suggestions", []) if feedback else []
    if suggestions:
        parts.append("Suggestions from analyzer:")
        for s in suggestions:
            parts.append(f" - {s}")

    # Analyzer hints
    if hints:
        parts.append("Analyzer / heuristic hints:")
        for h in hints:
            parts.append(f" - {h}")

    # Actionable steps
    lower_combined = "\n".join(parts).lower()
    actions = []
    if "length" not in lower_combined:
        actions.append("Increase password length (12+ characters or a 4+ word passphrase).")
    if not any("passphrase" in s.lower() for s in hints + suggestions):
        actions.append("Consider using a passphrase of several unrelated words.")
    if "mfa" not in lower_combined and "multi-factor" not in lower_combined:
        actions.append("Use multi-factor authentication (MFA) where available.")

    if actions:
        parts.append("Actionable steps:")
        for a in actions:
            parts.append(f" - {a}")

    if not parts:
        return "(No feedback available.)"
    return "\n".join(parts)

# --- Split estimates for GUI ---
def split_estimates(estimates: dict) -> tuple:
    online_keys = [
        "Per-account throttled (10/hr)",
        "Per-IP throttled (1000/day)",
        "Unthrottled single bot (10/sec)",
        "Distributed bot farm (1000/sec)",
        "Credential stuffing (1,000,000/sec)",
    ]
    online_lines = []
    offline_lines = []
    for k, v in estimates.items():
        line = f"{k}: {v.get('display', secs_to_human(v.get('seconds', 0)))}"
        if k in online_keys:
            online_lines.append(line)
        else:
            offline_lines.append(line)
    return ("\n".join(online_lines), "\n".join(offline_lines))

# --- Build GUI layout ---
def build_layout():
    layout = [
        [sg.Text("Enter Password:", font=FONT),
         sg.Input(key="PW-", password_char="*", size=(40, 1), font=FONT, enable_events=True),
         sg.Checkbox("Show", key="SHOW", enable_events=True, tooltip="Toggle to show/hide the password", font=FONT)],

        [sg.Button("Analyze", size=(12, 1), font=FONT),
         sg.Button("Generate Strong", key='-GEN-', size=(14, 1), font=FONT),
         sg.Button("Copy", key='-COPY-', size=(8,1), font=FONT),
         sg.Button("Clear", key="-CLEAR-", size=(8,1), font=FONT)],

        [sg.Text("Score:", font=TITLE_FONT), sg.Text("", key='-SCORE-', font=TITLE_FONT)],

        [sg.Text("Feedback:", font=FONT)],
        [sg.Multiline("", key='-FEED-', size=(70, 6), disabled=True, autoscroll=True, font=FONT)],

        [sg.Text("Online attack estimates (depends on site defenses):", font=FONT)],
        [sg.Multiline("", key='-ONLINE-', size=(70, 6), disabled=True, autoscroll=True, font=FONT)],

        [sg.Text("Offline attack estimates (attacker has password hash):", font=FONT)],
        [sg.Multiline("", key='-OFFLINE-', size=(70, 6), disabled=True, autoscroll=True, font=FONT)],

        [sg.Button("Why different?", key='-WHY-', font=FONT), sg.Button("Quit", font=FONT)]
    ]
    return layout

# --- Main GUI loop ---
def run():
    sg.theme('LightGrey1')
    layout = build_layout()
    window = sg.Window("Password Strength Analyser", layout, finalize=True)

    while True:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, 'Quit'):
            break

        # Toggle show/hide
        if event == 'SHOW':
            window['PW-'].update(password_char='' if values['SHOW'] else '*')
        
        if event == "-CLEAR-":
            window['PW-'].update('')
            window['-SCORE-'].update('')
            window['-FEED-'].update('')
            window['-ONLINE-'].update('')
            window['-OFFLINE-'].update('')
            continue

        # Copy password
        if event == '-COPY-':
            pw = values.get('PW-', '') or ''
            if pw:
                try:
                    pyperclip.copy(pw)
                    sg.popup("Password copied to clipboard", title="Copied", keep_on_top=True)
                except Exception:
                    sg.popup("Unable to copy to clipboard on this system", title="Error")
            else:
                sg.popup("No password to copy", title="Info")
                
                
        # Live feedback as user types
        if event == "PW-":
            pw = values.get("PW-", "") or ""
            if pw.strip():
                res = analyze_password(pw)
                local_hints = get_password_feedback(pw)
                window['-SCORE-'].update(str(res.get('score', 'N/A')))
                window['-FEED-'].update(format_feedback(res.get('feedback', {}), local_hints))
                guesses = res.get('guesses', None)
                if guesses is not None:
                    estimates = estimate_crack_times(guesses)
                    online_text, offline_text = split_estimates(estimates)
                    window['-ONLINE-'].update(online_text)
                    window['-OFFLINE-'].update(offline_text)


        # Generate strong password
        
        if event == '-GEN-':
            gen_pw = generate_random(16)
            window['PW-'].update(gen_pw)
            if not values.get('SHOW'):
                window['SHOW'].update(value=True)
                window['PW-'].update(password_char='')
            # Analyze generated password
            res = analyze_password(gen_pw)
            local_hints = get_password_feedback(gen_pw)
            window['-SCORE-'].update(str(res.get('score', 'N/A')))
            window['-FEED-'].update(format_feedback(res.get('feedback', {}), local_hints))
            estimates = estimate_crack_times(res.get('guesses', 0))
            online_text, offline_text = split_estimates(estimates)
            window['-ONLINE-'].update(online_text)
            window['-OFFLINE-'].update(offline_text)

        # Analyze typed password
        if event == 'Analyze':
            pw = values.get('PW-', '') or ''
            if not pw.strip():
                sg.popup("Please enter a password to analyze", title="Input required")
                continue

            res = analyze_password(pw)
            local_hints = get_password_feedback(pw)
            window['-SCORE-'].update(str(res.get('score', 'N/A')))
            window['-FEED-'].update(format_feedback(res.get('feedback', {}), local_hints))
            guesses = res.get('guesses', None)
            if guesses is None:
                sg.popup("Analyzer did not return guesses. Is zxcvbn installed?", title="Error")
                continue
            estimates = estimate_crack_times(guesses)
            online_text, offline_text = split_estimates(estimates)
            window['-ONLINE-'].update(online_text)
            window['-OFFLINE-'].update(offline_text)

        # Why different popup
        if event == '-WHY-':
            sg.popup(
                "Why online and offline estimates differ:\n\n"
                "• Online estimates assume guesses are being sent to a live login endpoint and are limited by rate-limiting, account lockouts, and network defenses.\n"
                "• Offline estimates assume the attacker has the password hash and can run guesses locally on powerful hardware (GPUs).\n"
                "• Distributed attacks (bot farms) can parallelize guesses across many IPs and machines, greatly increasing effective attempts/sec.\n\n"
                "Show the Online section to consider realistic attacker attempts; show Offline for breach scenarios.",
                title="About estimates",
                keep_on_top=True
            )

    window.close()

if __name__ == '__main__':
    run()
