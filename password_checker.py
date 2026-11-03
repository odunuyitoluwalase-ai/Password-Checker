#!/usr/bin/env python3
"""Password Strength Checker: analyses complexity and common weaknesses.

Usage:
    python password_checker.py              # prompts (input is hidden)
    python password_checker.py --generate   # makes a strong random password
"""
import argparse
import getpass
import math
import re
import secrets
import string

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein",
    "welcome", "monkey", "dragon", "iloveyou", "admin", "login", "master",
    "football", "baseball", "sunshine", "princess", "shadow", "superman",
    "trustno1", "passw0rd", "111111", "000000", "123123", "qwertyuiop",
    "1q2w3e4r", "zaq12wsx", "starwars", "whatever", "freedom", "hello", "secret",
}
WORDS = [
    "password", "passwd", "admin", "welcome", "letmein", "qwerty", "login",
    "master", "monkey", "dragon", "shadow", "sunshine", "princess", "football",
    "baseball", "soccer", "summer", "winter", "spring", "autumn", "love",
    "iloveyou", "hello", "secret", "computer", "michael", "jessica", "charlie",
    "superman", "batman", "school", "family", "freedom", "whatever", "default",
    "guest", "company", "office",
]
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "l", "!": "i",
                      "0": "o", "$": "s", "5": "s", "7": "t", "8": "b"})
LEVELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
GUESSES_PER_SEC = 1e10  # offline attack on a quickly hashed password


def pool_size(pw):
    size = 0
    size += 26 if re.search(r"[a-z]", pw) else 0
    size += 26 if re.search(r"[A-Z]", pw) else 0
    size += 10 if re.search(r"\d", pw) else 0
    size += 33 if re.search(r"[ -/:-@\[-`{-~]", pw) else 0
    size += 100 if re.search(r"[^\x00-\x7F]", pw) else 0
    return size


def analyse(pw):
    """Return (entropy_bits, list_of_weakness_messages)."""
    n = len(pw)
    if n == 0:
        return 0.0, []
    pool = max(pool_size(pw), 2)
    lower = pw.lower()
    norm = lower.translate(LEET)
    covered = [False] * n
    cost = 0.0
    found = []

    def mark(start, end, c, msg):
        nonlocal cost
        fresh = sum(1 for k in range(start, end) if not covered[k])
        for k in range(start, end):
            covered[k] = True
        if fresh:
            cost += c
            found.append(msg)

    if norm in COMMON or lower in COMMON:
        mark(0, n, 6, "This is one of the most commonly used passwords.")

    for w in WORDS:
        at = norm.find(w)
        if at > -1:
            extra = " (swapping in symbols like @ or 0 doesn't fool attackers)" \
                if w not in lower else ""
            mark(at, at + len(w), 11, f'Contains the common word "{w}"{extra}.')

    # Runs such as abc or 321
    i = 0
    while i < n - 2:
        d = ord(lower[i + 1]) - ord(lower[i])
        if abs(d) == 1:
            j = i + 1
            while j < n and ord(lower[j]) - ord(lower[j - 1]) == d:
                j += 1
            if j - i >= 3:
                mark(i, j, 5, f'Contains the sequence "{pw[i:j]}".')
                i = j
                continue
        i += 1

    # Keyboard walks such as qwerty or asdf
    for row in KEYBOARD_ROWS:
        for r in (row, row[::-1]):
            for s in range(len(r) - 3):
                for e in range(len(r), s + 3, -1):
                    sub = r[s:e]
                    at = lower.find(sub)
                    if at > -1:
                        mark(at, at + len(sub), 8,
                             f'Follows a keyboard pattern ("{sub}").')
                        break

    for m in re.finditer(r"(.)\1{2,}", pw):
        mark(m.start(), m.end(), 4, f'Repeats a character ("{m.group()}").')
    for m in re.finditer(r"(.{2,4})\1+", lower):
        mark(m.start(), m.end(), 5 + math.log2(len(m.group(1)) * pool),
             f'Repeats the chunk "{m.group(1)}".')
    for m in re.finditer(r"(?:19|20)\d\d", pw):
        mark(m.start(), m.end(), 7,
             f'Contains what looks like a year ("{m.group()}").')

    free = covered.count(False)
    return free * math.log2(pool) + cost, found


def level(bits):
    return 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4


def human_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("year", 31557600), ("month", 2629800), ("day", 86400),
             ("hour", 3600), ("minute", 60), ("second", 1)]
    for name, size in units:
        count = seconds / size
        if count >= 1:
            count = int(count)
            if name == "year" and count >= 10**6:
                return f"{count:.1e} years"
            return f"{count:,} {name}{'' if count == 1 else 's'}"
    return "instantly"


def report(pw):
    bits, weaknesses = analyse(pw)
    lv = level(bits)
    classes = {
        "lowercase letters": bool(re.search(r"[a-z]", pw)),
        "uppercase letters": bool(re.search(r"[A-Z]", pw)),
        "numbers": bool(re.search(r"\d", pw)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }
    print()
    print(f"Strength : {LEVELS[lv]}  [{'#' * (lv + 1)}{'-' * (4 - lv)}]")
    print(f"Entropy  : about {bits:.0f} bits")
    print(f"Length   : {len(pw)} characters (pool of {pool_size(pw)})")
    print(f"Crack time*: {human_time(2 ** bits / GUESSES_PER_SEC / 2)}")
    print("\nChecks")
    print(f"  [{'x' if len(pw) >= 12 else ' '}] At least 12 characters")
    for name, ok in classes.items():
        print(f"  [{'x' if ok else ' '}] Has {name}")
    if len(set(pw)) < len(pw) * 0.6:
        weaknesses.append(f"Many repeated characters ({len(set(pw))} unique of {len(pw)}).")
    print("\nWeaknesses")
    for w in weaknesses or ["None detected (common words, sequences, patterns)."]:
        print(f"  - {w}")
    print("\nTips")
    if len(pw) < 14:
        print("  - Aim for 14+ characters; length helps more than complexity.")
    if weaknesses:
        print("  - Replace the patterns above with random, unrelated characters or words.")
    if not all(classes.values()) and len(pw) < 20:
        print("  - Add the missing character types, or use a longer passphrase.")
    print("  - Use a unique password per account and a password manager.")
    print("\n*Assumes 10 billion guesses/second against a leaked, quickly hashed")
    print(" password. An estimate only; a breached password is weak at any score.")


def generate(length=18):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(not c.isalnum() for c in pw)):
            return pw


def main():
    parser = argparse.ArgumentParser(description="Password strength checker")
    parser.add_argument("--generate", action="store_true",
                        help="print a strong random password and analyse it")
    args = parser.parse_args()
    if args.generate:
        pw = generate()
        print(f"Generated: {pw}")
    else:
        pw = getpass.getpass("Password to test (hidden): ")
    report(pw)


if __name__ == "__main__":
    main()
