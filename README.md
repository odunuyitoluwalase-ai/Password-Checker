# Password Strength Checker

A command-line tool that analyses password complexity and weaknesses, then explains how to improve it. Written in Python using only the standard library.

## Features

- **Entropy estimate** and approximate **time to crack**
- **Complexity checks**: length, lowercase, uppercase, numbers, symbols
- **Weakness detection**:
  - Common passwords and words
  - Leetspeak substitutions (e.g. `p@ssw0rd`)
  - Sequences (`abc`, `321`)
  - Keyboard patterns (`qwerty`, `asdf`)
  - Repeated characters and chunks
  - Year-like numbers
- **Improvement tips** based on what was found
- **Secure password generator** using Python's `secrets` module
- Input is hidden while typing, and nothing is stored or sent anywhere

## Requirements

Python 3.8 or newer. No external packages.

## Usage

```bash
# Check a password (input is hidden)
python password_checker.py

# Generate a strong random password and analyse it
python password_checker.py --generate
```

## Example output

```
Strength : Very weak  [#---]
Entropy  : about 18 bits
Length   : 12 characters (pool of 95)
Crack time*: instantly

Weaknesses
  - Contains the common word "password" (swapping in symbols like @ or 0 doesn't fool attackers).
  - Contains what looks like a year ("2024").
```

## How it works

1. Calculates the character pool from the types of characters used.
2. Finds predictable patterns and counts those characters at a low fixed cost instead of full randomness.
3. Estimates entropy as `unpatterned characters × log2(pool size) + pattern costs`.
4. Converts entropy to an average crack time, assuming 10 billion guesses per second against a leaked, quickly hashed password.

## Limitations

- The word and common-password lists are short, so some weak passwords will be missed.
- Crack times are estimates. Online logins with attempt limits are far slower to attack.
- A password found in a past data breach is weak at any score.

## Roadmap

- [ ] Larger wordlist support (e.g. rockyou.txt)
- [ ] Check against known breaches (Have I Been Pwned k-anonymity API)
- [ ] GUI or web interface

## License

MIT
