# Cipher-Breaking Toolkit

A Python toolkit for breaking classical and basic modern ciphers, built to
demonstrate practical cryptanalysis techniques: frequency analysis,
Kasiski examination, Index of Coincidence, many-time-pad attacks, and
small-parameter RSA attacks.

## Status: Work in progress

- [x] Caesar cipher + chi-squared frequency attack
- [ ] Vigenère cipher + Kasiski test + Index of Coincidence
- [ ] Many-time pad XOR crib-dragging attack
- [ ] RSA attacks (small modulus / common modulus / Wiener's)
- [ ] Unified CLI

## Setup

```bash
git clone https://github.com/<your-username>/cipher-breaking-toolkit.git
cd cipher-breaking-toolkit
pip install -r requirements.txt
```

## Usage (so far)

```bash
python3 cipherbreaker/classical/caesar.py
```

## Why this project

Each module includes a writeup of the underlying attack theory, not just
the code — the goal is to demonstrate understanding of *why* each
cryptanalysis technique works, not just an implementation.
