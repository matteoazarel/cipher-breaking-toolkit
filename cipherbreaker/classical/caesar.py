"""
Caesar cipher: encryption, decryption, and automated cryptanalysis.

The Caesar cipher shifts each letter of the alphabet by a fixed amount k:
    E(x) = (x + k) mod 26
    D(x) = (x - k) mod 26

Breaking it without knowing k relies on the fact that English letters have a
well-known, very non-uniform frequency distribution (E ~12.7%, T ~9%, ... Z ~0.07%).
We try all 26 possible shifts and score each resulting plaintext against the
expected English letter frequencies using a chi-squared statistic. The shift
that produces the LOWEST chi-squared score is the best match to real English,
and is (almost always) the correct key.
"""

from string import ascii_uppercase

# Standard English letter frequency percentages (source: standard corpus stats).
# Index 0 = 'A', 1 = 'B', ... 25 = 'Z'
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074,
}


def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt plaintext with a Caesar shift. Non-letters pass through unchanged."""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shifted = (ord(ch) - base + shift) % 26
            result.append(chr(base + shifted))
        else:
            result.append(ch)
    return ''.join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt a Caesar-shifted ciphertext given the shift (key)."""
    return caesar_encrypt(ciphertext, -shift)


def letter_frequencies(text: str) -> dict:
    """Return observed letter counts (A-Z only, case-insensitive) for a text."""
    counts = {ch: 0 for ch in ascii_uppercase}
    for ch in text.upper():
        if ch in counts:
            counts[ch] += 1
    return counts


def chi_squared_score(text: str) -> float:
    """
    Compute chi-squared statistic comparing this text's letter distribution
    to expected English letter frequencies. Lower score = more English-like.

    chi^2 = sum( (observed - expected)^2 / expected )
    """
    counts = letter_frequencies(text)
    total_letters = sum(counts.values())
    if total_letters == 0:
        return float('inf')

    chi_sq = 0.0
    for letter, observed in counts.items():
        expected = ENGLISH_FREQ[letter] / 100.0 * total_letters
        if expected > 0:
            chi_sq += (observed - expected) ** 2 / expected
    return chi_sq


def break_caesar(ciphertext: str, top_n: int = 3) -> list[tuple[int, float, str]]:
    """
    Try all 26 shifts, score each by chi-squared, and return the top_n
    best candidates as (shift, score, decrypted_text), sorted best-first.
    """
    candidates = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = chi_squared_score(decrypted)
        candidates.append((shift, score, decrypted))

    candidates.sort(key=lambda c: c[1])  # lower chi-squared = better
    return candidates[:top_n]


if __name__ == "__main__":
    # Quick self-test
    secret = caesar_encrypt("Attack at dawn, the eagle has landed", 7)
    print("Ciphertext:", secret)

    print("\nTop 3 candidate shifts (lower score = better English match):")
    for shift, score, text in break_caesar(secret):
        print(f"  shift={shift:2d}  chi^2={score:8.2f}  -> {text}")
