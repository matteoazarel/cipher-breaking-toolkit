"""
Vigenere cipher: encryption and decryption.

The Vigenere cipher is a polyalphabetic substitution cipher: instead of a
single fixed shift (like Caesar), it uses a repeating keyword where each
letter of the keyword specifies a different Caesar shift.

    E(x_i) = (x_i + k_(i mod len(key))) mod 26
    D(x_i) = (x_i - k_(i mod len(key))) mod 26

Key insight (used later for cryptanalysis): if you know the key length L,
then every L-th letter of the ciphertext was encrypted with the SAME shift.
That means each of the L "columns" is just a Caesar cipher, breakable with
the same chi-squared frequency attack from caesar.py.
"""

from string import ascii_uppercase


def _key_shifts(key: str) -> list[int]:
    """Convert a keyword into a list of integer shifts (A=0, B=1, ... Z=25)."""
    if not key or not key.isalpha():
        raise ValueError("Key must be a non-empty alphabetic string")
    return [ord(ch.upper()) - ord('A') for ch in key]


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext with a Vigenere cipher using the given keyword.
    Non-letter characters pass through unchanged and do NOT consume
    a position in the key (matches typical classroom convention).
    """
    shifts = _key_shifts(key)
    result = []
    key_index = 0  # only advances on alphabetic plaintext characters

    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = shifts[key_index % len(shifts)]
            shifted = (ord(ch) - base + shift) % 26
            result.append(chr(base + shifted))
            key_index += 1
        else:
            result.append(ch)

    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt a Vigenere ciphertext given the keyword."""
    shifts = _key_shifts(key)
    # Decryption is encryption with negated shifts
    neg_key = ''.join(
        ascii_uppercase[(-s) % 26] for s in shifts
    )
    return vigenere_encrypt(ciphertext, neg_key)


if __name__ == "__main__":
    # Quick self-test using the same example from your coursework
    plaintext = "The melody was still dancing about the boat, but now it was only a whisper"
    key = "GCGH"

    ciphertext = vigenere_encrypt(plaintext, key)
    print("Plaintext: ", plaintext)
    print("Key:       ", key)
    print("Ciphertext:", ciphertext)

    decrypted = vigenere_decrypt(ciphertext, key)
    print("Decrypted: ", decrypted)
    print("Round-trip OK:", decrypted == plaintext)