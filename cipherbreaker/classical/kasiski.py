"""
Kasiski Examination: finding the key length of a Vigenere cipher.

The attack works in three steps:
    1. Find all repeated substrings (length >= 3) in the ciphertext
    2. Measure the distance between each pair of repeats
    3. The key length is the value that divides most of those distances

Why does this work?
    A repeated chunk of ciphertext means the same plaintext letters were
    encrypted with the same key letters. That only happens when the distance
    between the two occurrences is a multiple of the key length (because the
    key has cycled back to the same position). So the key length will show up
    as a common factor across many of the distances we find.
"""

from collections import Counter


def find_repeated_sequences(ciphertext: str, min_length: int = 3) -> dict[str, list[int]]:
    """
    Step 1: Find all substrings of length >= min_length that appear
    more than once in the ciphertext.

    Returns a dict mapping each repeated substring to the list of
    positions where it starts.
    """
    # Strip spaces/punctuation and uppercase everything
    # Kasiski only works on raw encrypted letters, not formatting
    clean = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())

    sequences = {}  # substring -> list of start positions

    # Try substring lengths 3, 4, 5, 6, 7
    # Longer matches are stronger evidence, shorter ones are more common
    for length in range(min_length, min_length + 5):

        # Slide a window of that length across every position
        for i in range(len(clean) - length + 1):
            seq = clean[i:i + length]  # the current chunk we're looking at

            # Record every position we see this chunk at
            if seq not in sequences:
                sequences[seq] = []
            sequences[seq].append(i)

    # Throw away chunks that only appeared once — useless for Kasiski
    # We only care about chunks appearing at multiple positions
    repeated = {seq: positions for seq, positions in sequences.items()
                if len(positions) > 1}

    return repeated


def get_distances(repeated_sequences: dict[str, list[int]]) -> list[int]:
    """
    Step 2: For every repeated chunk, compute the distance between
    each pair of positions it appeared at.

    Example: "TIG" at positions [4, 16, 40]
        -> distances: 16-4=12, 40-4=36, 40-16=24
    """
    distances = []

    for positions in repeated_sequences.values():
        # Compare every pair of positions (i, j) where j > i
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distances.append(positions[j] - positions[i])

    return distances


def get_factors(n: int, max_factor: int = 20) -> list[int]:
    """
    Return all factors of n up to max_factor.

    We cap at 20 because real Vigenere keys are almost never longer
    than 20 characters. Uses modulo (n % i == 0) to check divisibility
    — same modulo you know from crypto coursework.

    Example: get_factors(12) -> [2, 3, 4, 6, 12]
    """
    return [i for i in range(2, max_factor + 1) if n % i == 0]


def rank_key_lengths(distances: list[int], max_key_length: int = 20) -> list[tuple[int, int]]:
    """
    Step 3: Count how many distances each candidate key length divides
    evenly into. The key length that divides the most distances is the
    most likely answer — because it lined up with the most repeats.

    Returns (key_length, score) pairs sorted best-first.
    """
    factor_counts = Counter()

    for distance in distances:
        # Every factor of this distance gets a "vote"
        # e.g. distance=12 gives votes to key lengths 2, 3, 4, 6, 12
        for factor in get_factors(distance, max_key_length):
            factor_counts[factor] += 1

    # most_common() returns results sorted highest score first
    # so index [0] is always our best guess
    return factor_counts.most_common()


def kasiski_attack(ciphertext: str, top_n: int = 5) -> list[tuple[int, int]]:
    """
    Full Kasiski pipeline — chains all three steps together:
        1. find_repeated_sequences()
        2. get_distances()
        3. rank_key_lengths()

    Returns the top_n candidate key lengths as (key_length, score) pairs.
    """
    # Step 1: find repeated chunks
    repeated = find_repeated_sequences(ciphertext)

    if not repeated:
        print("No repeated sequences found — ciphertext may be too short.")
        return []

    # Step 2: compute distances between repeat occurrences
    distances = get_distances(repeated)

    # Step 3: rank candidates by how many distances they divide
    rankings = rank_key_lengths(distances)

    print(f"Found {len(repeated)} repeated sequences, {len(distances)} distances")
    print(f"\nTop {top_n} candidate key lengths:")
    for key_length, count in rankings[:top_n]:
        print(f"  key length {key_length:2d}  ->  divides {count} distances")

    return rankings[:top_n]


if __name__ == "__main__":
    # Self-test using your coursework example: key = GCGH (length 4)
    from vigenere import vigenere_encrypt

    plaintext = (
        "The melody was still dancing about the boat but now it was only a whisper "
        "the thin thread of melody was not more than that the boat was not more than "
        "a shadow the melody was the only thing that was real"
    )
    key = "GCGH"

    ciphertext = vigenere_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext)
    print()

    results = kasiski_attack(ciphertext)
    print()
    print(f"Best guess for key length: {results[0][0]} (correct answer: {len(key)})")