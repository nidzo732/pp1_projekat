"""
Ovaj modul implementira Data Encryption Standard (DES) algoritam
za sifrovanje podataka po specifikaciji iz "Federal Information
Processing Standards Publication 46-3", NIST 1999.
"""

import hashlib
from cryptography.util_functions import bytes_to_integer, integer_to_bytes

BLOCK_SIZE = 8
MAX_KEY_SCHEDULE_CACHE_SIZE = 4

# mapa za pocetnu permutaciju bloka
initial_permutation_map = [57, 49, 41, 33, 25, 17, 9, 1,
                           59, 51, 43, 35, 27, 19, 11, 3,
                           61, 53, 45, 37, 29, 21, 13, 5,
                           63, 55, 47, 39, 31, 23, 15, 7,
                           56, 48, 40, 32, 24, 16, 8, 0,
                           58, 50, 42, 34, 26, 18, 10, 2,
                           60, 52, 44, 36, 28, 20, 12, 4,
                           62, 54, 46, 38, 30, 22, 14, 6]

# mapa za zavrsnu permutaciju bloka
inverse_initial_permutation_map = [39, 7, 47, 15, 55, 23, 63, 31,
                                   38, 6, 46, 14, 54, 22, 62, 30,
                                   37, 5, 45, 13, 53, 21, 61, 29,
                                   36, 4, 44, 12, 52, 20, 60, 28,
                                   35, 3, 43, 11, 51, 19, 59, 27,
                                   34, 2, 42, 10, 50, 18, 58, 26,
                                   33, 1, 41, 9, 49, 17, 57, 25,
                                   32, 0, 40, 8, 48, 16, 56, 24]

# mapa za permutaciju koja vrsi ekspanziju
# 32 bitnog podbloka u 48 bitni
block_expansion_map = [31, 0, 1, 2, 3, 4, 3, 4,
                       5, 6, 7, 8, 7, 8, 9, 10,
                       11, 12, 11, 12, 13, 14, 15, 16,
                       15, 16, 17, 18, 19, 20, 19, 20,
                       21, 22, 23, 24, 23, 24, 25, 26,
                       27, 28, 27, 28, 29, 30, 31, 0]

# mapa za zavrsnu permutaciju podbloka, tokom jedne iteracije
p_map = [16, 7, 20, 21,
         29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2, 8, 24, 14,
         32, 27, 3, 9,
         19, 13, 30, 6,
         22, 11, 4, 25]

# tabele za selection funkcije
s_tables = {1: [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            2: [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            3: [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            4: [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            5: [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            6: [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            7: [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            8: [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
            }

# broj "levih" bit shiftova za svaku iteraciju
# key schedule funkcije
ks_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# mapa za izdvajanje C dela iz kljuca
ks_pc1_map_C = [56, 48, 40, 32, 24, 16, 8, 0,
                57, 49, 41, 33, 25, 17, 9, 1,
                58, 50, 42, 34, 26, 18, 10, 2,
                59, 51, 43, 35]

# mapa za izdvajanje D dela iz kljuca
ks_pc1_map_D = [63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4]

# mapa za konacnu obradu kljuca
ks_pc2_map = [62, 54, 46, 38, 30, 22, 14, 6,
              61, 53, 45, 37, 29, 21, 13, 5,
              60, 52, 44, 36, 28, 20, 12, 4,
              27, 19, 11, 3]


def generate_key(password):
    """
    Generise 64 bitni DES kljuc,
    uz pravilno podesavanje bitova parnosti
    """
    key_generator = hashlib.sha256()
    key_generator.update(password)
    primary_key = key_generator.digest()[:8]

    valid_key = ""
    for byte in primary_key:
        bit_count = 0
        primary_byte = ord(byte)
        while primary_byte > 0:
            bit_count += primary_byte % 2
            primary_byte /= 2
        if bit_count % 2 == 0:         # imamo paran broj bitova
            byte = chr(ord(byte) ^ 1)  # flipuj poslednji
        valid_key += byte
    return valid_key


def validate_key(key):
    """
    Vrsi proveru validnosti kljuca
    na osnovu bitova parnosti
    """
    key = key
    if len(key) != 8:
        return False
    for byte in key:
        bit_count = 0
        byte = ord(byte)
        while byte > 0:
            bit_count += byte % 2
            byte /= 2
        if bit_count % 2 == 0:  # paran broj bitova
            return False        # kljuc nije ispravan
    return True


def permute_block(block, permutation_map):
    # vrsi permutaciju datog bloka po datoj mapi
    permuted_block = 0
    for position in range(len(permutation_map)):
        extracted_bit = block & (1 << permutation_map[position])
        if extracted_bit:
            permuted_block |= 1 << position
    return permuted_block


def selection_function(block, iteration):
    """
    funkcija koja mapira svaki blok
    na 4 bitni broj iz odgovarajuce tabele
    """
    row = ((block >> 5) << 1) + (block & 1)  # trazimo broj reda i kolone
    column = (block >> 1) & 15
    return s_tables[iteration][row][column]


def cipher_function(expanded_block, subkey):
    """
    Funkcija koja se primenjuje na 32 bitni pod-blok
    u svakoj od 16 iteracija
    """
    expanded_block = permute_block(expanded_block, block_expansion_map)  # blok se prosiruje na 48 bita

    s_input = expanded_block ^ subkey  # blok se xoruje sa podkljucem

    output = 0
    for i in range(8):  # podblok se obradjuje kao 8 6-bitnih blokova
        input_segment = (s_input & (63 << ((8 - i - 1) * 6))) >> ((8 - i - 1) * 6)  # izdvajanje 6-bitnog bloka
        output_segment = selection_function(input_segment, i + 1)  # primena S funkcije
        output += output_segment << ((8 - i - 1) * 4)  # dodavanje 4 bitnog rezultata na izlaz

    return permute_block(output, p_map)


# posto se jedan kljuc verovatno primenjuje na vise blokova
# bilo bi korisno da se key-schedule kesira, umesto da se
# racuna za svaki blok
key_schedule_cache = {}


def key_schedule(key):
    """
    Funkcija koja generise 16 podkljuceva za 16
    iteracija DES algoritma
    """

    global key_schedule_cache

    if key in key_schedule_cache:    # mozda imamo kesiran key-schedule za ovaj kljuc
        return key_schedule_cache[key]

    c_part = permute_block(key, ks_pc1_map_C)  # rastavljanje kljuca na delove
    d_part = permute_block(key, ks_pc1_map_D)

    keys = []
    for i in range(16):
        c_part_next = c_part << ks_shifts[i]
        c_part_next |= c_part & (2 ** ks_shifts[i] - 1)
        d_part_next = d_part << ks_shifts[i]
        d_part_next |= d_part & (2 ** ks_shifts[i] - 1)
        c_part = c_part_next
        d_part = d_part_next
        keys.append(permute_block((c_part << 28) + d_part, ks_pc2_map))

    if len(key_schedule_cache) > MAX_KEY_SCHEDULE_CACHE_SIZE:  # cache postao preveliki
        key_schedule_cache = {}
    key_schedule_cache[key] = keys  # dodajemo kljuc u cache
    return keys


def encrypt_block(block, key):
    """
    Funkcija koja vrsi enkripciju
    jednog bloka po datom kljucu
    """
    assert len(block) == 8

    block = bytes_to_integer(block)  # sadrzaj bloka se pretvara u broj
    key = bytes_to_integer(key)  # radi lakse obrade

    block = permute_block(block, initial_permutation_map)  # pocetna permutacija

    left = block >> 32  # rastavljanje na dva
    right = block & ((1 << 32) - 1)  # 32 bitna bloka

    keys = key_schedule(key)  # generisemo skup podkljuceva

    for subkey in keys:  # vrsimo 16 iteracija
        new_left = right
        new_right = left ^ cipher_function(right, subkey)
        left = new_left
        right = new_right

    block = (right << 32) + left  # spajanje blokova
    block = permute_block(block, inverse_initial_permutation_map)  # zavrsna permutacija
    block = integer_to_bytes(block)  # vracanje u bajt-oblik
    while len(block) < 8:  # dodavanje 0-bajtova do 8-bajtnog oblika
        block = "\x00" + block

    return block


def decrypt_block(block, key):
    """
    Funkcija koja vrsi dekripciju jednog bloka
    po datom kljucu
    """
    assert len(block) == 8

    block = bytes_to_integer(block)  # konverzija u broj
    key = bytes_to_integer(key)  # radi lakse obrade

    block = permute_block(block, initial_permutation_map)  # pocetna permutacija

    left = block >> 32  # rastavljanje na levi i desni
    right = block & ((1 << 32) - 1)  # blok

    keys = key_schedule(key)  # generisanje podkljuceva

    for subkey in reversed(keys):  # primena kljuceva, obrnutim redom od enkripcije
        new_left = right
        new_right = left ^ cipher_function(right, subkey)
        left = new_left
        right = new_right

    block = (right << 32) + left  # sastavljanje blokova
    block = permute_block(block, inverse_initial_permutation_map)  # zavrsna permutacija
    block = integer_to_bytes(block)  # vracanje u bajt-oblik
    while len(block) < 8:  # produzavanje do 8-bajta
        block = "\x00" + block
    return block
