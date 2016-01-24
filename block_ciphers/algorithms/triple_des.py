"""
Ovaj modul implementira Triple Data Encryption Standard (3DES) algoritam
za sifrovanje podataka po specifikaciji iz "Federal Information
Processing Standards Publication 46-3", NIST 1999.
"""

import hashlib

from block_ciphers.algorithms import des

BLOCK_SIZE = 8


def generate_key(password):
    """
    Generise 196 bitni 3DES kljuc,
    uz pravilno podesavanje bitova parnosti
    """
    key_generator = hashlib.sha256()
    key_generator.update(password)
    primary_key = key_generator.digest()[:24]

    valid_key = ""
    for byte in primary_key:
        bit_count = 0
        primary_byte = ord(byte)
        while primary_byte > 0:
            bit_count += primary_byte % 2
            primary_byte /= 2
        if bit_count % 2 == 0:
            byte = chr(ord(byte) ^ 1)
        valid_key += byte
    return valid_key


def validate_key(key):
    """
    Vrsi proveru validnosti kljuca
    na osnovu bitova parnosti
    """
    key = key
    if len(key) != 24:
        return False
    for byte in key:
        bit_count = 0
        byte = ord(byte)
        while byte > 0:
            bit_count += byte % 2
            byte /= 2
        if bit_count % 2 == 0:
            return False
    return True


def encrypt_block(block, key):
    """
    Enkriptuje dati blok 3DES algoritmom,
    po datom kljucu
    """
    assert len(block) == 8

    key1 = key[:8]  # izdvajanje kljuceva
    key2 = key[8:16]
    key3 = key[16:]

    return des.encrypt_block(des.decrypt_block(des.encrypt_block(block, key1), key2), key3)


def decrypt_block(block, key):
    """
    Dekriptuje dati blok 3DES algoritmom
    po datom kljucu
    """
    assert len(block) == 8

    key1 = key[:8]  # izdvajanje kljuceva
    key2 = key[8:16]
    key3 = key[16:]

    return des.decrypt_block(des.encrypt_block(des.decrypt_block(block, key3), key2), key1)
