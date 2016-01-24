"""
Ovaj fajl implementira PCBC mod operacije za proizvoljnu
blok-sifru
"""
from os import urandom

from block_ciphers.block_management import unpad_data
from block_ciphers.util_functions import xor_blocks


def encrypt(blocks, key, algorithm):
    """
    Vrsi enkripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po PCBC modu.
    """
    iv = urandom(algorithm.BLOCK_SIZE)
    previous_xoring_block = iv

    yield iv

    for block in blocks:
        input_block = xor_blocks(block, previous_xoring_block)
        ciphertext_block = algorithm.encrypt_block(input_block, key)
        previous_xoring_block = xor_blocks(block, ciphertext_block)
        yield ciphertext_block


def decrypt(blocks, key, algorithm):
    """
    Vrsi dekripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po PCBC modu.
    """
    iv = blocks.next()

    previous_xoring_block = iv
    block_to_write = None
    for block in blocks:
        if block_to_write:
            yield block_to_write
        plaintext_block = xor_blocks(algorithm.decrypt_block(block, key), previous_xoring_block)
        previous_xoring_block = xor_blocks(block, plaintext_block)
        block_to_write = plaintext_block

    yield unpad_data(block_to_write)