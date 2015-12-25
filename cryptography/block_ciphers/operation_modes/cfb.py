"""
Ovaj fajl implementira CFB mod operacije za proizvoljnu
blok-sifru
"""
from os import urandom

from cryptography.block_ciphers.block_management import unpad_data
from cryptography.util_functions import xor_blocks


def encrypt(blocks, key, algorithm):
    """
    Vrsi enkripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po CFB modu.
    """
    iv = urandom(algorithm.BLOCK_SIZE)
    previous_block = iv

    yield iv

    for block in blocks:
        ciphertext_block = xor_blocks(algorithm.encrypt_block(previous_block, key), block)
        previous_block = ciphertext_block
        yield ciphertext_block


def decrypt(blocks, key, algorithm):
    """
    Vrsi dekripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po CFB modu.
    """
    iv = blocks.next()

    previous_block = iv
    block_to_write = None
    for block in blocks:
        if block_to_write:
            yield block_to_write
        plaintext_block = xor_blocks(algorithm.encrypt_block(previous_block, key), block)
        previous_block = block
        block_to_write = plaintext_block

    yield unpad_data(block_to_write)