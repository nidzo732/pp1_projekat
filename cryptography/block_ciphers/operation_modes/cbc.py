"""
Ovaj fajl implementira CBC mod operacije za proizvoljnu
blok-sifru
"""
from os import urandom

from cryptography.block_ciphers.block_management import unpad_data
from cryptography.util_functions import xor_blocks


def encrypt(blocks, key, algorithm):
    """
    Vrsi enkripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po CBC modu.
    """
    iv = urandom(algorithm.BLOCK_SIZE)
    previous_ciphertext_block = iv
    yield iv

    for block in blocks:
        input_block = xor_blocks(previous_ciphertext_block, block)
        previous_ciphertext_block = algorithm.encrypt_block(input_block, key)
        yield previous_ciphertext_block


def decrypt(blocks, key, algorithm):
    """
    Vrsi dekripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po CBC modu.
    """
    iv = blocks.next()

    previous_ciphertext_block = iv
    block_to_write = None
    for block in blocks:
        if block_to_write:
            yield block_to_write
        plaintext_block = xor_blocks(previous_ciphertext_block, algorithm.decrypt_block(block, key))
        previous_ciphertext_block = block
        block_to_write = plaintext_block

    yield unpad_data(block_to_write)