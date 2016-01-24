"""
Ovaj fajl implementira OFB mod operacije za proizvoljnu
blok-sifru
"""
from os import urandom

from block_ciphers.block_management import unpad_data
from block_ciphers.util_functions import xor_blocks


def encrypt(blocks, key, algorithm):
    """
    Vrsi enkripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po OFB modu.
    """
    iv = urandom(algorithm.BLOCK_SIZE)
    previous_block = iv

    yield iv

    for block in blocks:
        output_block = algorithm.encrypt_block(previous_block, key)
        ciphertext_block = xor_blocks(output_block, block)
        previous_block = output_block
        yield ciphertext_block


def decrypt(blocks, key, algorithm):
    """
    Vrsi dekripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po OFB modu.
    """
    iv = blocks.next()

    previous_block = iv
    block_to_write = None
    for block in blocks:
        if block_to_write:
            yield block_to_write
        output_block = algorithm.encrypt_block(previous_block, key)
        plaintext_block = xor_blocks(output_block, block)
        previous_block = output_block
        block_to_write = plaintext_block

    yield unpad_data(block_to_write)