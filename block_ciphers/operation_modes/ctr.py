"""
Ovaj fajl implementira CTR mod operacije za proizvoljnu
blok-sifru
"""
from os import urandom

from block_ciphers.block_management import unpad_data
from block_ciphers.util_functions import xor_blocks, integer_to_bytes


def create_counter_generator(iv):
    """
    Generise niz brojackih blokova koji se kasnije
    kombinuju sa blokovima plaintexta/ciphertexta
    tokom enkripcije/dekripcije
    """
    counter = 0
    while True:
        counter += 1
        counter_bytes = integer_to_bytes(counter)
        while len(counter_bytes) < len(iv):
            counter_bytes = "\x00" + counter_bytes
        yield xor_blocks(counter_bytes, iv)


def encrypt(blocks, key, algorithm):
    """
    Vrsi enkripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po CTR modu.
    """
    iv = urandom(algorithm.BLOCK_SIZE)
    counter_generator = create_counter_generator(iv)
    yield iv

    for block in blocks:
        input_block = counter_generator.next()
        ciphertext_block = xor_blocks(algorithm.encrypt_block(input_block, key), block)

        yield ciphertext_block


def decrypt(blocks, key, algorithm):
    """
    Vrsi dekripciju datog niza blokova, datim kljucem i block-cipher algoritmom,
    uz kombinovanje blokova po CTR modu.
    """
    iv = blocks.next()

    counter_generator = create_counter_generator(iv)
    block_to_write = None
    for block in blocks:
        if block_to_write:
            yield block_to_write
        input_block = counter_generator.next()
        plaintext_block = xor_blocks(block, algorithm.encrypt_block(input_block, key))
        block_to_write = plaintext_block

    yield unpad_data(block_to_write)
