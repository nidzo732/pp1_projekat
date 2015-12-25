"""
U ovom paketu se nalaze implementacije
block-cipher algoritama.

Da bi se dodao novi algoritam potrebno je uraditi sledece:

1) Dodati modul u kojem se nalazi implementacija algoritma


2) Modul mora da sadrzi sledece:
    - promenljivu BLOCK_SIZE koja odredjuje velicinu bloka u bajtima

    - funkciju oblika def generate_key(password) koja generise validan
    kljuc za taj algoritam od proizvoljne korisnicke sifre

    - funkciju oblika def validate_key(key) koja proverava da li
    je dati kljuc validan za taj algoritam

    - funkciju oblika def encrypt_block(block, key) koja enkriptuje
    jedan blok od BLOCK_SIZE bajta datim kljucem

    - funkciju oblika def decrypt_block(block, key) koja dekriptuje
    jedan blok od BLOCK_SIZE bajta datim kljucem

    - modul moze sadrzati i druge stvari koje mu trebaju za rad


3) Importovati modul u ovaj fajl i dodati ga u recnik algorithms,
dodeliti mu string koji ga jedinstveno identifikuje
"""

from cryptography.block_ciphers.algorithms import des, triple_des

algorithms = {"DES": des,
              "3DES": triple_des}

__all__ = ["algorithms"]