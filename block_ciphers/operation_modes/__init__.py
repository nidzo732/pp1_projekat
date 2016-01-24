"""
U ovom paketu se nalaze implementacije
modova operacija za block-cipher algoritme.

Da bi se dodao novi mod operacije, potrebno je uraditi sledece:

1) Dodati modul koji implementira taj mod operacije


2) Modul mora da sarzi sledece:

    - funkciju oblika def encrypt(blocks, key, algorithm).
    Parametri su:
        blocks - iterabilan niz blokova plaintexta, od kojih je svaki duzine
        algorithm.BLOCK_SIZE bajta
        key - kljuc za dati algoritam
        algorithm - modul u kome je implementiran algoritam za
        enkripciju i koji sadrzi:
            BLOCK_SIZE - duzina bloka za taj algoritam
            encrypt_block(block, key) - enkriptuje jedan blok
            decrypt_block(block, key) - dekriptuje jedan blok

    - funkciju oblika def decrypt(blocks, key, algorithm), ciji su
    parametri isti kao i za funkciju encrypt().

    - modul moze sadrzati i druge stvari potrebne za rad.


3) Importovati modul i dodati ga u recnik operation_modes,
dodeliti mu string koji ga jedinstveno identifikuje
"""
import logging
from block_ciphers.operation_modes import cfb, ofb, ctr
from block_ciphers.operation_modes import cbc, pcbc

installed_operation_modes = {"CBC": cbc,
                             "PCBC": pcbc,
                             "CFB": cfb,
                             "OFB": ofb,
                             "CTR": ctr
                             }

operation_modes = {}
required_attributes = ["encrypt", "decrypt"]

# proveravamo da li svi modovi imaju trazenu strukturu, oni koji je nemaju se ne dodaju
# na listu dostupnih
for mode_name in installed_operation_modes:
    for attribute in required_attributes:
        if not hasattr(installed_operation_modes[mode_name], attribute):
            logging.warning("Algoritam {} nije ispravan, nedostaje {}".format(mode_name, attribute))
            break
    else:
        operation_modes[mode_name] = installed_operation_modes[mode_name]

__all__ = ["operation_modes"]
