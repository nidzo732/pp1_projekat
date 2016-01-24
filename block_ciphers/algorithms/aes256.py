# -*- coding: utf-8 -*-
"""
Created on Wed Jan 13 20:29:47 2016

@author: bulse_eye
"""
import aes128

BLOCK_SIZE = 16


def generate_key(key):
    valid_key = ''
    for i in range(8):
        if len(key) < 4:
            key = key + ' ' * (4 - len(key))
        valid_key += key[:4]
        key = key[4:]
    return valid_key


def validate_key(key):
    if len(key) == 32:
        return True
    else:
        return False


def encrypt_block(block, key):
    return aes128.encrypt_block(block, key)


def decrypt_block(block, key):
    return aes128.decrypt_block(block, key)
