# -*- coding: utf-8 -*-
"""
Created on Wed Jan 13 16:45:13 2016

@author: bulse_eye
"""

# -------------------------------------------------------------------------------
# Name:        module2
# Purpose:
#
# Author:      ratkoz
#
# Created:     24/12/2015
# Copyright:   (c) ratkoz 2015
# Licence:     <your licence>
# -------------------------------------------------------------------------------
import math

from block_ciphers.util_functions import xor_blocks

BLOCK_SIZE = 16

s_box_dic = {0: 99, 1: 124, 2: 119, 3: 123, 4: 242, 5: 107, 6: 111, 7: 197, 8: 48, 9: 1, 10: 103, 11: 43,
             12: 254, 13: 215, 14: 171, 15: 118, 16: 202, 17: 130, 18: 201, 19: 125, 20: 250, 21: 89, 22: 71, 23: 240,
             24: 173, 25: 212, 26: 162, 27: 175, 28: 156, 29: 164, 30: 114, 31: 192, 32: 183, 33: 253, 34: 147, 35: 38,
             36: 54, 37: 63, 38: 247, 39: 204, 40: 52, 41: 165, 42: 229, 43: 241, 44: 113, 45: 216, 46: 49, 47: 21,
             48: 4, 49: 199, 50: 35, 51: 195, 52: 24, 53: 150, 54: 5, 55: 154, 56: 7, 57: 18, 58: 128, 59: 226, 60: 235,
             61: 39, 62: 178, 63: 117, 64: 9, 65: 131, 66: 44, 67: 26, 68: 27, 69: 110, 70: 90, 71: 160, 72: 82, 73: 59,
             74: 214, 75: 179, 76: 41, 77: 227, 78: 47, 79: 132, 80: 83, 81: 209, 82: 0, 83: 237, 84: 32, 85: 252,
             86: 177, 87: 91, 88: 106, 89: 203, 90: 190, 91: 57, 92: 74, 93: 76, 94: 88, 95: 207, 96: 208, 97: 239,
             98: 170, 99: 251, 100: 67, 101: 77, 102: 51, 103: 133, 104: 69, 105: 249, 106: 2, 107: 127, 108: 80,
             109: 60, 110: 159, 111: 168, 112: 81, 113: 163, 114: 64, 115: 143, 116: 146, 117: 157, 118: 56, 119: 245,
             120: 188, 121: 182, 122: 218, 123: 33, 124: 16, 125: 255, 126: 243, 127: 210, 128: 205, 129: 12, 130: 19,
             131: 236, 132: 95, 133: 151, 134: 68, 135: 23, 136: 196, 137: 167, 138: 126, 139: 61, 140: 100, 141: 93,
             142: 25, 143: 115, 144: 96, 145: 129, 146: 79, 147: 220, 148: 34, 149: 42, 150: 144, 151: 136, 152: 70,
             153: 238,
             154: 184, 155: 20, 156: 222, 157: 94, 158: 11, 159: 219, 160: 224, 161: 50, 162: 58, 163: 10, 164: 73,
             165: 6, 166: 36, 167: 92, 168: 194, 169: 211, 170: 172, 171: 98, 172: 145, 173: 149, 174: 228, 175: 121,
             176: 231, 177: 200, 178: 55, 179: 109, 180: 141, 181: 213, 182: 78, 183: 169, 184: 108, 185: 86, 186: 244,
             187: 234, 188: 101, 189: 122, 190: 174, 191: 8, 192: 186, 193: 120, 194: 37, 195: 46, 196: 28, 197: 166,
             198: 180,
             199: 198, 200: 232, 201: 221, 202: 116, 203: 31, 204: 75, 205: 189, 206: 139, 207: 138, 208: 112, 209: 62,
             210: 181, 211: 102, 212: 72, 213: 3, 214: 246, 215: 14, 216: 97, 217: 53, 218: 87, 219: 185, 220: 134,
             221: 193,
             222: 29, 223: 158, 224: 225, 225: 248, 226: 152, 227: 17, 228: 105, 229: 217, 230: 142, 231: 148, 232: 155,
             233: 30,
             234: 135, 235: 233, 236: 206, 237: 85, 238: 40, 239: 223, 240: 140, 241: 161, 242: 137, 243: 13, 244: 191,
             245: 230, 246: 66, 247: 104, 248: 65, 249: 153, 250: 45, 251: 15, 252: 176, 253: 84, 254: 187, 255: 22}

inv_s_box_dic = dict([[v, k] for k, v in s_box_dic.items()])


def generate_key(key):
    valid_key = ''
    for i in range(4):
        if len(key) < 4:
            key = key + ' ' * (4 - len(key))
        valid_key += key[:4]
        key = key[4:]
    return valid_key


def validate_key(key):
    if len(key) == 16:
        return True
    else:
        return False


def make_blocks(string, size):
    listt = []
    k = int(math.ceil(len(string) / float(size)))
    for i in range(k):
        if len(string) < size:
            string = string + ' ' * (size - len(string))
        listt.append(string[0:size])
        string = string[size:]
    return listt


def make_sub_blocks(sixt_bytes):
    sub_list = []
    sub_list.append(sixt_bytes[0:4])
    sub_list.append(sixt_bytes[4:8])
    sub_list.append(sixt_bytes[8:12])
    sub_list.append(sixt_bytes[12:16])
    return sub_list


def s_box(byte, is_inv):
    if not is_inv:
        return chr(s_box_dic[ord(byte)])
    if is_inv:
        return chr(inv_s_box_dic[ord(byte)])


def byte_subst_1x4(bytesx4, is_inv):
    global s_box_dic
    global inv_s_box_dic
    subst_bytex4 = ''
    for byte in bytesx4:
        subst_bytex4 += s_box(byte, is_inv)
    return subst_bytex4


def byte_subst_4x4(list_of_4x4_bytes, is_inv):
    global s_box_dic
    global inv_s_box_dic
    subst_list = []
    for bytesx4 in list_of_4x4_bytes:
        subst_list.append(byte_subst_1x4(bytesx4, is_inv))
    return subst_list


def shift_row(list_of_4x4_bytes):
    shifted_row_list_of_4x4_bytes = []
    n = 0
    for k in range(4):
        new_byte = ""
        for i in range(4):
            j = (i + n) % 4
            new_byte += list_of_4x4_bytes[j][i]
        shifted_row_list_of_4x4_bytes.append(new_byte)
        n += 1
    return shifted_row_list_of_4x4_bytes


def inv_shift_row(list_of_4x4_bytes):
    shifted_row_list_of_4x4_bytes = []
    temp_list = [3, 2, 1, 0]
    n = 0
    for k in range(4):
        new_byte = ""
        for i in range(4):
            j = temp_list[(i + 3 - n) % 4]
            new_byte += list_of_4x4_bytes[j][i]
        shifted_row_list_of_4x4_bytes.append(new_byte)
        n += 1
    return shifted_row_list_of_4x4_bytes


def g(a, b):
    p = 0
    for counter in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        # keep a 8 bit
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p


def mix_col(list_4x4_bytes, is_inv):
    output = []
    if not is_inv:
        temp = [2, 3, 1, 1]
    else:
        temp = [14, 11, 13, 9]
    for bytesx4 in list_4x4_bytes:
        new_col = ''
        # 1
        res = g(ord(bytesx4[0]), temp[0]) ^ g(ord(bytesx4[1]), temp[1]) ^ g(ord(bytesx4[2]), temp[2]) ^ g(
            ord(bytesx4[3]), temp[3])
        new_col += chr(res)
        # 2
        res = g(ord(bytesx4[0]), temp[3]) ^ g(ord(bytesx4[1]), temp[0]) ^ g(ord(bytesx4[2]), temp[1]) ^ g(
            ord(bytesx4[3]), temp[2])
        new_col += chr(res)
        # 3
        res = g(ord(bytesx4[0]), temp[2]) ^ g(ord(bytesx4[1]), temp[3]) ^ g(ord(bytesx4[2]), temp[0]) ^ g(
            ord(bytesx4[3]), temp[1])
        new_col += chr(res)
        # 4
        res = g(ord(bytesx4[0]), temp[1]) ^ g(ord(bytesx4[1]), temp[2]) ^ g(ord(bytesx4[2]), temp[3]) ^ g(
            ord(bytesx4[3]), temp[0])
        new_col += chr(res)
        output.append(new_col)
    return output


def generate_round_key(key_list_4x4_byte, round_number, size):
    round_keys = [''] * (size / 32)
    round_keys[0] = xor_blocks(key_list_4x4_byte[0], g_function(key_list_4x4_byte[3], round_number))
    for i in range(1, size / 32):
        if i == 4 and size == 256:
            round_keys[4] = xor_blocks(h_function(round_keys[3]), key_list_4x4_byte[i])
        else:
            round_keys[i] = xor_blocks(round_keys[i - 1], key_list_4x4_byte[i])
    return round_keys


def generate_128_keys(key_list_4x4_byte):
    r_keys = [key_list_4x4_byte]
    for i in range(1, 11):
        temp = generate_round_key(r_keys[i - 1], i, 128)
        r_keys.append(temp)
    return r_keys


def generate_192_keys(key_list_6x4_byte):
    r_keys_str = ''
    r_keys_str += ''.join(key_list_6x4_byte)
    r_keys = [key_list_6x4_byte]
    for i in range(1, 8):
        temp = generate_round_key(r_keys[i - 1], i, 192)
        r_keys.append(temp)
        r_keys_str += ''.join(temp)
    t = xor_blocks(r_keys_str[168:172], g_function(r_keys_str[188:192], 8))
    r_keys += t
    r_keys_str += t
    for n in range(3):
        r_keys_str += xor_blocks(r_keys_str[172 + n * 4:176 + n * 4], r_keys_str[-4:])
    r_keys_f = [r_keys_str[i:i + 4] for i in range(0, len(r_keys_str), 4)]
    r_keys_final = [r_keys_f[x:x + 4] for x in range(0, len(r_keys_f), 4)]
    return r_keys_final


def generate_256_keys(key_list_8x4_byte):
    pass
    r_keys_str = ''
    r_keys_str += ''.join(key_list_8x4_byte)
    r_keys = [key_list_8x4_byte]
    for i in range(1, 7):
        temp = generate_round_key(r_keys[i - 1], i, 256)
        r_keys.append(temp)
        r_keys_str += ''.join(temp)
    t = xor_blocks(r_keys_str[192:196], g_function(r_keys_str[220:224], 7))
    r_keys += t
    r_keys_str += t
    for n in range(3):
        r_keys_str += xor_blocks(r_keys_str[196 + n * 4:200 + n * 4], r_keys_str[-4:])
    r_keys_f = [r_keys_str[i:i + 4] for i in range(0, len(r_keys_str), 4)]
    r_keys_final = [r_keys_f[x:x + 4] for x in range(0, len(r_keys_f), 4)]
    return r_keys_final


def rotate(bytex4):
    return bytex4[1:] + bytex4[:1]


def g_function(bytesx4, round_number):
    # vrace 4 byte-a kao str
    new = byte_subst_1x4(rotate(bytesx4), False)
    new = chr(ord(new[0]) ^ rc(round_number)) + new[1:]
    return new


def h_function(bytesx4):
    new = ''
    for i in range(4):
        new += s_box(bytesx4[i], False)
    return new


def rc(i):
    rc_list = ['first', 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]
    return rc_list[i]


# ----------------------- key split -----------------------
def get_key_split(key, size):
    keys = []
    for i in range(size / 32):
        keys.append(key[:4])
        key = key[4:]
    return keys


# -----------------------------------------------------------
def key_addition(list_4x4_bytes, key_list):
    output = ['', '', '', '']
    for i in range(4):
        output[i] = xor_blocks(list_4x4_bytes[i], key_list[i])
    return output


def encrypt_block(block, key):
    list_4x4_bytes = make_sub_blocks(block)
    size = len(key) * 8
    round_no = size / 32 + 6

    if size == 128:
        r_keys = generate_128_keys(get_key_split(key, size))
    elif size == 192:
        r_keys = generate_192_keys(get_key_split(key, size))
    else:
        r_keys = generate_256_keys(get_key_split(key, size))

    cipher_block = key_addition(list_4x4_bytes, r_keys[0])
    for i in range(1, round_no + 1):
        cipher_block = byte_subst_4x4(cipher_block, False)
        cipher_block = shift_row(cipher_block)
        if i != round_no:
            cipher_block = mix_col(cipher_block, False)
        cipher_block = key_addition(cipher_block, r_keys[i])
    return "".join(cipher_block)


def decrypt_block(block, key):
    list_4x4_bytes = make_sub_blocks(block)
    size = len(key) * 8
    round_no = size / 32 + 6

    if size == 128:
        r_keys = generate_128_keys(get_key_split(key, size))
    elif size == 192:
        r_keys = generate_192_keys(get_key_split(key, size))
    else:
        r_keys = generate_256_keys(get_key_split(key, size))

    for i in range(round_no, 0, -1):
        if i == round_no:
            cipher_block = key_addition(list_4x4_bytes, r_keys[i])
        else:
            cipher_block = key_addition(cipher_block, r_keys[i])
            cipher_block = mix_col(cipher_block, True)
        cipher_block = inv_shift_row(cipher_block)
        cipher_block = byte_subst_4x4(cipher_block, True)
    cipher_block = key_addition(cipher_block, r_keys[0])
    return "".join(cipher_block)