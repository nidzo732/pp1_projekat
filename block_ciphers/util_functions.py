"""
Ovaj modul implementira zajednicke funkcije, koje cesto koriste
razni kriptografski algoritmi.

"""


def bytes_to_integer(byte_string):
    """
    Pretvara niz bajtova u pozitivan ceo broj
    """
    integer = 0
    for byte in byte_string:
        integer = integer * 256 + ord(byte)
    return integer


def integer_to_bytes(integer):
    """
    Pretvara pozitivan ceo broj u niz bajtova
    """
    assert integer >= 0
    byte_string = ""
    while integer > 0:
        byte_string = chr(integer % 256) + byte_string
        integer /= 256
    return byte_string


def xor_blocks(block1, block2):
    """
    Kombinuje dva niza bajtova, bajt po bajt XOR-ovanjem
    """
    assert len(block1) == len(block2)
    output_block = ""

    for i in range(len(block1)):
        output_block += chr(ord(block1[i]) ^ ord(block2[i]))
    return output_block
