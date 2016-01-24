import os


class BadLengthError(Exception):
    pass


def pad_data(data, block_size):
    """
    Dovodi date podatke na duzinu deljivu sa
    block_size, tako sto na kraj prvo
    doda bajt 0xff a zatim bajtove 0x00
    dok ne dobije potrebnu duzinu.
    """
    padding_length = block_size - (len(data) % block_size)
    return data + "\xff" + (padding_length - 1) * "\x00"


def unpad_data(data):
    """
    Skida bajtove dodate funkcijom pad_data.
    """
    data = data.rstrip("\x00")
    return data[:-1]


def fetch_blocks(input_file, block_size, mac_size=-1, pad=True):
    """
    Cita podatke iz ulaznog fajla i razdvaja ih na blokove.

    :param input_file: ulazni fajl, mora biti otvoren za citanje
     i mora podrzavati .seek() i .tell() operacije

    :param block_size: duzina blokova na koje treba deliti ulaz

    :param mac_size: duzina HMAC koda ako se nalazi na kraju, nece biti citan
     prilikom obrade.

    :param pad: da li da paduje poslednji blok koji mozda nije duzine block_size

    :return: generator nad kojim se moze vrsiti iteracija kako bi se citali
     podaci blok po blok
    """
    last_block = None
    mac_start = None
    data_read = 0
    if mac_size != -1:
        input_file.seek(-mac_size, os.SEEK_END)
        mac_start = input_file.tell()
        input_file.seek(0)
        if mac_start % block_size != 0:
            raise BadLengthError()
    while True:
        if data_read == mac_start:  # stigli smo na pocetak HMAC koda
            break                   # ne citamo dalje
        if last_block:  # procitali smo poslednji blok
            yield last_block
            break
        block = input_file.read(block_size)
        data_read += len(block)
        if mac_start and data_read > mac_start:  # blokovi nisu duzine block size
            raise BadLengthError()               # upali smo u HMAC
        if len(block) == block_size:  # blok je ok duzine
            yield block
        else:             # ovo je poslednji blok, kraci od block_size
            if pad:       # padujemo ga ako treba
                block = pad_data(block, block_size)
                if len(block) == block_size:
                    yield block
                    break
                else:  # padovanje nekad napravi dva bloka, pa ih vracamo u odvojenim koracima
                    last_block = block[-block_size:]
                    yield block[:-block_size]
            else:
                if block:
                    raise BadLengthError()  # poslednji blok mora imati block_size ili 0 duzinu
                else:                       # ako ne radimo padovanje
                    break
