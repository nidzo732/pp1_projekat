"""
Ovaj modul implementira funkcije koje vrse enkripciju
i dekripciju sadrzaja fajlova upotrebom block-cipher algoritama.
"""
import os
import random
import re
import hmac
import hashlib
import tempfile

from block_ciphers.block_management import fetch_blocks, BadLengthError
from algorithms import algorithms
from util_functions import integer_to_bytes
from operation_modes import operation_modes

algorithm_name_regex = "^([A-Za-z0-9]+)\-([A-Za-z0-9]+)$"


def encrypt(infile, outfile, key, algorithm, authenticate=True):
    """
    Enkriptuje sadrzaj ulaznog fajla i upisuje ga u izlazni fajl.

    :param infile: ulazni fajl, mora biti otvoren za citanje i
     mora podrzavati operacije .seek() i .tell()

    :param outfile: izlazni fajl, mora biti otvoren za upis

    :param key: kljuc za sifrovanje, mora biti validan za trazeni algoritam

    :param algorithm: algoritam za sifrovanje. String oblika 'ALG-OPM', gde
     je ALG string koji identifikuje block cipher algoritam. Dostupni algoritmi
     se nalaze u skupu block_ciphers.available_algorithms. OPM je
     string koji identifikuje mod operacije. Dostupni modovi se nalaze u skupu
     block_ciphers.available_operation_modes

    :param authenticate: odredjuje da li treba da se vrsi dodavanje HMAC koda
     na ciphertext

    :return: string sa porukom o gresci ako je doslo do problema, None ako je sve
     u redu
    """

    try:
        parameters = re.findall(algorithm_name_regex, algorithm)

        if not parameters:  # provera validnosti parametara
            return "Los format za ime algoritma"
        algorithm, operation_mode = parameters[0]
        if algorithm not in algorithms:
            return "Nepostojeci algoritam" + algorithm
        if operation_mode not in operation_modes:
            return "Nepostojeci mod operacije: " + operation_mode
        algorithm = algorithms[algorithm]
        if not algorithm.validate_key(key):
            return "Neispravan kljuc"

        mac_generator = None
        if authenticate:    # pokrecemo HMAC generator
            mac_generator = hmac.new(key, digestmod=hashlib.sha256)

        blocks = fetch_blocks(infile, algorithm.BLOCK_SIZE)  # pokrecemo dobavljac blokova

        for block in operation_modes[operation_mode].encrypt(blocks, key, algorithm):
            outfile.write(block)    # upisujemo izlaz
            if authenticate:        # generisemo HMAC blok po blok
                mac_generator.update(block)

        if mac_generator:       # upisujemo HMAC
            outfile.write(mac_generator.digest())

        return None  # sve OK
    except OSError as error:
        return "Citanje fajla nije uspelo: "+error.strerror


def decrypt(infile, outfile, key, algorithm, authenticate=True):
    """
    Dekriptuje sadrzaj ulaznog fajla i upisuje ga u izlazni fajl.

    :param infile: ulazni fajl, mora biti otvoren za citanje i
     mora podrzavati operacije .seek() i .tell()

    :param outfile: izlazni fajl, mora biti otvoren za upis

    :param key: kljuc za desifrovanje, mora biti validan za trazeni algoritam

    :param algorithm: algoritam za desifrovanje. String oblika 'ALG-OPM', gde
     je ALG string koji identifikuje block cipher algoritam. Dostupni algoritmi
     se nalaze u skupu block_ciphers.available_algorithms. OPM je
     string koji identifikuje mod operacije. Dostupni modovi se nalaze u skupu
     block_ciphers.available_operation_modes

    :param authenticate: odredjuje da li treba da se vrsi provera HMAC koda koji se
    nalazi na kraju fajla. HMAC mora postojati u ulazu. Ako HMAC nije validan ili ne postoji
    vraca se poruka o gresci i u izlazni fajl se nista ne upisuje.

    :return: string sa porukom o gresci ako je doslo do problema, None ako je sve
     u redu
    """
    try:
        parameters = re.findall(algorithm_name_regex, algorithm)
        if not parameters:  # provera validnosti parametara
            return "Los format za ime algoritma"
        algorithm, operation_mode = parameters[0]
        if algorithm not in algorithms:
            return "Nepostojeci algoritam" + algorithm
        if operation_mode not in operation_modes:
            return "Nepostojeci mod operacije: " + operation_mode
        algorithm = algorithms[algorithm]
        if not algorithm.validate_key(key):
            return "Neispravan kljuc"

        mac_generator = None
        if authenticate:    # ako je zatrazena provera, generisemo HMAC i proveravamo ga
            mac_generator = hmac.new(key, digestmod=hashlib.sha256)
            infile.seek(-mac_generator.digest_size, os.SEEK_END)
            mac = infile.read()
            infile.seek(0)
            for block in fetch_blocks(infile, algorithm.BLOCK_SIZE, mac_generator.digest_size, pad=False):
                mac_generator.update(block)
            if mac != mac_generator.digest():
                return "Desifrovanje fajla nije moguce sa ovom sifrom"
            infile.seek(0)  # vracamo se na pocetak fajla

        if mac_generator:   # ne zelimo da dekriptujemo sam HMAC
            blocks = fetch_blocks(infile, algorithm.BLOCK_SIZE, mac_generator.digest_size, pad=False)
        else:
            blocks = fetch_blocks(infile, algorithm.BLOCK_SIZE, pad=False)
        for block in operation_modes[operation_mode].decrypt(blocks, key, algorithm):
            outfile.write(block)
        return None  # sve OK
    except BadLengthError:
        return "Sadrzaj fajla je neispravan ili nije odgovarajuce duzine"
    except OSError as error:
        return "Citanje fajla nije uspelo: "+error.strerror


def generate_key(password, algorithm):
    """
    Generise validan kljuc za trazeni algoritam, od na osnovu korisnicke sifre.

    :param password: sifra korisnika, string proizvoljnog oblika

    :param algorithm: ime algoritma za koji je kljuc namenjen. Dostupni algoritmi
     se nalaze u listi block_ciphers.available_algorithms

    :return: kljuc za trazeni algoritam
    """
    if algorithm not in algorithms:
        return None
    return algorithms[algorithm].generate_key(password)


def test():
    """
    Funkcija koja vrsi testiranje svih dostupnih algoritama i modova operacija
    sa random kljucevima i ciphertextima.
    """
    SINGLE_COMBO_TEST_COUNT = 20
    MAX_KEY_SEED_LENGTH = 1024
    MAX_PLAINTEXT_LENGTH = 1024

    def single_combo_test(algorithm, opmode, authenticate):
        print "Testing:", algorithm + "-" + opmode + (" with MAC" if authenticate else "")
        for i in range(SINGLE_COMBO_TEST_COUNT):
            key = generate_key(integer_to_bytes(random.getrandbits(random.randint(1, MAX_KEY_SEED_LENGTH))), algorithm)
            bad_key = key
            while bad_key == key:
                bad_key = generate_key(integer_to_bytes(random.getrandbits(random.randint(1, MAX_KEY_SEED_LENGTH))),
                                       algorithm)
            plaintext = integer_to_bytes(random.getrandbits(random.randint(1, MAX_PLAINTEXT_LENGTH)))

            input_file = tempfile.NamedTemporaryFile("w", delete=False)
            input_file.write(plaintext)
            input_file.close()
            input_file = open(input_file.name, "r")
            output_file = tempfile.NamedTemporaryFile("w", delete=False)
            encrypt(input_file, output_file, key, algorithm + "-" + opmode, authenticate=authenticate)

            output_file.close()
            input_file.close()
            input_file = open(output_file.name, "r")
            output_file = tempfile.NamedTemporaryFile("w", delete=False)

            assert (not decrypt(input_file, output_file, key, algorithm + "-" + opmode, authenticate=authenticate))

            input_file.close()
            output_file.close()

            output_file = open(output_file.name, "r")
            text = output_file.read()
            if plaintext != text:
                print("Decryption fail, plaintexts dont match")
                return False
            output_file.close()
            input_file = open(input_file.name, "r")
            output_file = open(output_file.name, "w")
            if authenticate:
                if decrypt(input_file, output_file, bad_key, algorithm + "-" + opmode, True) is None:
                    print("MAC FAIL")
                    return False
        print("OK")
        return True

    for algorithm in algorithms:
        for mode in operation_modes:
            if not single_combo_test(algorithm, mode, False):
                return
            if not single_combo_test(algorithm, mode, True):
                return
