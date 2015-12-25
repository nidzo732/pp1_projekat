"""
U ovom paketu su implementirane funkcije za sifrovanje fajlova
block-cipher algoritmima.
"""
from block_cipher import encrypt, decrypt, generate_key
from operation_modes import operation_modes
from algorithms import algorithms

available_algorithms = set(algorithms.keys())
available_operation_modes = set(operation_modes.keys())

__all__ = ["encrypt", "decrypt", "generate_key", "available_algorithms", "available_operation_modes"]
