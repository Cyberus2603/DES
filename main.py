"""
Github:
Based on:
https://www.comparitech.com/blog/information-security/3des-encryption/
https://en.wikipedia.org/wiki/DES_supplementary_material
https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm
"""

from bitarray import bitarray
import PySimpleGUI

# Tables of key permutation
key_transpose_table_pc1 = [57, 49, 41, 33, 25, 17, 9,
                           1, 58, 50, 42, 34, 26, 18,
                           10, 2, 59, 51, 43, 35, 27,
                           19, 11, 3, 60, 52, 44, 36,
                           63, 55, 47, 39, 31, 23, 15,
                           7, 62, 54, 46, 38, 30, 22,
                           14, 6, 61, 53, 45, 37, 29,
                           21, 13, 5, 28, 20, 12, 4]
key_transpose_table_pc2 = [14, 17, 11, 24, 1, 5,
                           3, 28, 15, 6, 21, 10,
                           23, 19, 12, 4, 26, 8,
                           16, 7, 27, 20, 13, 2,
                           41, 52, 31, 37, 47, 55,
                           30, 40, 51, 45, 33, 48,
                           44, 49, 39, 56, 34, 53,
                           46, 42, 50, 36, 29, 32]
# Table of left shift moves for key
key_shifts_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# Data permutation tables
data_initial_permutation_table = [58, 50, 42, 34, 26, 18, 10, 2,
                                  60, 52, 44, 36, 28, 20, 12, 4,
                                  62, 54, 46, 38, 30, 22, 14, 6,
                                  64, 56, 48, 40, 32, 24, 16, 8,
                                  57, 49, 41, 33, 25, 17, 9, 1,
                                  59, 51, 43, 35, 27, 19, 11, 3,
                                  61, 53, 45, 37, 29, 21, 13, 5,
                                  63, 55, 47, 39, 31, 23, 15, 7]
data_expansion_table = [32, 1, 2, 3, 4, 5,
                        4, 5, 6, 7, 8, 9,
                        8, 9, 10, 11, 12, 13,
                        12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21,
                        20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29,
                        28, 29, 30, 31, 32, 1]


# Extra function to make transpose table indexes correct to programming index table
def fix_indexes_for_table(table_to_fix):
    for i in range(0, len(table_to_fix)):
        table_to_fix[i] = table_to_fix[i] - 1


# Function to shift bits to left
def shift_bits(bits, round_number):
    val = key_shifts_table[round_number]
    first_bits = bitarray()
    for i in range(0, val):
        first_bits.append(bits[i])
    bits = bits[val:] + (bitarray('0') * val)
    for i in range(0, val):
        bits[len(bits) - val + i] = first_bits[i]
    return bits


# Function to xor key and dataset
def xor_bits(data, key):
    if len(data) != len(key):
        raise Exception("Data and key length mismatch")
    done = bitarray()
    for i in range(0, len(data)):
        done.append(data[i] ^ key[i])
    return done


# Change bits location in key according to transpose table
def permute_bits(bits, transpose_table, row_size):
    permuted_bits = bitarray()
    for i in range(0, 8):
        bits_to_parity_check = bitarray()
        for j in range(0, row_size):
            permuted_bits.append(bits[transpose_table[(row_size * i) + j]])
            bits_to_parity_check.append(bits[transpose_table[(row_size * i) + j]])
    return permuted_bits


# Where DES magic happens
def process(in_data, key):
    # First key permute and shift
    key = permute_bits(key, key_transpose_table_pc1, 7)
    key_left = key[0:28]
    key_right = key[28:56]
    keys = []
    # Generate round sub keys
    for i in range(0, 16):
        key_left = shift_bits(key_left, i)
        key_right = shift_bits(key_right, i)
        keys.append(key_left + key_right)

        # Second key permute
        keys[i] = permute_bits(keys[i], key_transpose_table_pc2, 6)

    in_data = permute_bits(in_data, data_initial_permutation_table, 8)
    in_data_left = in_data[0:32]
    in_data_right = in_data[32:64]

    # Expansion
    in_data_right = permute_bits(in_data_right, data_expansion_table, 6)
    in_data_right_set = []
    # XOR
    for i in range(0, 16):
        in_data_right_set.append(xor_bits(in_data_right, keys[i]))

    # TODO: Substitution and rest

    return in_data


if __name__ == '__main__':
    # Tables indexes fix
    fix_indexes_for_table(key_transpose_table_pc1)
    fix_indexes_for_table(key_transpose_table_pc2)
    fix_indexes_for_table(data_initial_permutation_table)
    fix_indexes_for_table(data_expansion_table)

    key_values = bitarray()
    in_data_values = bitarray()
    key_values.frombytes(bytes("1234abcd", encoding="ascii"))
    in_data_values.frombytes(bytes("almakota", encoding="ascii"))
    out_data_values = process(in_data_values, key_values)
    print("Done")
