"""
Github:
Based on:
https://www.comparitech.com/blog/information-security/3des-encryption/
https://en.wikipedia.org/wiki/DES_supplementary_material
https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm
https://www.youtube.com/watch?v=Sy0sXa73PZA
"""

from bitarray import bitarray
import struct
import PySimpleGUI as Sg

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
permutation_table = [16, 7, 20, 21,
                     29, 12, 28, 17,
                     1, 15, 23, 26,
                     5, 18, 31, 10,
                     2, 8, 24, 14,
                     32, 27, 3, 9,
                     19, 13, 30, 6,
                     22, 11, 4, 25]
final_permutation_table = [40, 8, 48, 16, 56, 24, 64, 32,
                           39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30,
                           37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28,
                           35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26,
                           33, 1, 41, 9, 49, 17, 57, 25]
# S-boxes table [box_number][row_number][column_number]
s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
          [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
          [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
          [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
         [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
          [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
          [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
          [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
         [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
          [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
          [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
          [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
         [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
          [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
          [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
          [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
         [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
          [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
          [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
          [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
         [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
         [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
          [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
          [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
          [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]


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
        for j in range(0, row_size):
            permuted_bits.append(bits[transpose_table[(row_size * i) + j]])
    return permuted_bits


# Substitution-box
def substitute(data):
    done = bitarray()
    for i in range(0, 8):
        data_chunk = data[i * 6:i * 6 + 6]
        row_num = bitarray('0' * 6)
        row_num.append(data_chunk[0])
        row_num.append(data_chunk[5])
        row_num = struct.unpack("<B", row_num)[0]  # struct module requires 8 bit number do decode
        col_num = bitarray('0' * 4)
        col_num.append(data_chunk[1])
        col_num.append(data_chunk[2])
        col_num.append(data_chunk[3])
        col_num.append(data_chunk[4])
        col_num = struct.unpack("<B", col_num)[0]  # struct module requires 8 bit number do decode
        s_value = s_box[i][row_num][col_num]
        s_value = f'{s_value:08b}'  # f-string formatting
        done.append(int(s_value[4]))
        done.append(int(s_value[5]))
        done.append(int(s_value[6]))
        done.append(int(s_value[7]))
    return done


# Where DES encryption magic happens
def encrypt(data, key):
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

    data = permute_bits(data, data_initial_permutation_table, 8)
    in_data_left = data[0:32]
    in_data_right = data[32:64]

    for i in range(0, 16):
        # One round data mix with sub key
        new_data = permute_bits(in_data_right, data_expansion_table, 6)
        new_data = xor_bits(new_data, keys[i])
        new_data = substitute(new_data)
        new_data = permute_bits(new_data, permutation_table, 4)
        new_data = xor_bits(new_data, in_data_left)
        in_data_left = in_data_right
        in_data_right = new_data

    data = bitarray('0' * 64)
    data[0:32] = in_data_right
    data[32:64] = in_data_left
    data = permute_bits(data, final_permutation_table, 8)

    out = ''
    for i in range(0, 8):
        val = data[i * 8: i * 8 + 8]
        val = struct.unpack("<B", val)[0]
        tmp = hex(val)
        if len(tmp) != 4:
            out += "0" + tmp[2]
        else:
            out += tmp[2:4]
    return out


# Where DES decryption magic happens
def decrypt(data, key):
    bits_tmp = bitarray()
    for i in range(0, len(data), 2):
        tmp = "0x" + data[0 + i:2 + i]
        tmp = int(tmp, 16)
        tmp = bin(tmp)
        tmp = tmp[2:10]
        if len(tmp) < 8:
            diff = 8 - len(tmp)
            zeros = ''
            for j in range(0, diff):
                zeros += "0"
            tmp = zeros + tmp
        if len(tmp) != 8:
            raise Exception("Hex conversion error")
        for j in range(0, 8):
            bits_tmp.append(int(tmp[j]))
    data = bits_tmp

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

    data = permute_bits(data, data_initial_permutation_table, 8)
    in_data_left = data[0:32]
    in_data_right = data[32:64]

    for i in range(0, 16):
        # One round data mix with sub key
        new_data = permute_bits(in_data_right, data_expansion_table, 6)
        new_data = xor_bits(new_data, keys[15 - i])
        new_data = substitute(new_data)
        new_data = permute_bits(new_data, permutation_table, 4)
        new_data = xor_bits(new_data, in_data_left)
        in_data_left = in_data_right
        in_data_right = new_data

    data = bitarray('0' * 64)
    data[0:32] = in_data_right
    data[32:64] = in_data_left
    data = permute_bits(data, final_permutation_table, 8)

    out = ''
    for i in range(0, 8):
        val = data[i * 8: i * 8 + 8]
        val = struct.unpack("<B", val)[0]
        out += chr(val)
    return out


if __name__ == '__main__':
    # Tables indexes fix
    fix_indexes_for_table(key_transpose_table_pc1)
    fix_indexes_for_table(key_transpose_table_pc2)
    fix_indexes_for_table(data_initial_permutation_table)
    fix_indexes_for_table(data_expansion_table)
    fix_indexes_for_table(permutation_table)
    fix_indexes_for_table(final_permutation_table)

    Sg.theme('Dark Blue 3')  # please make your windows colorful

    col = [[Sg.Text('Text (in lowercase hex to decode):', size=(26, 1)), Sg.InputText(key='text', size=(32, 1))],
           [Sg.Text('Key (8 ascii characters):', size=(26, 1)), Sg.InputText(key='key', size=(32, 1))],
           [Sg.Text('Result:', size=(26, 1)), Sg.InputText(key="out", size=(32, 1))]]
    layout = [[Sg.Column(col)], [Sg.Button("Encrypt"), Sg.Button("Decrypt")]]

    window = Sg.Window('DES (ascii only)', layout)

    while True:
        event, values = window.read(10)
        if event is Sg.WIN_CLOSED:
            break
        if event == "Encrypt":
            window['text'].Update(background_color="white")
            window['key'].Update(background_color="white")
            val_ok = True
            if len(values['key']) != 8:
                window['key'].Update(background_color="red")
                val_ok = False
            if val_ok:
                encrypted = ''
                text = values["text"]
                blocks = len(text)
                if blocks % 8 != 0:
                    blocks = int(blocks/8) + 1
                    padding = int(8 - (blocks % 8))
                    for block in range(0, padding):
                        text += "\0"
                else:
                    blocks = int(blocks / 8)
                in_key = bitarray()
                try:
                    in_key.frombytes(bytes(values["key"], encoding="ascii"))
                except UnicodeEncodeError:
                    window['key'].Update(background_color="red")
                    continue
                no_print = False
                for block in range(0, blocks):
                    value = bitarray()
                    try:
                        value.frombytes(bytes(text[0 + block * 8: 8 + block * 8], encoding="ascii"))
                    except UnicodeEncodeError:
                        window['text'].Update(background_color="red")
                        no_print = True
                        break
                    encrypted += encrypt(value, in_key)
                if not no_print:
                    window['out'].Update(value=encrypted)

        if event == "Decrypt":
            window['text'].Update(background_color="white")
            window['key'].Update(background_color="white")
            val_ok = True
            if len(values['key']) != 8:
                window['key'].Update(background_color="red")
                val_ok = False
            if len(values['text']) % 16 != 0:
                window['text'].Update(background_color="red")
                val_ok = False
            for letter in values['text']:
                if not (('0' <= letter <= '9') or ('a' <= letter <= 'f')):
                    val_ok = False
                    window['text'].Update(background_color="red")
            if val_ok:
                decrypted = ''
                text = values["text"]
                blocks = len(text)
                blocks = int(blocks / 16)
                in_key = bitarray()
                try:
                    in_key.frombytes(bytes(values["key"], encoding="ascii"))
                except UnicodeEncodeError:
                    window['key'].Update(background_color="red")
                    continue
                for block in range(0, blocks):
                    value = text[0 + block * 16: 16 + block * 16]
                    decrypted += decrypt(value, in_key)
                window['out'].Update(value=decrypted)

