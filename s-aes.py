"""Implementacao do algoritimo S-AES"""

import numpy as np

s_box = np.array([
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
])

inv_s_box = np.array([
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
])

mc_matrix = np.array([ # Matriz MixColumns
    [0x1, 0x4],
    [0x4, 0x1]
])

inv_mc_matrix = np.array([ # Matriz MixColumns inversa
    [0x9, 0x2],
    [0x2, 0x9]
])

def to_matrix(pre_matrix, size):
    """Funcao para transformar em matriz"""
    matrix = np.array(pre_matrix).reshape(size, size)
    return matrix

def add_round_key(state_matrix, key_matrix):
    """Funcao AddRoundKey"""
    result = np.bitwise_xor(state_matrix, key_matrix)
    print(f"AddRoundKey Result:\n{result}")
    return result

def substitute_nibbles(state_matrix):
    """Funcao SubstituteNibbles"""
    result  = np.zeros_like(state_matrix) #Matriz final

    """Iterando sobre a matriz"""
    for i in range(state_matrix.shape[0]):
        for j in range(state_matrix.shape[1]):
            row = (state_matrix[i, j] >> 2) & 0x3 #Pega os 2 MSB
            col = state_matrix[i, j] & 0x3 #Pega os 2 LSB

            """Posicionando na matriz final faazendo lookup do LSB e MSB na s_box"""
            result[i, j] = s_box[row, col]

    print(f"SubstituteNibbles Result:\n{result}")
    return result

def inv_substitute_nibbles(state_matrix):
    """Funcao InverseSubstituteNibbles para decriptação"""
    result = np.zeros_like(state_matrix)

    for i in range(state_matrix.shape[0]):
        for j in range(state_matrix.shape[1]):
            row = (state_matrix[i, j] >> 2) & 0x3
            col = state_matrix[i, j] & 0x3
            result[i, j] = inv_s_box[row, col]

    print(f"InvSubstituteNibbles Result:\n{result}")
    return result

def shift_rows(state_matrix):
    """Funcao ShiftRows"""
    result = np.zeros_like(state_matrix) #Matriz final

    """Iterando sobre a matriz"""
    for i in range(state_matrix.shape[0]):
        for j in range(state_matrix.shape[1]):
            result[i, j] = state_matrix[i, (j + i) % state_matrix.shape[1]]

    print(f"ShiftRows Result:\n{result}")
    return result

def inv_shift_rows(state_matrix):
    """Funcao InverseShiftRows para decriptação"""
    result = np.zeros_like(state_matrix)

    for i in range(state_matrix.shape[0]):
        for j in range(state_matrix.shape[1]):
            result[i, j] = state_matrix[i, (j - i) % state_matrix.shape[1]]

    print(f"InvShiftRows Result:\n{result}")
    return result

def gf_mult(a, b):
    """Multiplicação no GF"""
    p = 0
    for i in range(4):  # 4 bits for S-AES
        if (b & 1) == 1:
            p ^= a
        high_bit = a & 0x8
        a <<= 1
        if high_bit:
            a ^= 0x13  # x^4 + x + 1 (0b10011)
        b >>= 1
        a &= 0xF  # Keep within 4 bits
    return p

def mix_columns(state_matrix):
    """Funcao MixColumns"""
    result = np.zeros_like(state_matrix)

    """Iterando sobre a matriz e multiplicação no GF"""
    for j in range(state_matrix.shape[1]):
        for i in range(state_matrix.shape[0]):
            result[i, j] = gf_mult(mc_matrix[i, 0], state_matrix[0, j]) ^ gf_mult(mc_matrix[i, 1], state_matrix[1, j])

    print(f"MixColumns Result:\n{result}")
    return result

def inv_mix_columns(state_matrix):
    """Funcao InverseMixColumns para decriptação"""
    result = np.zeros_like(state_matrix)

    for j in range(state_matrix.shape[1]):
        for i in range(state_matrix.shape[0]):
            result[i, j] = gf_mult(inv_mc_matrix[i, 0], state_matrix[0, j]) ^ gf_mult(inv_mc_matrix[i, 1], state_matrix[1, j])

    print(f"InvMixColumns Result:\n{result}")
    return result

def key_expansion(key):
    """Funcao para expansão da chave"""
    # Constantes
    rcon1 = 0x80
    rcon2 = 0x30

    # Extrair w0
    w0 = (key[0, 0] << 4) | key[0, 1]

    # Extrair w1
    w1 = (key[1, 0] << 4) | key[1, 1]

    # Primeira rodada de expansão
    # Rotacionar w1
    rot_w1 = ((w1 & 0x0F) << 4) | ((w1 & 0xF0) >> 4)

    # Aplicar SubNib
    sub_w1_high = s_box[(rot_w1 >> 6) & 0x3, (rot_w1 >> 4) & 0x3]
    sub_w1_low = s_box[(rot_w1 >> 2) & 0x3, rot_w1 & 0x3]
    sub_w1 = (sub_w1_high << 4) | sub_w1_low

    # Calcular w2
    w2 = w0 ^ rcon1 ^ sub_w1

    # Calcular w3
    w3 = w1 ^ w2

    # Segunda rodada de expansão
    # Rotacionar w3
    rot_w3 = ((w3 & 0x0F) << 4) | ((w3 & 0xF0) >> 4)

    # Aplicar SubNib
    sub_w3_high = s_box[(rot_w3 >> 6) & 0x3, (rot_w3 >> 4) & 0x3]
    sub_w3_low = s_box[(rot_w3 >> 2) & 0x3, rot_w3 & 0x3]
    sub_w3 = (sub_w3_high << 4) | sub_w3_low

    # Calcular w4
    w4 = w2 ^ rcon2 ^ sub_w3

    # Calcular w5
    w5 = w3 ^ w4

    # Construir chaves de rodada
    k0 = key.copy()

    k1 = np.array([
        [(w2 >> 4) & 0xF, w2 & 0xF],
        [(w3 >> 4) & 0xF, w3 & 0xF]
    ])

    k2 = np.array([
        [(w4 >> 4) & 0xF, w4 & 0xF],
        [(w5 >> 4) & 0xF, w5 & 0xF]
    ])

    print(f"Key Schedule:")
    print(f"K0:\n{k0}")
    print(f"K1:\n{k1}")
    print(f"K2:\n{k2}")

    return k0, k1, k2

def encrypt(plaintext, key):
    """Função de criptografia S-AES"""
    print("\nencrypt ----------------------")

    k0, k1, k2 = key_expansion(key)

    print(f"\nPlaintext:\n{plaintext}")

    print("\n-> Rodada Inicial")
    state = add_round_key(plaintext, k0)

    print("\n-> Rodada 1")
    state = substitute_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, k1)

    print("\n-> Rodada 2")
    state = substitute_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, k2)

    print(f"\nCiphertext:\n{state}")
    return state

def decrypt(ciphertext, key):
    """Função de decriptação S-AES"""
    print("\ndecrypt ----------------------")

    k0, k1, k2 = key_expansion(key)

    print(f"\nCiphertext:\n{ciphertext}")

    print("\n-> Rodada Inicial")
    state = add_round_key(ciphertext, k2)

    print("\n-> Rodada 1")
    state = inv_shift_rows(state)
    state = inv_substitute_nibbles(state)
    state = add_round_key(state, k1)
    state = inv_mix_columns(state)

    print("\n-> Rodada 2")
    state = inv_shift_rows(state)
    state = inv_substitute_nibbles(state)
    state = add_round_key(state, k0)

    print(f"\nPlaintext recuperado:\n{state}")
    return state

if __name__ == "__main__":
    print("\n===== IMPLEMENTAÇÃO DO S-AES =====")

    # Estado
    plaintext = [0x6, 0xF, 0x6, 0xB]
    plaintext = to_matrix(plaintext, 2)

    # Chave
    key = [0xA, 0x7, 0x3, 0xB]
    key = to_matrix(key, 2)

    print(f"\nPlaintext original:\n{plaintext}")
    print(f"Chave:\n{key}")

    # Criptografar
    ciphertext = encrypt(plaintext, key)

    # Decriptografar
    decrypted = decrypt(ciphertext, key)

    # Verificar se a decriptação foi bem-sucedida
    if np.array_equal(plaintext, decrypted):
        print("\nSucesso - texto igual ao original")
    else:
        print("\nErro - texto diferente do original")