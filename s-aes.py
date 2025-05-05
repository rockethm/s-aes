"""Implementação simplificada do algoritmo S-AES (Simplified AES)"""

import numpy as np
import base64

S_BOX = np.array([
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
])

INV_S_BOX = np.array([
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
])

# Matrizes para MixColumns
MC_MATRIX = np.array([
    [0x1, 0x4],
    [0x4, 0x1]
])

INV_MC_MATRIX = np.array([
    [0x9, 0x2],
    [0x2, 0x9]
])

# Constantes para KeyExpansion
RCON1 = 0x80
RCON2 = 0x30

def to_matrix(data, size):
    """Converte array para matriz de tamanho size x size"""
    return np.array(data).reshape(size, size)

def add_round_key(state, key):
    """Operação AddRoundKey: XOR entre state e key"""
    result = np.bitwise_xor(state, key)
    print(f"AddRoundKey Result:\n{result}")
    return result

def sub_nibbles(state, box=S_BOX):
    """Operação SubNibbles: substitui cada nibble usando a S-Box"""
    result = np.zeros_like(state)

    for i in range(state.shape[0]):
        for j in range(state.shape[1]):
            row = (state[i, j] >> 2) & 0x3  # 2 MSB
            col = state[i, j] & 0x3         # 2 LSB
            result[i, j] = box[row, col]

    print(f"SubNibbles Result:\n{result}")
    return result

def inv_sub_nibbles(state):
    """Operação inversa de SubNibbles"""
    return sub_nibbles(state, INV_S_BOX)

def shift_rows(state, inverse=False):
    """Operação ShiftRows: desloca linhas para a direita (ou esquerda se inverse=True)"""
    result = np.zeros_like(state)

    for i in range(state.shape[0]):
        for j in range(state.shape[1]):
            if not inverse:
                result[i, j] = state[i, (j + i) % state.shape[1]]
            else:
                result[i, j] = state[i, (j - i) % state.shape[1]]

    label = "InvShiftRows" if inverse else "ShiftRows"
    print(f"{label} Result:\n{result}")
    return result

def gf_mult(a, b):
    """Multiplicação em GF(2^4) com polinômio irredutível x^4 + x + 1"""
    p = 0
    for i in range(4):
        if (b & 1) == 1:
            p ^= a
        high_bit = a & 0x8
        a <<= 1
        if high_bit:
            a ^= 0x13  # x^4 + x + 1 (0b10011)
        b >>= 1
        a &= 0xF  # Mantém em 4 bits
    return p

def mix_columns(state, matrix=MC_MATRIX):
    """Operação MixColumns usando multiplicação em GF(2^4)"""
    result = np.zeros_like(state)

    for j in range(state.shape[1]):
        for i in range(state.shape[0]):
            result[i, j] = gf_mult(matrix[i, 0], state[0, j]) ^ gf_mult(matrix[i, 1], state[1, j])

    label = "InvMixColumns" if np.array_equal(matrix, INV_MC_MATRIX) else "MixColumns"
    print(f"{label} Result:\n{result}")
    return result

def inv_mix_columns(state):
    """Operação inversa de MixColumns"""
    return mix_columns(state, INV_MC_MATRIX)

def key_expansion(key):
    """Expande a chave de 16 bits para as chaves de rodada"""
    # Extrair w0 e w1 da chave original
    w0 = (key[0, 0] << 4) | key[0, 1]
    w1 = (key[1, 0] << 4) | key[1, 1]

    # Rodada 1
    rot_w1 = ((w1 & 0x0F) << 4) | ((w1 & 0xF0) >> 4)

    sub_w1_high = S_BOX[(rot_w1 >> 6) & 0x3, (rot_w1 >> 4) & 0x3]
    sub_w1_low = S_BOX[(rot_w1 >> 2) & 0x3, rot_w1 & 0x3]
    sub_w1 = (sub_w1_high << 4) | sub_w1_low

    w2 = w0 ^ RCON1 ^ sub_w1
    w3 = w1 ^ w2

    # Rodada 2
    rot_w3 = ((w3 & 0x0F) << 4) | ((w3 & 0xF0) >> 4)

    sub_w3_high = S_BOX[(rot_w3 >> 6) & 0x3, (rot_w3 >> 4) & 0x3]
    sub_w3_low = S_BOX[(rot_w3 >> 2) & 0x3, rot_w3 & 0x3]
    sub_w3 = (sub_w3_high << 4) | sub_w3_low

    w4 = w2 ^ RCON2 ^ sub_w3
    w5 = w3 ^ w4

    # Criar matrizes de chave
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
    """Criptografa um bloco de 16 bits usando S-AES"""
    print("\nCriptografando...")
    k0, k1, k2 = key_expansion(key)

    print(f"\nPlaintext:\n{plaintext}")

    print("\n-> Rodada 0")
    state = add_round_key(plaintext, k0)

    print("\n-> Rodada 1")
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, k1)

    print("\n-> Rodada 2")
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, k2)

    print(f"\nCiphertext:\n{state}")
    return state

def decrypt(ciphertext, key):
    """Decriptografa um bloco de 16 bits usando S-AES"""
    print("\nDecriptografando...")

    k0, k1, k2 = key_expansion(key)

    print(f"\nCiphertext:\n{ciphertext}")

    print("\n-> Rodada 0")
    state = add_round_key(ciphertext, k2)

    print("\n-> Rodada 1")
    state = shift_rows(state, inverse=True)
    state = inv_sub_nibbles(state)
    state = add_round_key(state, k1)
    state = inv_mix_columns(state)

    print("\n-> Rodada 2")
    state = shift_rows(state, inverse=True)
    state = inv_sub_nibbles(state)
    state = add_round_key(state, k0)

    print(f"\nPlaintext recuperado:\n{state}")
    return state

def string_to_nibbles(text):
    """Converte string para array de nibbles (4 bits)"""
    nibbles = []
    for byte in text.encode('utf-8'):
        nibbles.append((byte >> 4) & 0xF)  # Nibble superior
        nibbles.append(byte & 0xF)         # Nibble inferior
    return nibbles

def nibbles_to_bytes(nibbles):
    """Converte array de nibbles para bytes"""
    byte_array = bytearray()
    for i in range(0, len(nibbles), 2):
        if i + 1 < len(nibbles):
            byte_val = (nibbles[i] << 4) | nibbles[i + 1]
            byte_array.append(byte_val)
        else:
            byte_val = (nibbles[i] << 4)
            byte_array.append(byte_val)
    return bytes(byte_array)

def nibbles_to_hex(nibbles):
    """Converte array de nibbles para string hexadecimal"""
    bytes_data = nibbles_to_bytes(nibbles)
    return bytes_data.hex()

def nibbles_to_base64(nibbles):
    """Converte array de nibbles para string base64"""
    bytes_data = nibbles_to_bytes(nibbles)
    return base64.b64encode(bytes_data).decode('utf-8')

def matrix_to_nibbles(matrix):
    """Converte matriz para array de nibbles"""
    nibbles = []
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            nibbles.append(int(matrix[i, j]))
    return nibbles

def encrypt_saes_ecb(message, key):
    """Criptografa uma mensagem usando S-AES no modo ECB"""
    block_size = 2
    nibbles = string_to_nibbles(message)

    # Padding se necessário
    if len(nibbles) % (block_size * block_size) != 0:
        padding = (block_size * block_size) - (len(nibbles) % (block_size * block_size))
        nibbles.extend([0] * padding)

    print(f"Mensagem em nibbles (com padding): {nibbles}")
    print(f"Total de blocos: {len(nibbles) // (block_size * block_size)}")

    key_matrix = to_matrix(key, block_size)
    encrypted_blocks = []

    # ECB
    for i in range(0, len(nibbles), block_size * block_size):
        block = nibbles[i:i + block_size * block_size]
        block_matrix = to_matrix(block, block_size)

        print(f"\nProcessando bloco ECB {i // (block_size * block_size) + 1}:")
        print(f"Bloco em formato de matriz:\n{block_matrix}")

        encrypted_block = encrypt(block_matrix, key_matrix)
        encrypted_nibbles = matrix_to_nibbles(encrypted_block)
        encrypted_blocks.extend(encrypted_nibbles)

    hex_result = nibbles_to_hex(encrypted_blocks)
    base64_result = nibbles_to_base64(encrypted_blocks)

    print(f"\nResultado da criptografia ECB (nibbles): {encrypted_blocks}")
    print(f"Resultado em Hexadecimal: {hex_result}")
    print(f"Resultado em Base64: {base64_result}")

    return {
        "encrypted_nibbles": encrypted_blocks,
        "hex": hex_result,
        "base64": base64_result
    }

def decode_from_hex(hex_str):
    """Decodifica string hexadecimal para array de nibbles"""
    nibbles = []
    for i in range(0, len(hex_str), 2):
        if i + 1 < len(hex_str):
            byte = int(hex_str[i:i+2], 16)
            nibbles.append((byte >> 4) & 0xF)
            nibbles.append(byte & 0xF)
        else:
            nibble = int(hex_str[i], 16)
            nibbles.append(nibble)
    return nibbles

def decode_from_base64(base64_str):
    """Decodifica string base64 para array de nibbles"""
    data_bytes = base64.b64decode(base64_str)
    nibbles = []
    for byte in data_bytes:
        nibbles.append((byte >> 4) & 0xF)
        nibbles.append(byte & 0xF)
    return nibbles

def decrypt_saes_ecb(encrypted_data, key, input_format="base64"):
    """Decriptografa dados usando S-AES no modo ECB"""
    block_size = 2

    # Decodificar dados de entrada
    if input_format.lower() == "base64":
        nibbles = decode_from_base64(encrypted_data)
        print(f"Decodificado de Base64: {nibbles}")
    elif input_format.lower() == "hex":
        nibbles = decode_from_hex(encrypted_data)
        print(f"Decodificado de Hexadecimal: {nibbles}")
    else:
        nibbles = encrypted_data  # Assumindo que já são nibbles

    print(f"Total de blocos criptografados: {len(nibbles) // (block_size * block_size)}")

    key_matrix = to_matrix(key, block_size)
    decrypted_blocks = []

    # ECB
    for i in range(0, len(nibbles), block_size * block_size):
        block = nibbles[i:i + block_size * block_size]

        # Padding se necessário
        if len(block) < block_size * block_size:
            block = block + [0] * (block_size * block_size - len(block))

        block_matrix = to_matrix(block, block_size)

        print(f"\nProcessando bloco ECB cifrado {i // (block_size * block_size) + 1}:")
        print(f"Bloco em formato de matriz:\n{block_matrix}")

        decrypted_block = decrypt(block_matrix, key_matrix)
        decrypted_nibbles = matrix_to_nibbles(decrypted_block)
        decrypted_blocks.extend(decrypted_nibbles)

    # Converter de volta para texto
    decrypted_bytes = nibbles_to_bytes(decrypted_blocks)
    try:
        decrypted_text = decrypted_bytes.decode('utf-8').rstrip('\x00')
    except UnicodeDecodeError:
        decrypted_text = decrypted_bytes.hex()

    print(f"\nResultado da decriptografia ECB (nibbles): {decrypted_blocks}")
    print(f"Mensagem decifrada: '{decrypted_text}'")

    return {
        "decrypted_nibbles": decrypted_blocks,
        "decrypted_text": decrypted_text
    }

def main():
    # Teste 1 -------------------------------------
    print("\n1 -> Criptografar e decriptografar um bloco")

    plaintext = [0x3, 0x1, 0xF, 0xB]
    plaintext = to_matrix(plaintext, 2)

    key = [0x7, 0x4, 0x1, 0x9]
    key = to_matrix(key, 2)

    print(f"\nPlaintext original:\n{plaintext}")
    print(f"Chave:\n{key}")

    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)

    if np.array_equal(plaintext, decrypted):
        print("\nSucesso!")
    else:
        print("\nErro")

    # Teste 2 ---------------------------------------
    print("\n2-> Criptografar e decriptografar uma string")
    message = "OK"
    key_nibbles = [0x7, 0x4, 0x1, 0x9]

    print(f"Mensagem: '{message}'")
    print(f"Chave (nibbles): {key_nibbles}")

    encrypted = encrypt_saes_ecb(message, key_nibbles)
    decrypted = decrypt_saes_ecb(encrypted["base64"], key_nibbles)

    # Teste 3 ---------------------------------------
    print("\n3-> Fraqueza do modo ECB")
    message_repetido = "AESAES"  # Mensagem com blocos repetidos

    print(f"Mensagem com blocos repetidos: '{message_repetido}'")
    encrypted_rep = encrypt_saes_ecb(message_repetido, key_nibbles)


if __name__ == "__main__":
    main()