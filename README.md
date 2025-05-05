# Implementação em Python do S-AES
---
## Funcionalidades

- **Criptografia e Decriptografia**: Implementação completa do algoritmo S-AES para cifrar e decifrar dados
- **Operações Principais**: 
  - SubNibbles (usando S-Box 4x4)
  - ShiftRows
  - MixColumns (campo GF(2^4))
  - AddRoundKey
- **Modo de operação**: ECB (Electronic Codebook)
- **Formatos de saída**: Hexadecimal e Base64

## Principais Componentes do Código

### SubNibbles
Substitui cada nibble (4 bits) usando uma S-Box pré-definida:
```python
def sub_nibbles(state, box=S_BOX):
    result = np.zeros_like(state)
    for i in range(state.shape[0]):
        for j in range(state.shape[1]):
            row = (state[i, j] >> 2) & 0x3  # 2 MSB
            col = state[i, j] & 0x3         # 2 LSB
            result[i, j] = box[row, col]
    return result
```
### ShiftRows
Desloca os nibbles de cada linha da matriz de estado:
```python
def shift_rows(state, inverse=False):
    result = np.zeros_like(state)
    for i in range(state.shape[0]):
        for j in range(state.shape[1]):
            if not inverse:
                result[i, j] = state[i, (j + i) % state.shape[1]]
            else:
                result[i, j] = state[i, (j - i) % state.shape[1]]
    return result
```

### MixColumns
Mistura os dados de cada coluna usando multiplicação no campo GF(2⁴):
```python
def mix_columns(state, matrix=MC_MATRIX):
    result = np.zeros_like(state)
    for j in range(state.shape[1]):
        for i in range(state.shape[0]):
            result[i, j] = gf_mult(matrix[i, 0], state[0, j]) ^ gf_mult(matrix[i, 1], state[1, j])
    return result
```

### AddRoundKey
Realiza XOR entre o state e a chave da rodada:
```python
def add_round_key(state, key):
    return np.bitwise_xor(state, key)
```

### KeyExpansion
Gera as chaves de cada rodada:
```python
def key_expansion(key):
    # Extrai w0 e w1 da chave original
    w0 = (key[0, 0] << 4) | key[0, 1]
    w1 = (key[1, 0] << 4) | key[1, 1]
    
    # Calcula as demais palavras (w2 a w5)
    # ...
    
    # Retorna as três chaves de rodada
    return k0, k1, k2
```
---
### Criptografia e Decriptografia
As funções "encrypt" e "decrypt" implementam o processo de criptografia e decriptografia, respectivamente. Elas utilizam as funções acima para realizar as operações necessárias em cada rodada.

---
## COMPARATIVO ENTRE S-AES E AES
### S-AES:
- Tamanho de bloco: 16 bits (matriz 2x2 de nibbles)
- Tamanho de chave: 16 bits
- Número de rodadas: 2
- S-Box: Simplificada (4x4)
- MixColumns: Matriz 2x2 no campo GF(2^4)

### AES:
- Tamanho de bloco: 128 bits (matriz 4x4 de bytes)
- Tamanho de chave: 128, 192 ou 256 bits
- Número de rodadas: 10, 12 ou 14 (dependendo do tamanho da chave)
- S-Box: Completa (256 valores)
- MixColumns: Matriz 4x4 no campo GF(2^8)
---
## Parte 2 - Modo de Operação ECB
```python
def encrypt_saes_ecb(message, key):
    # Converte a mensagem para nibbles e divide em blocos
    nibbles = string_to_nibbles(message)
    
    # Para cada bloco
    for i in range(0, len(nibbles), block_size * block_size):
        block = nibbles[i:i + block_size * block_size]
        block_matrix = to_matrix(block, block_size)
        
        # Criptografa o bloco
        encrypted_block = encrypt(block_matrix, key_matrix)
        encrypted_blocks.extend(matrix_to_nibbles(encrypted_block))
    
    return {
        "encrypted_nibbles": encrypted_blocks,
        "hex": nibbles_to_hex(encrypted_blocks),
        "base64": nibbles_to_base64(encrypted_blocks)
    }
```

### Limitação do Modo ECB

No modo ECB (Electronic Codebook), blocos de texto idênticos produzem blocos cifrados idênticos. Esta característica é demonstrada no teste 3 com a mensagem "AESAES".

Esta limitação torna o modo ECB inadequado para muitas aplicações reais, pois padrões no texto original podem ser identificados no texto cifrado, comprometendo a segurança.

---
## Demonstração

O programa inclui três testes de demonstração:
1. Criptografar e decriptografar um único bloco
2. Criptografar e decriptografar uma string simples
3. Demonstração da vulnerabilidade do modo ECB
