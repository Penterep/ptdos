import numpy as np

def create_base_matrices():
    M0 = np.zeros((33, 33), dtype=np.int8)
    M1 = np.zeros((33, 33), dtype=np.int8)
    for i in range(32):
        if i > 0:
            M0[i-1, i] = 1
            M1[i-1, i] = 1
        if (0xedb88320 >> i) & 1:
            M0[i, 0] = 1
            M1[i, 0] = 1
            M1[i, 32] = 1
    M0[32, 32] = 1
    M1[32, 32] = 1
    return M0, M1

def gf2_matmul(A, B):
    return np.dot(A, B) % 2

def build_data_matrix(data: bytes):
    """Converts any string of bytes into its exact CRC-32 state change matrix."""
    M0, M1 = create_base_matrices()
    M_data = np.eye(33, dtype=np.int8)
    
    for byte in data:
        for i in range(8):
            bit = (byte >> i) & 1
            M_data = gf2_matmul(M1 if bit == 1 else M0, M_data)
            
    return M_data

def get_final_crc(M):
    """Applies pre- and post-conditioning to get the final integer."""
    initial_vector = np.ones(33, dtype=np.int8)
    final_state_vector = gf2_matmul(M, initial_vector)
    crc_result = sum(int(bit) << i for i, bit in enumerate(final_state_vector[:32]))
    return crc_result ^ 0xFFFFFFFF

def build_kernel_matrix(size_MB):
    M0, M1 = create_base_matrices()
    bits = [1, 0, 0, 0, 0, 1, 1, 0] 
    M_a = np.eye(33, dtype=np.int8)
    for bit in bits:
        M_a = gf2_matmul(M1 if bit == 1 else M0, M_a)
    M_kernel = gf2_matrix_pow(M_a, 1024*1024*size_MB)

    return M_kernel

def gf2_matrix_pow(M, power):
    """Exponentiation by squaring using NumPy."""
    result = np.eye(33, dtype=np.int8)
    base = M.copy()
    while power > 0:
        if power % 2 == 1:
            result = gf2_matmul(result, base)
        base = gf2_matmul(base, base)
        power //= 2
    return result