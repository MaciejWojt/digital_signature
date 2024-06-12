from PIL import Image
import numpy as np
import sympy
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def logistic_map(x, r=4):
    return r * x * (1 - x)

def generate_random_sequence(x_0, r, iterations, discard=250):
    x = x_0
    for _ in range(discard):
        x = logistic_map(x, r)
    sequence = []
    for _ in range(iterations):
        x = logistic_map(x, r)
        sequence.append(x)
    return sequence

def permute_image(image, sequence):
    flat_image = np.array(image).flatten()
    indices = np.argsort(sequence)
    permuted_image = flat_image[indices]
    return Image.fromarray(permuted_image.reshape(image.size))

def generate_bit_sequence(chaotic_sequence, threshold=0.5):
    return [1 if x > threshold else 0 for x in chaotic_sequence]

def xor_bit_planes(bit_planes, chaotic_sequences):
    result = np.zeros_like(bit_planes[0])
    for plane, seq in zip(bit_planes, chaotic_sequences):
        result = np.bitwise_xor(result, plane & np.array(seq, dtype=int))
    return result

def generate_large_prime(bits, random_sequence):
    assert len(random_sequence) >= bits, "Sekwencja losowa jest zbyt krótka"
    random_bits = (np.array(random_sequence[:bits]) > 0.5).astype(int)
    candidate = int(''.join(map(str, random_bits)), 2)
    prime = sympy.nextprime(candidate)
    return prime

def generate_rsa_keys(random_sequence, bits=2048):
    p = generate_large_prime(bits // 2, random_sequence[:bits // 2])
    q = generate_large_prime(bits // 2, random_sequence[bits // 2:bits])
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = sympy.mod_inverse(e, phi)
    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(
        p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q), public_numbers
    )
    return public_numbers, private_numbers

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False

def TRNG(path):
    image_path = path
    image = Image.open(image_path).convert('L')
    data = np.array(image)
  
    initial_values = [0.361,0.362,0.363,0.364,0.365,0.366,0.367,0.368,0.369]
    iterations = data.size
    chaotic_sequences = [generate_random_sequence(x_0, 4, iterations) for x_0 in initial_values]

    permuted_image = permute_image(image, chaotic_sequences[0])

    bit_sequences = [generate_bit_sequence(seq) for seq in chaotic_sequences]

    bit_planes = [((np.array(permuted_image) >> i) & 1).flatten() for i in range(8)]

    xor_result = xor_bit_planes(bit_planes, bit_sequences[1:9])
    
    xor_bytes = np.packbits(xor_result)

    return xor_bytes