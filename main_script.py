import time
from rsa_utils import (
    generate_rsa_keys, 
    sign_data, 
    verify_signature,
    TRNG
)
from cryptography.hazmat.primitives import serialization

def main():
    start_time = time.time()

    first_xor_bytes = TRNG('nature.jpeg')
    second_xor_bytes = TRNG('mountains.jpg')
    
    first_public_key, first_private_key = generate_rsa_keys(first_xor_bytes)
    second_public_key, second_private_key = generate_rsa_keys(second_xor_bytes)


    first_rsa_public_key = first_public_key.public_key()
    first_rsa_private_key = first_private_key.private_key()

    second_rsa_public_key = second_public_key.public_key()
    second_rsa_private_key = second_private_key.private_key()

    print("public_key: ", (first_public_key.e, first_public_key.n))
    print("\n")
    print("private_key: ", (first_private_key.d, first_private_key.public_numbers.n))

    # Eksportowanie klucza publicznego do formatu PEM
    public_pem = first_rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

    # Eksportowanie klucza prywatnego do formatu PEM
    private_pem = first_rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)

    # Podpisywanie danych
    message = b'Secret message.'
    signature = sign_data(first_rsa_private_key, message)

    # Weryfikacja poprawnego podpisu
    valid = verify_signature(first_rsa_public_key, message, signature)
    print("Signature valid:", valid)

    # Zmiana treści wiadomości
    altered_message = b'Secred message.'
    altered_valid = verify_signature(first_rsa_public_key, altered_message, signature)
    print("Signature valid after message change:", altered_valid)

    # Weryfikacja podpisu przy użyciu innego klucza publicznego
    different_key_valid = verify_signature(second_rsa_public_key, message, signature)
    print("Signature valid with different public key:", different_key_valid)

    end_time = time.time()
    exec_time = end_time - start_time
    print("total execution time: ", round(exec_time,2), " seconds")

if __name__ == '__main__':
    main()
