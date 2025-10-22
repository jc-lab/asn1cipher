"""기본 사용 예제"""

from asn1cipher import Provider
from asn1crypto.algos import EncryptionAlgorithm, Pbes1Params
import os

def main():
    provider = Provider()

    # Data to encrypt and password
    plaintext = b"Hello, World! This is a secret message."
    password = "my_secret_password"

    # Configure PBES1 (SHA1 + DES) algorithm
    encryption_algorithm = EncryptionAlgorithm({
        'algorithm': 'pbes1_sha1_des',
        'parameters': Pbes1Params({
            'salt': os.urandom(8),
            'iterations': 10000,
        })
    })

    # Encrypt
    encrypted_content_info = provider.encrypt(
        plaintext=plaintext,
        password=password,
        encryption_algorithm=encryption_algorithm
    )

    # Decrypt
    decrypted = provider.decrypt(
        encrypted_content_info=encrypted_content_info,
        password=password
    )

    assert decrypted == plaintext
    print("✓ Encryption/decryption successful!")

if __name__ == "__main__":
    main()