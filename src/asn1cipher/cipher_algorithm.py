from abc import ABC

from asn1crypto.algos import EncryptionAlgorithm

from .block_cipher import BlockCipher
from .rc2_cipher import RC2Cipher
from .cipher_adapter import TripleDESCipher, AESCipher

class CipherAlgorithm(ABC):
    @property
    def name(self) -> str:
        ...

    @property
    def block_mode(self) -> str:
        return 'cbc'

    def create(self, key: bytes) -> BlockCipher:
        ...

    def override_key_size(self) -> int:
        return 0

    def get_iv(self, encryption_scheme: EncryptionAlgorithm) -> bytes:
        return encryption_scheme.encryption_iv

class DESCipherAlgorithm(CipherAlgorithm):
    @property
    def name(self) -> str:
        return "des"

    def create(self, key: bytes) -> BlockCipher:
        return TripleDESCipher(key)

class TripleDESCipherAlgorithm(CipherAlgorithm):
    @property
    def name(self) -> str:
        return "tripledes"

    def create(self, key: bytes) -> BlockCipher:
        return TripleDESCipher(key)

class RC2CipherAlgorithm(CipherAlgorithm):
    @property
    def name(self) -> str:
        return "rc2"

    def create(self, key: bytes) -> BlockCipher:
        return RC2Cipher(key)

class AESCipherAlgorithm(CipherAlgorithm):
    @property
    def name(self) -> str:
        return "aes"

    def create(self, key: bytes) -> BlockCipher:
        return AESCipher(key)
