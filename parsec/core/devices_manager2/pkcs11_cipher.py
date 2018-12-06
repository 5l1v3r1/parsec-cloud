from json import JSONDecodeError

from parsec.schema import UnknownCheckedSchema, fields, ValidationError
from parsec.core.devices_manager2.cipher import (
    CipherError,
    BaseLocalDeviceEncryptor,
    BaseLocalDeviceDecryptor,
)
from parsec.core.devices_manager2.pkcs11_tools import (
    DevicePKCS11Error,
    encrypt_data,
    decrypt_data,
    get_LIB,
)


class PKCS11PayloadSchema(UnknownCheckedSchema):
    type = fields.CheckedConstant("PKCS11", required=True)
    ciphertext = fields.Base64Bytes(required=True)


pkcs11_payload_schema = PKCS11PayloadSchema(strict=True)


class PKCS11DeviceEncryptor(BaseLocalDeviceEncryptor):
    def __init__(self, token_id: int, key_id: int):
        self.key_id = key_id
        self.token_id = token_id
        # Force loading to crash early if opensc-pkcs11.so is not available
        get_LIB()

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Raises:
            CipherError
        """
        try:
            ciphertext = encrypt_data(self.token_id, self.key_id, plaintext)
            return pkcs11_payload_schema.dumps({"ciphertext": ciphertext}).data.encode("utf8")

        except (DevicePKCS11Error, ValidationError, JSONDecodeError, ValueError) as exc:
            raise CipherError(str(exc)) from exc


class PKCS11DeviceDecryptor(BaseLocalDeviceDecryptor):
    def __init__(self, pin: str, token_id: int, key_id: int):
        self.pin = pin
        self.key_id = key_id
        self.token_id = token_id
        # Force loading to crash early if opensc-pkcs11.so is not available
        get_LIB()

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Raises:
            CipherError
        """
        try:
            payload = pkcs11_payload_schema.loads(ciphertext.decode("utf8")).data
            return decrypt_data(self.pin, self.token_id, self.key_id, payload["ciphertext"])

        except (DevicePKCS11Error, ValidationError, JSONDecodeError, ValueError) as exc:
            raise CipherError(str(exc)) from exc
