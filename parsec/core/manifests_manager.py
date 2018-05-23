import json
from nacl.public import Box
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError, CryptoError

from parsec.core.base import BaseAsyncComponent
from parsec.core.schemas import TypedManifestSchema
from parsec.core.fs.base import SecurityError
from parsec.utils import ParsecError, from_jsonb64


class ManifestSignatureError(SecurityError):
    status = "invalid_signature"


class ManifestDecryptionError(ParsecError):
    status = "decryption_error"


class ManifestsManager(BaseAsyncComponent):

    def __init__(self, device, local_storage, backend_storage, backend_connection):
        super().__init__()
        self.device = device
        self._backend_connection = backend_connection
        self._local_storage = local_storage
        self._backend_storage = backend_storage

    async def _init(self, nursery):
        pass

    async def _teardown(self):
        pass

    async def _verify(self, signed):
        unsigned_message = json.loads(signed[64:].decode())
        if (
            unsigned_message["user_id"] == self.device.user_id
            and unsigned_message["device_name"] == self.device.device_name
        ):
            verify_key = self.device.device_verifykey
        else:
            # TODO: create a component (or methods in backend_storage ?)
            # dedicated to retrieve user infos
            verify_key_str = self._local_storage.fetch_device_verify_key(unsigned_message["user_id"], unsigned_message["device_name"])
            if not verify_key_str:
                rep = await self._backend_connection.send(
                    {"cmd": "user_get", "user_id": unsigned_message["user_id"]}
                )
                assert rep["status"] == "ok"
                verify_key_str = rep["devices"][unsigned_message["device_name"]]["verify_key"]
                self._local_storage.flush_device_verify_key(unsigned_message["user_id"], unsigned_message["device_name"], verify_key_str)
            # TODO: handle crash, handle key validity expiration
            verify_key = VerifyKey(
                from_jsonb64(verify_key_str)
            )
        return verify_key.verify(signed)

    def _encrypt_manifest(self, key, manifest):
        raw = json.dumps(manifest).encode()
        box = SecretBox(key)
        signed = self.device.device_signkey.sign(raw)
        return box.encrypt(signed)

    async def _decrypt_manifest(self, key, blob):
        box = SecretBox(key)
        try:
            signed = box.decrypt(blob)
            raw = await self._verify(signed)

        except json.decoder.JSONDecodeError as exc:
            raise exc

        except BadSignatureError as exc:
            raise ManifestSignatureError() from exc

        except (CryptoError, ValueError) as exc:
            raise ManifestDecryptionError() from exc

        return json.loads(raw.decode())

    def _encrypt_user_manifest(self, manifest):
        raw = json.dumps(manifest).encode()
        box = Box(self.device.user_privkey, self.device.user_pubkey)
        signed = self.device.device_signkey.sign(raw)
        return box.encrypt(signed)

    async def _decrypt_user_manifest(self, blob):
        box = Box(self.device.user_privkey, self.device.user_pubkey)
        try:
            signed = box.decrypt(blob)
            raw = await self._verify(signed)
        except json.decoder.JSONDecodeError as exc:
            raise exc

        except BadSignatureError as exc:
            raise ManifestSignatureError() from exc

        except (CryptoError, ValueError) as exc:
            raise ManifestDecryptionError() from exc

        return json.loads(raw.decode())

    async def fetch_user_manifest_from_local(self):
        blob = self._local_storage.fetch_user_manifest()
        if blob:
            decrypted = await self._decrypt_user_manifest(blob)
            data, _ = TypedManifestSchema(strict=True).load(decrypted)
            return data

    async def fetch_user_manifest_from_backend(self, version=None):
        blob = await self._backend_storage.fetch_user_manifest(version=version)
        if blob:
            decrypted = await self._decrypt_user_manifest(blob)
            data, _ = TypedManifestSchema(strict=True).load(decrypted)
            return data

    async def flush_user_manifest_on_local(self, manifest):
        data, _ = TypedManifestSchema(strict=True).dump(manifest)
        blob = self._encrypt_user_manifest(data)
        self._local_storage.flush_user_manifest(blob)

    async def sync_user_manifest_with_backend(self, manifest):
        data, _ = TypedManifestSchema(strict=True).dump(manifest)
        blob = self._encrypt_user_manifest(data)
        # if b'"children": {"0"' in blob:
        #     import pdb; pdb.set_trace()
        await self._backend_storage.sync_user_manifest(manifest["version"], blob)

    async def fetch_from_local(self, id, key):
        blob = self._local_storage.fetch_manifest(id)
        if blob:
            decrypted = await self._decrypt_manifest(key, blob)
            data, _ = TypedManifestSchema(strict=True).load(decrypted)
            return data

    async def fetch_from_backend(self, id, rts, key, version=None):
        blob = await self._backend_storage.fetch_manifest(id, rts, version=version)
        if blob:
            # TODO: store cache in local ?
            decrypted = await self._decrypt_manifest(key, blob)
            data, _ = TypedManifestSchema(strict=True).load(decrypted)
            return data

    async def flush_on_local(self, id, key, manifest):
        data, _ = TypedManifestSchema(strict=True).dump(manifest)
        blob = self._encrypt_manifest(key, data)
        self._local_storage.flush_manifest(id, blob)

    async def sync_new_entry_with_backend(self, key, manifest):
        data, _ = TypedManifestSchema(strict=True).dump(manifest)
        blob = self._encrypt_manifest(key, data)
        return await self._backend_storage.sync_new_manifest(blob)

    async def sync_with_backend(self, id, wts, key, manifest):
        version = manifest["version"]
        data, _ = TypedManifestSchema(strict=True).dump(manifest)
        blob = self._encrypt_manifest(key, data)
        await self._backend_storage.sync_manifest(id, wts, version, blob)
