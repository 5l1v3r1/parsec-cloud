import pendulum
from collections import Mapping
from marshmallow import ValidationError
from marshmallow.fields import (
    # Republishing
    Int,
    String,
    List,
    Dict,
    Nested,
    Integer,
    UUID,
    Boolean,
    Field,
)

from parsec.utils import to_jsonb64, from_jsonb64
from parsec.types import DeviceID as _DeviceID, UserID as _UserID, DeviceName as _DeviceName
from parsec.crypto_types import (
    SigningKey as _SigningKey,
    VerifyKey as _VerifyKey,
    PrivateKey as _PrivateKey,
    PublicKey as _PublicKey,
)


# TODO: test this field and use it everywhere in the api !


class Path(Field):
    """Absolute path"""

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        if not value.startswith("/"):
            raise ValidationError("Path must be absolute")
        if value != "/":
            for item in value.split("/")[1:]:
                if item in (".", "..", ""):
                    raise ValidationError("Invalid path")
        return value


class UUID(UUID):
    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return value.hex


class Base64Bytes(Field):
    """Pass bytes through json by encoding them into base64"""

    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return to_jsonb64(value)

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        try:
            return from_jsonb64(value)

        except Exception:
            raise ValidationError("Invalid base64-encoded bytes")


class DateTime(Field):
    """DateTime using pendulum instead of regular datetime"""

    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return value.isoformat()

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        try:
            return pendulum.parse(value)

        except Exception:
            raise ValidationError("Invalid datetime")


class CheckedConstant(Field):
    """Make sure the value is present during deserialization"""

    def __init__(self, constant, **kwargs):
        kwargs.setdefault("default", constant)
        super().__init__(**kwargs)
        self.constant = constant

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        if value != self.constant:
            raise ValidationError("Invalid value, should be `%s`" % self.constant)

        return value


class Map(Field):
    default_error_messages = {"invalid": "Not a valid mapping type."}

    def __init__(self, key_field, nested_field, **kwargs):
        super().__init__(**kwargs)
        self.key_field = key_field
        self.nested_field = nested_field

    def _deserialize(self, value, attr, obj):

        if not isinstance(value, Mapping):
            self.fail("invalid")

        ret = {}
        for key, val in value.items():
            k = self.key_field.deserialize(key)
            v = self.nested_field.deserialize(val)
            ret[k] = v
        return ret

    def _serialize(self, value, attr, obj):
        ret = {}
        for key, val in value.items():
            k = self.key_field._serialize(key, attr, obj)
            v = self.nested_field._serialize(val, key, value)
            ret[k] = v
        return ret


class SigningKey(Field):
    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return to_jsonb64(value.encode())

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        try:
            return _SigningKey(from_jsonb64(value))

        except Exception:
            raise ValidationError("Invalid signing key.")


class VerifyKey(Field):
    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return to_jsonb64(value.encode())

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        try:
            return _VerifyKey(from_jsonb64(value))

        except Exception:
            raise ValidationError("Invalid verify key.")


class PrivateKey(Field):
    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return to_jsonb64(value.encode())

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        try:
            return _PrivateKey(from_jsonb64(value))

        except Exception:
            raise ValidationError("Invalid secret key.")


class PublicKey(Field):
    def _serialize(self, value, attr, obj):
        if value is None:
            return None

        return to_jsonb64(value.encode())

    def _deserialize(self, value, attr, data):
        if value is None:
            return None

        try:
            return _PublicKey(from_jsonb64(value))

        except Exception:
            raise ValidationError("Invalid verify key.")


class DeviceID(Field):
    def _deserialize(self, value, attr, data):
        try:
            return _DeviceID(value)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


class UserID(Field):
    def _deserialize(self, value, attr, data):
        try:
            return _UserID(value)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


class DeviceName(Field):
    def _deserialize(self, value, attr, data):
        try:
            return _DeviceName(value)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


__all__ = (
    "Int",
    "String",
    "List",
    "Dict",
    "Nested",
    "Integer",
    "UUID",
    "Boolean",
    "Field",
    "Path",
    "Base64Bytes",
    "DateTime",
    "CheckedConstant",
    "Map",
    "VerifyKey",
    "PublicKey",
    "DeviceID",
    "UserID",
    "DeviceName",
)
