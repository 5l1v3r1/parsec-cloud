# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from typing import Optional, Tuple, List
from random import randint, shuffle

from parsec.crypto import VerifyKey, PublicKey, PrivateKey, SecretKey
from parsec.serde import fields, post_load
from parsec.api.protocol import (
    DeviceID,
    DeviceIDField,
    DeviceName,
    DeviceNameField,
    HumanHandle,
    HumanHandleField,
)
from parsec.api.data.base import BaseAPIData, BaseSchema


def generate_sas_codes(
    invitee_nonce: bytes, inviter_nonce: bytes, shared_secret_key: SecretKey
) -> Tuple[int, int]:
    # Computes combined HMAC
    combined_nonce = invitee_nonce + inviter_nonce
    # Digest size of 5 bytes so we can split it beween two 20bits SAS
    combined_hmac = shared_secret_key.hmac(combined_nonce, digest_size=5)

    hmac_as_int = int.from_bytes(combined_hmac, "big")
    # Big endian number extracted from bits [0, 20[
    invitee_sas = hmac_as_int % 2 ** 20
    # Big endian number extracted from bits [20, 40[
    inviter_sas = (hmac_as_int >> 20) % 2 ** 20

    # # TODO: remove me before the merge
    # assert invitee_sas == combined_hmac[0] << 12 | combined_hmac[1] << 4 | combined_hmac[2] >> 4
    # assert inviter_sas == (combined_hmac[2] & 0xF) << 16 | combined_hmac[3] << 8 | combined_hmac[4]

    return invitee_sas, inviter_sas


def generate_sas_code_candidates(valid_sas: int, size: int = 3) -> List[int]:
    candidates = {valid_sas}
    while len(candidates) < size:
        candidates.add(randint(0, 2 ** 20 - 1))
    candidates = list(candidates)
    shuffle(candidates)
    return candidates


class InviteUserData(BaseAPIData):
    class SCHEMA_CLS(BaseSchema):
        type = fields.CheckedConstant("invite_user_data", required=True)
        # Invitee ask for device_id/human_handle, but inviter has final word on this
        requested_device_id = DeviceIDField(required=True)
        requested_human_handle = HumanHandleField(allow_none=True, missing=None)
        # Note claiming user also imply creating a first device
        public_key = fields.PublicKey(required=True)
        verify_key = fields.VerifyKey(required=True)

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return InviteUserData(**data)

    requested_device_id: DeviceID
    requested_human_handle: Optional[HumanHandle]
    public_key: PublicKey
    verify_key: VerifyKey


class InviteUserConfirmation(BaseAPIData):
    class SCHEMA_CLS(BaseSchema):
        type = fields.CheckedConstant("invite_user_confirmation", required=True)
        device_id = DeviceIDField(required=True)
        human_handle = HumanHandleField(allow_none=True, missing=None)
        is_admin = fields.Boolean(required=True)
        root_verify_key = fields.VerifyKey(required=True)

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return InviteUserConfirmation(**data)

    device_id: DeviceID
    human_handle: Optional[HumanHandle]
    is_admin: bool
    root_verify_key: VerifyKey


class InviteDeviceData(BaseAPIData):
    class SCHEMA_CLS(BaseSchema):
        type = fields.CheckedConstant("invite_device_data", required=True)
        # Invitee ask for device_name, but inviter has final word on this
        requested_device_name = DeviceNameField(required=True)
        verify_key = fields.VerifyKey(required=True)

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return InviteDeviceData(**data)

    requested_device_name: DeviceName
    verify_key: VerifyKey


class InviteDeviceConfirmation(BaseAPIData):
    class SCHEMA_CLS(BaseSchema):
        type = fields.CheckedConstant("invite_device_confirmation", required=True)
        device_id = DeviceIDField(required=True)
        human_handle = HumanHandleField(allow_none=True, missing=None)
        is_admin = fields.Boolean(required=True)
        private_key = fields.PrivateKey(required=True)
        root_verify_key = fields.VerifyKey(required=True)

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return InviteDeviceConfirmation(**data)

    device_id: DeviceID
    human_handle: Optional[HumanHandle]
    is_admin: bool
    private_key: PrivateKey
    root_verify_key: VerifyKey
