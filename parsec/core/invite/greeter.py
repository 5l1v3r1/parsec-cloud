# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import attr
from uuid import UUID
from typing import Optional, List, Tuple
from pendulum import now as pendulum_now

from parsec.crypto import (
    generate_shared_secret_key,
    generate_nonce,
    SecretKey,
    PrivateKey,
    HashDigest,
    PublicKey,
    VerifyKey,
)
from parsec.api.data import (
    DataError,
    generate_sas_codes,
    generate_sas_code_candidates,
    InviteUserData,
    InviteUserConfirmation,
    InviteDeviceData,
    InviteDeviceConfirmation,
    DeviceCertificateContent,
    UserCertificateContent,
)
from parsec.api.protocol import DeviceName, DeviceID, HumanHandle
from parsec.core.backend_connection import BackendInvitedCmds
from parsec.core.types import LocalDevice
from parsec.core.invite.exceptions import InviteError, InvitePeerResetError, InviteNotAvailableError


@attr.s(slots=True, frozen=True, auto_attribs=True)
class BaseGreetInitialCtx:
    token: UUID
    _cmds: BackendInvitedCmds

    async def _do_wait_peer(self) -> Tuple[int, int, SecretKey]:
        inviter_private_key = PrivateKey.generate()
        rep = await self._cmds.invite_1_inviter_wait_peer(
            token=self.token, inviter_public_key=inviter_private_key.public_key
        )
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 1: {rep}")

        shared_secret_key = generate_shared_secret_key(
            our_private_key=inviter_private_key, peer_public_key=rep["invitee_public_key"]
        )
        inviter_nonce = generate_nonce()

        rep = await self._cmds.invite_2a_inviter_get_hashed_nonce(token=self.token)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 2a: {rep}")

        invitee_hashed_nonce = rep["invitee_hashed_nonce"]

        rep = await self._cmds.invite_2b_inviter_send_nonce(
            token=self.token, inviter_nonce=inviter_nonce
        )
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 2b: {rep}")

        if HashDigest.from_data(rep["invitee_nonce"]) != invitee_hashed_nonce:
            raise InviteError("Invitee nonce and hashed nonce doesn't match")

        invitee_sas, inviter_sas = generate_sas_codes(
            invitee_nonce=rep["invitee_nonce"],
            inviter_nonce=inviter_nonce,
            shared_secret_key=shared_secret_key,
        )

        return invitee_sas, inviter_sas, shared_secret_key


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserGreetInitialCtx(BaseGreetInitialCtx):
    async def do_wait_peer(self) -> "UserGreetInProgress1Ctx":
        claimer_sas, greeter_sas, shared_secret_key = await self._do_wait_peer()

        return UserGreetInProgress1Ctx(
            token=self.token,
            greeter_sas=greeter_sas,
            claimer_sas=claimer_sas,
            shared_secret_key=shared_secret_key,
            cmds=self._cmds,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceGreetInitialCtx(BaseGreetInitialCtx):
    async def do_wait_peer(self) -> "DeviceGreetInProgress1Ctx":
        claimer_sas, greeter_sas, shared_secret_key = await self._do_wait_peer()

        return DeviceGreetInProgress1Ctx(
            token=self.token,
            greeter_sas=greeter_sas,
            claimer_sas=claimer_sas,
            shared_secret_key=shared_secret_key,
            cmds=self._cmds,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class BaseGreetInProgress1Ctx:
    token: UUID
    greeter_sas: int

    _claimer_sas: int
    _shared_secret_key: SecretKey
    _cmds: BackendInvitedCmds

    async def _do_wait_peer_trust(self) -> None:
        rep = await self._cmds.invite_3a_inviter_wait_peer_trust(token=self.token)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 3b: {rep}")


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserGreetInProgress1Ctx(BaseGreetInProgress1Ctx):
    async def do_wait_peer_trust(self) -> "UserGreetInProgress2Ctx":
        await self._do_wait_peer_trust()

        return UserGreetInProgress2Ctx(
            token=self.token,
            claimer_sas=self._claimer_sas,
            shared_secret_key=self._shared_secret_key,
            cmds=self._cmds,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceGreetInProgress1Ctx(BaseGreetInProgress1Ctx):
    async def do_wait_peer_trust(self) -> "DeviceGreetInProgress2Ctx":
        await self._do_wait_peer_trust()

        return DeviceGreetInProgress2Ctx(
            token=self.token,
            claimer_sas=self._claimer_sas,
            shared_secret_key=self._shared_secret_key,
            cmds=self._cmds,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class BaseGreetInProgress2Ctx:
    token: UUID
    claimer_sas: int

    _shared_secret_key: SecretKey
    _cmds: BackendInvitedCmds

    def generate_claimer_sas_choices(self, size: int = 3) -> List[int]:
        return generate_sas_code_candidates(self.claimer_sas, size=size)

    async def _do_signify_trust(self) -> None:
        rep = await self._cmds.invite_3b_inviter_signify_trust(token=self.token)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 3a: {rep}")


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserGreetInProgress2Ctx(BaseGreetInProgress2Ctx):
    async def do_signify_trust(self) -> "UserGreetInProgress3Ctx":
        await self._do_signify_trust()

        return UserGreetInProgress3Ctx(
            token=self.token, shared_secret_key=self._shared_secret_key, cmds=self._cmds
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceGreetInProgress2Ctx(BaseGreetInProgress2Ctx):
    async def do_signify_trust(self) -> "DeviceGreetInProgress3Ctx":
        await self._do_signify_trust()

        return DeviceGreetInProgress3Ctx(
            token=self.token, shared_secret_key=self._shared_secret_key, cmds=self._cmds
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserGreetInProgress3Ctx:
    token: UUID

    _shared_secret_key: SecretKey
    _cmds: BackendInvitedCmds

    async def do_get_claim_requests(self) -> "UserGreetInProgress4Ctx":
        rep = await self._cmds.invite_4_inviter_communicate(token=self.token, payload=None)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 4 (data exchange): {rep}")

        if rep["payload"] is None:
            raise InviteError("Missing InviteUserData payload")

        try:
            data = InviteUserData.decrypt_and_load(rep["payload"], key=self._shared_secret_key)
        except DataError as exc:
            raise InviteError("Invalid InviteUserData payload provided by peer") from exc

        return UserGreetInProgress4Ctx(
            token=self.token,
            requested_device_id=data.requested_device_id,
            requested_human_handle=data.requested_human_handle,
            public_key=data.public_key,
            verify_key=data.verify_key,
            shared_secret_key=self._shared_secret_key,
            cmds=self._cmds,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceGreetInProgress3Ctx:
    token: UUID

    _shared_secret_key: SecretKey
    _cmds: BackendInvitedCmds

    async def do_get_claim_requests(self) -> "DeviceGreetInProgress4Ctx":
        rep = await self._cmds.invite_4_inviter_communicate(token=self.token, payload=None)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 4 (data exchange): {rep}")

        if rep["payload"] is None:
            raise InviteError("Missing InviteDeviceData payload")

        try:
            data = InviteDeviceData.decrypt_and_load(rep["payload"], key=self._shared_secret_key)
        except DataError as exc:
            raise InviteError("Invalid InviteDeviceData payload provided by peer") from exc

        return DeviceGreetInProgress4Ctx(
            token=self.token,
            requested_device_name=data.requested_device_name,
            verify_key=data.verify_key,
            shared_secret_key=self._shared_secret_key,
            cmds=self._cmds,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserGreetInProgress4Ctx:
    token: UUID
    requested_device_id: DeviceID
    requested_human_handle: Optional[HumanHandle]

    _public_key: PublicKey
    _verify_key: VerifyKey
    _shared_secret_key: SecretKey
    _cmds: BackendInvitedCmds

    async def do_create_new_user(
        self, author: LocalDevice, device_id: DeviceID, human_handle: HumanHandle, is_admin: bool
    ) -> None:
        try:
            now = pendulum_now()

            user_certificate = UserCertificateContent(
                author=author.device_id,
                timestamp=now,
                user_id=device_id.user_id,
                human_handle=human_handle,
                public_key=self._public_key,
            ).dump_and_sign(author.signing_key)

            device_certificate = DeviceCertificateContent(
                author=author.device_id,
                timestamp=now,
                device_id=device_id,
                verify_key=self._verify_key,
            ).dump_and_sign(author.signing_key)

        except DataError as exc:
            raise InviteError(f"Cannot generate device certificate: {exc}") from exc

        rep = await self._cmds.user_create(
            user_certificate=user_certificate, device_certificate=device_certificate
        )
        if rep["status"] != "ok":
            raise InviteError(f"Cannot create device: {rep}")

        try:
            payload = InviteUserConfirmation(
                device_id=device_id,
                human_handle=human_handle,
                is_admin=is_admin,
                root_verify_key=author.root_verify_key,
            ).dump_and_encrypt(key=self._shared_secret_key)
        except DataError as exc:
            raise InviteError("Cannot generate InviteUserConfirmation payload") from exc

        rep = await self._cmds.invite_4_inviter_communicate(token=self.token, payload=payload)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 4 (confirmation exchange): {rep}")


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceGreetInProgress4Ctx:
    token: UUID
    requested_device_name: DeviceName

    _verify_key: VerifyKey
    _shared_secret_key: SecretKey
    _cmds: BackendInvitedCmds

    async def do_create_new_device(self, author: LocalDevice, device_name: DeviceName) -> None:
        device_id = DeviceID(f"{author.user_id}@{device_name}")
        try:
            now = pendulum_now()

            device_certificate = DeviceCertificateContent(
                author=author.device_id,
                timestamp=now,
                device_id=device_id,
                verify_key=self._verify_key,
            ).dump_and_sign(author.signing_key)

        except DataError as exc:
            raise InviteError(f"Cannot generate device certificate: {exc}") from exc

        rep = await self._cmds.device_create(device_certificate=device_certificate)
        if rep["status"] != "ok":
            raise InviteError(f"Cannot create device: {rep}")

        try:
            payload = InviteDeviceConfirmation(
                device_id=device_id,
                human_handle=author.human_handle,
                is_admin=author.is_admin,
                private_key=author.private_key,
                root_verify_key=author.root_verify_key,
            ).dump_and_encrypt(key=self._shared_secret_key)
        except DataError as exc:
            raise InviteError("Cannot generate InviteUserConfirmation payload") from exc

        rep = await self._cmds.invite_4_inviter_communicate(token=self.token, payload=payload)
        if rep["status"] in ("not_found", "already_deleted"):
            raise InviteNotAvailableError()
        elif rep["status"] == "invalid_state":
            raise InvitePeerResetError()
        elif rep["status"] != "ok":
            raise InviteError(f"Backend error during step 4 (confirmation exchange): {rep}")
