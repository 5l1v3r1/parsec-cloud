# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import attr
from enum import Enum
from uuid import UUID, uuid4
from typing import List, Optional, Union
from pendulum import Pendulum, now as pendulum_now

from parsec.api.protocol import (
    OrganizationID,
    UserID,
    HumanHandle,
    HandshakeType,
    InvitationType,
    InvitationDeletedReason,
    InvitationStatus,
    invite_new_serializer,
    invite_delete_serializer,
    invite_list_serializer,
    invite_info_serializer,
    invite_1_invitee_wait_peer_serializer,
    invite_1_inviter_wait_peer_serializer,
    invite_2_invitee_send_hashed_nonce_serializer,
    invite_2_inviter_get_hashed_nonce_serializer,
    invite_2_inviter_send_nonce_serializer,
    invite_2_invitee_send_nonce_serializer,
    invite_3_inviter_wait_peer_trust_serializer,
    invite_3_invitee_wait_peer_trust_serializer,
    invite_3_inviter_signify_trust_serializer,
    invite_3_invitee_signify_trust_serializer,
    invite_4_inviter_communicate_serializer,
    invite_4_invitee_communicate_serializer,
)
from parsec.event_bus import EventBus
from parsec.backend.utils import catch_protocol_errors, api


PEER_EVENT_MAX_WAIT = 300  # 5mn


class InvitationError(Exception):
    pass


class InvitationAlreadyExistsError(InvitationError):
    pass


class InvitationNotFoundError(InvitationError):
    pass


class InvitationAlreadyDeletedError(InvitationError):
    pass


class InvitationInvalidStateError(InvitationError):
    pass


class ConduitState(Enum):
    STATE_1_WAIT_PEERS = "state_1_wait_peers"
    STATE_2_1_INVITEE_HASHED_NONCE = "state_2_1_invitee_hashed_nonce"
    STATE_2_2_INVITER_NONCE = "state_2_2_inviter_nonce"
    STATE_2_3_INVITEE_NONCE = "state_2_3_invitee_nonce"
    STATE_3_1_INVITEE_TRUST = "state_3_1_invitee_trust"
    STATE_3_2_INVITER_TRUST = "state_3_2_inviter_trust"
    STATE_4_COMMUNICATE = "state_4_communicate"


NEXT_CONDUIT_STATE = {
    ConduitState.STATE_1_WAIT_PEERS: ConduitState.STATE_2_1_INVITEE_HASHED_NONCE,
    ConduitState.STATE_2_1_INVITEE_HASHED_NONCE: ConduitState.STATE_2_2_INVITER_NONCE,
    ConduitState.STATE_2_2_INVITER_NONCE: ConduitState.STATE_2_3_INVITEE_NONCE,
    ConduitState.STATE_2_3_INVITEE_NONCE: ConduitState.STATE_3_1_INVITEE_TRUST,
    ConduitState.STATE_3_1_INVITEE_TRUST: ConduitState.STATE_3_2_INVITER_TRUST,
    ConduitState.STATE_3_2_INVITER_TRUST: ConduitState.STATE_4_COMMUNICATE,
    ConduitState.STATE_4_COMMUNICATE: ConduitState.STATE_4_COMMUNICATE,
}


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserInvitation:
    inviter_user_id: UserID
    inviter_human_handle: Optional[HumanHandle]
    invitee_email: str
    token: UUID = attr.ib(factory=uuid4)
    created_on: Pendulum = attr.ib(factory=pendulum_now)
    status: InvitationStatus = InvitationStatus.IDLE
    deleted_on: Optional[Pendulum] = None
    deleted_reason: Optional[InvitationDeletedReason] = None

    def evolve(self, **kwargs):
        return attr.evolve(self, **kwargs)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceInvitation:
    inviter_user_id: UserID
    inviter_human_handle: Optional[HumanHandle]
    token: UUID = attr.ib(factory=uuid4)
    created_on: Pendulum = attr.ib(factory=pendulum_now)
    status: InvitationStatus = InvitationStatus.IDLE
    deleted_on: Optional[Pendulum] = None
    deleted_reason: Optional[InvitationDeletedReason] = None

    def evolve(self, **kwargs):
        return attr.evolve(self, **kwargs)


Invitation = Union[UserInvitation, DeviceInvitation]


class BaseInviteComponent:
    def __init__(self, event_bus: EventBus):
        self._event_bus = event_bus
        self._wip_invitations = {}

        def _on_status_changed(event, organization_id, inviter, token, status):
            key = (organization_id, token)
            if status == InvitationStatus.IDLE:
                self._wip_invitations[key] = status
            else:  # Deleted or back to Ready
                self._wip_invitations.pop(key, None)

        self._event_bus.connect("invite.status_changed", _on_status_changed)

    @api("invite_new", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_new(self, client_ctx, msg):
        msg = invite_new_serializer.req_load(msg)
        if msg["type"] == InvitationType.USER:
            # TODO: implement send email feature
            if msg["send_email"]:
                return invite_new_serializer.rep_dump({"status": "not_implemented"})
            invitation = UserInvitation(
                inviter_user_id=client_ctx.user_id,
                inviter_human_handle=client_ctx.human_handle,
                invitee_email=msg["invitee_email"],
            )
        else:  # Device
            invitation = DeviceInvitation(
                inviter_user_id=client_ctx.user_id, inviter_human_handle=client_ctx.human_handle
            )
        try:
            await self.new(organization_id=client_ctx.organization_id, invitation=invitation)

        except InvitationAlreadyExistsError:
            return {"status": "already_exists"}

        return invite_new_serializer.rep_dump({"status": "ok", "token": invitation.token})

    @api("invite_delete", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_delete(self, client_ctx, msg):
        msg = invite_delete_serializer.req_load(msg)
        try:
            await self.delete(
                organization_id=client_ctx.organization_id,
                inviter=client_ctx.user_id,
                token=msg["token"],
                on=pendulum_now(),
                reason=msg["reason"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        return invite_delete_serializer.rep_dump({"status": "ok"})

    @api("invite_list", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_list(self, client_ctx, msg):
        msg = invite_list_serializer.req_load(msg)
        invitations = await self.list(
            organization_id=client_ctx.organization_id, inviter=client_ctx.user_id
        )
        return invite_list_serializer.rep_dump(
            {
                "invitations": [
                    {
                        "type": InvitationType.USER
                        if isinstance(item, UserInvitation)
                        else InvitationType.DEVICE,
                        "token": item.token,
                        "created_on": item.created_on,
                        "invitee_email": getattr(
                            item, "invitee_email", None
                        ),  # Only available for user
                        "status": item.status,
                        "deleted_on": item.deleted_on,
                        "deleted_reason": item.deleted_reason,
                    }
                    for item in invitations
                ]
            }
        )

    @api("invite_info", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_info(self, client_ctx, msg):
        invite_info_serializer.req_load(msg)
        # Invitation has already been fetched during handshake
        invitation = client_ctx.invitation
        # TODO: check invitation status and close connection if deleted ?
        if isinstance(invitation, UserInvitation):
            rep = {
                "type": InvitationType.USER,
                "invitee_email": invitation.invitee_email,
                "inviter_user_id": invitation.inviter_user_id,
                "inviter_human_handle": invitation.inviter_human_handle,
            }
        else:  # DeviceInvitation
            rep = {
                "type": InvitationType.DEVICE,
                "inviter_user_id": invitation.inviter_user_id,
                "inviter_human_handle": invitation.inviter_human_handle,
            }
        return invite_info_serializer.rep_dump(rep)

    @api("invite_1_invitee_wait_peer", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_1_invitee_wait_peer(self, client_ctx, msg):
        msg = invite_1_invitee_wait_peer_serializer.req_load(msg)

        try:
            inviter_public_key = await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_1_WAIT_PEERS,
                payload=msg["invitee_public_key"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_1_invitee_wait_peer_serializer.rep_dump(
            {"status": "ok", "inviter_public_key": inviter_public_key}
        )

    @api("invite_1_inviter_wait_peer", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_1_inviter_wait_peer(self, client_ctx, msg):
        msg = invite_1_inviter_wait_peer_serializer.req_load(msg)

        try:
            invitee_public_key = await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_1_WAIT_PEERS,
                payload=msg["inviter_public_key"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_1_inviter_wait_peer_serializer.rep_dump(
            {"status": "ok", "invitee_public_key": invitee_public_key}
        )

    @api("invite_2_invitee_send_hashed_nonce", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_2_invitee_send_hashed_nonce(self, client_ctx, msg):
        msg = invite_2_invitee_send_hashed_nonce_serializer.req_load(msg)

        try:
            await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_2_1_INVITEE_HASHED_NONCE,
                payload=msg["invitee_hashed_nonce"],
            )

            inviter_nonce = await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_2_2_INVITER_NONCE,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_2_invitee_send_hashed_nonce_serializer.rep_dump(
            {"status": "ok", "inviter_nonce": inviter_nonce}
        )

    @api("invite_2_inviter_get_hashed_nonce", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_2_inviter_get_hashed_nonce(self, client_ctx, msg):
        msg = invite_2_inviter_get_hashed_nonce_serializer.req_load(msg)

        try:
            invitee_hashed_nonce = await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_2_1_INVITEE_HASHED_NONCE,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_2_inviter_get_hashed_nonce_serializer.rep_dump(
            {"status": "ok", "invitee_hashed_nonce": invitee_hashed_nonce}
        )

    @api("invite_2_inviter_send_nonce", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_2_inviter_send_nonce(self, client_ctx, msg):
        msg = invite_2_inviter_send_nonce_serializer.req_load(msg)

        try:
            await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_2_2_INVITER_NONCE,
                payload=msg["inviter_nonce"],
            )

            invitee_nonce = await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_2_3_INVITEE_NONCE,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_2_inviter_send_nonce_serializer.rep_dump(
            {"status": "ok", "invitee_nonce": invitee_nonce}
        )

    @api("invite_2_invitee_send_nonce", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_2_invitee_send_nonce(self, client_ctx, msg):
        msg = invite_2_invitee_send_nonce_serializer.req_load(msg)

        try:
            await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_2_3_INVITEE_NONCE,
                payload=msg["invitee_nonce"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_2_invitee_send_nonce_serializer.rep_dump({"status": "ok"})

    @api("invite_3_inviter_wait_peer_trust", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_3_inviter_wait_peer_trust(self, client_ctx, msg):
        msg = invite_3_inviter_wait_peer_trust_serializer.req_load(msg)

        try:
            await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_3_1_INVITEE_TRUST,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_3_inviter_wait_peer_trust_serializer.rep_dump({"status": "ok"})

    @api("invite_3_invitee_wait_peer_trust", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_3_invitee_wait_peer_trust(self, client_ctx, msg):
        msg = invite_3_invitee_wait_peer_trust_serializer.req_load(msg)

        try:
            await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_3_2_INVITER_TRUST,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_3_invitee_wait_peer_trust_serializer.rep_dump({"status": "ok"})

    @api("invite_3_inviter_signify_trust", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_3_inviter_signify_trust(self, client_ctx, msg):
        msg = invite_3_inviter_signify_trust_serializer.req_load(msg)

        try:
            await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_3_2_INVITER_TRUST,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_3_inviter_signify_trust_serializer.rep_dump({"status": "ok"})

    @api("invite_3_invitee_signify_trust", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_3_invitee_signify_trust(self, client_ctx, msg):
        msg = invite_3_invitee_signify_trust_serializer.req_load(msg)

        try:
            await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_3_1_INVITEE_TRUST,
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_3_invitee_signify_trust_serializer.rep_dump({"status": "ok"})

    @api("invite_4_inviter_communicate", handshake_types=[HandshakeType.AUTHENTICATED])
    @catch_protocol_errors
    async def api_invite_4_inviter_communicate(self, client_ctx, msg):
        msg = invite_4_inviter_communicate_serializer.req_load(msg)

        try:
            answer_payload = await self.conduit_inviter_talk(
                organization_id=client_ctx.organization_id,
                token=msg["token"],
                state=ConduitState.STATE_4_COMMUNICATE,
                payload=msg["payload"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_4_inviter_communicate_serializer.rep_dump(
            {"status": "ok", "payload": answer_payload}
        )

    @api("invite_4_invitee_communicate", handshake_types=[HandshakeType.INVITED])
    @catch_protocol_errors
    async def api_invite_4_invitee_communicate(self, client_ctx, msg):
        msg = invite_4_invitee_communicate_serializer.req_load(msg)

        try:
            answer_payload = await self.conduit_invitee_talk(
                organization_id=client_ctx.organization_id,
                token=client_ctx.invitation.token,
                state=ConduitState.STATE_4_COMMUNICATE,
                payload=msg["payload"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        except InvitationInvalidStateError:
            return {"status": "invalid_state"}

        return invite_4_invitee_communicate_serializer.rep_dump(
            {"status": "ok", "payload": answer_payload}
        )

    async def conduit_invitee_talk(
        self,
        organization_id: OrganizationID,
        token: UUID,
        state: ConduitState,
        payload: Optional[bytes] = None,
    ) -> bytes:
        raise NotImplementedError()

    async def conduit_inviter_talk(
        self,
        organization_id: OrganizationID,
        token: UUID,
        state: ConduitState,
        payload: Optional[bytes] = None,
    ) -> bytes:
        raise NotImplementedError()

    async def new(self, organization_id: OrganizationID, invitation: Invitation) -> None:
        """
        Raises:
            InvitationAlreadyExistsError
        """
        raise NotImplementedError()

    async def delete(
        self,
        organization_id: OrganizationID,
        inviter: UserID,
        token: UUID,
        on: Pendulum,
        reason: InvitationDeletedReason,
    ) -> None:
        """
        Raises:
            InvitationNotFoundError
            InvitationAlreadyDeletedError
        """
        raise NotImplementedError()

    async def list(self, organization_id: OrganizationID, inviter: UserID) -> List[Invitation]:
        """
        Raises: Nothing
        """
        raise NotImplementedError()

    async def info(self, organization_id: OrganizationID, token: UUID) -> Invitation:
        """
        Raises:
            InvitationNotFoundError
            InvitationAlreadyDeletedError
        """
        raise NotImplementedError()
