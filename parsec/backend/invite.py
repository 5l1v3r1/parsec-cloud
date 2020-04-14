# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import attr
from uuid import UUID, uuid4
from typing import List, Optional
from pendulum import Pendulum, now as pendulum_now

from parsec.api.protocol import (
    OrganizationID,
    UserID,
    HumanHandle,
    InvitationType,
    InvitationDeletedReason,
    InvitationStatus,
    invite_new_serializer,
    invite_delete_serializer,
    invite_list_serializer,
    invite_info_serializer,
    invite_1_wait_peer_serializer,
    invite_2_send_hash_nonce_serializer,
    invite_2_get_hashed_nonce_serializer,
    invite_2_send_nonce_serializer,
    invite_3_wait_peer_trust_serializer,
    invite_3_signify_trust_serializer,
    invite_4_communicate_serializer,
)
from parsec.backend.utils import catch_protocol_errors, api


class InvitationError(Exception):
    pass


class InvitationAlreadyExistsError(InvitationError):
    pass


class InvitationNotFoundError(InvitationError):
    pass


class InvitationAlreadyDeletedError(InvitationError):
    pass


@attr.s(slots=True, frozen=True, auto_attribs=True)
class Invitation:
    token: UUID
    type: InvitationType
    created: Pendulum
    inviter_user_id: UserID
    inviter_human_handle: HumanHandle
    invitee_email: Optional[str]
    status: InvitationStatus = InvitationStatus.IDLE
    deleted_reason: Optional[InvitationDeletedReason] = None


class BaseInviteComponent:
    @api("invite_new", auth="authenticated")
    @catch_protocol_errors
    async def invite_new(self, client_ctx, msg):
        msg = invite_new_serializer.req_load(msg)
        # TODO: implement send email feature
        if msg["send_email"]:
            return invite_new_serializer.rep_dump({"status": "not_implemented"})
        invitation = Invitation(
            token=uuid4(), type=msg["type"], author=client_ctx.user_id, created=pendulum_now()
        )
        try:
            await self.new(organization_id=client_ctx.organization_id, invitation=invitation)

        except InvitationAlreadyExistsError:
            return {"status": "already_exists"}

        return invite_new_serializer.rep_dump({"status": "ok", "token": invitation.token})

    @api("invite_delete", auth="authenticated")
    @catch_protocol_errors
    async def invite_delete(self, client_ctx, msg):
        msg = invite_delete_serializer.req_load(msg)
        try:
            await self.delete(
                organization_id=client_ctx.organization_id,
                author=client_ctx.user_id,
                token=msg["token"],
                reason=msg["reason"],
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        return invite_delete_serializer.rep_dump({"status": "ok"})

    @api("invite_list", auth="authenticated")
    @catch_protocol_errors
    async def invite_list(self, client_ctx, msg):
        msg = invite_list_serializer.req_load(msg)
        invitations = await self.list(
            organization_id=client_ctx.organization_id, author=client_ctx.user_id
        )
        return invite_list_serializer.rep_dump(
            {
                "invitations": [
                    {
                        "token": item.token,
                        "type": item.type,
                        "created": item.created,
                        "status": item.status,
                        "deleted_reason": item.deleted_reason,
                    }
                    for item in invitations
                ]
            }
        )

    @api("invite_info", auth="anonymous")
    @catch_protocol_errors
    async def invite_info(self, client_ctx, msg):
        invite_info_serializer.req_load(msg)
        try:
            invitation = await self.info(
                organization_id=client_ctx.organization_id, token=client_ctx.token
            )

        except InvitationNotFoundError:
            return {"status": "not_found"}

        except InvitationAlreadyDeletedError:
            return {"status": "already_deleted"}

        return invite_info_serializer.rep_dump(
            {
                "type": invitation.type,
                "email": invitation.email,
                "inviter_human_email": invitation.inviter_human_email,
                "inviter_human_label": invitation.inviter_human_label,
            }
        )

    @api("invite_1_wait_peer", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_1_wait_peer(self, client_ctx, msg):
        msg = invite_1_wait_peer_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_1_wait_peer_serializer.rep_dump(rep)

    @api("invite_2_send_hash_nonce", auth="anonymous")
    @catch_protocol_errors
    async def invite_2_send_hash_nonce(self, client_ctx, msg):
        msg = invite_2_send_hash_nonce_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_2_send_hash_nonce_serializer.rep_dump(rep)

    @api("invite_2_get_hashed_nonce", auth="authenticated")
    @catch_protocol_errors
    async def invite_2_get_hashed_nonce(self, client_ctx, msg):
        msg = invite_2_get_hashed_nonce_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_2_get_hashed_nonce_serializer.rep_dump(rep)

    @api("invite_2_send_nonce", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_2_send_nonce(self, client_ctx, msg):
        msg = invite_2_send_nonce_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_2_send_nonce_serializer.rep_dump(rep)

    @api("invite_3_wait_peer_trust", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_3_wait_peer_trust(self, client_ctx, msg):
        msg = invite_3_wait_peer_trust_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_3_wait_peer_trust_serializer.rep_dump(rep)

    @api("invite_3_signify_trust", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_3_signify_trust(self, client_ctx, msg):
        msg = invite_3_signify_trust_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_3_signify_trust_serializer.rep_dump(rep)

    @api("invite_4_communicate", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_4_communicate(self, client_ctx, msg):
        msg = invite_4_communicate_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_4_communicate_serializer.rep_dump(rep)

    async def new(self, organization_id: OrganizationID, invitation: Invitation) -> None:
        raise NotImplementedError()

    async def delete(
        self,
        organization_id: OrganizationID,
        author: UserID,
        token: UUID,
        reason: InvitationDeletedReason,
    ) -> None:
        raise NotImplementedError()

    async def list(self, organization_id: OrganizationID, author: UserID) -> List[Invitation]:
        raise NotImplementedError()

    async def info(self, organization_id: OrganizationID, token: UUID) -> Invitation:
        raise NotImplementedError()
