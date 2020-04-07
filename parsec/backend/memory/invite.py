# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import trio
import attr
from uuid import UUID
from typing import List, Optional
from collections import defaultdict
from pendulum import Pendulum

from parsec.api.protocol import OrganizationID, UserID, InvitationStatus, InvitationDeletedReason
from parsec.backend.invite import (
    ConduitState,
    NEXT_CONDUIT_STATE,
    BaseInviteComponent,
    Invitation,
    InvitationNotFoundError,
    InvitationAlreadyExistsError,
    InvitationAlreadyDeletedError,
    InvitationInvalidStateError,
)


class Conduit:
    def __init__(self):
        self.state = ConduitState.STATE_1_WAIT_PEERS
        self.invitee_send_channel, self.inviter_recv_channel = trio.open_memory_channel(0)
        self.inviter_send_channel, self.invitee_recv_channel = trio.open_memory_channel(0)


@attr.s
class OrganizationStore:
    invitations = attr.ib(factory=dict)
    conduits = attr.ib(factory=dict)


class MemoryInviteComponent(BaseInviteComponent):
    def __init__(self, send_event, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._send_event = send_event
        self._organizations = defaultdict(OrganizationStore)

    def register_components(self, **other_components):
        pass

    async def conduit_invitee_talk(
        self,
        organization_id: OrganizationID,
        token: UUID,
        state: ConduitState,
        payload: Optional[bytes] = None,
    ) -> bytes:
        return await self._conduit_talk(
            organization_id, token, state, payload, is_inviter=False, inviter=None
        )

    async def conduit_inviter_talk(
        self,
        organization_id: OrganizationID,
        inviter: UserID,
        token: UUID,
        state: ConduitState,
        payload: Optional[bytes] = None,
    ) -> bytes:
        return await self._conduit_talk(
            organization_id, token, state, payload, is_inviter=True, inviter=inviter
        )

    async def _conduit_talk(
        self,
        organization_id: OrganizationID,
        token: UUID,
        state: ConduitState,
        payload: Optional[bytes],
        is_inviter: bool,
        inviter: Optional[UserID],
    ) -> bytes:
        org = self._organizations[organization_id]
        invitation = org.invitations.get(token)
        if not invitation or (is_inviter and invitation.inviter_user_id != inviter):
            raise InvitationNotFoundError(token)
        if invitation.status == InvitationStatus.DELETED:
            raise InvitationAlreadyDeletedError(token)
        if not is_inviter and state == ConduitState.STATE_1_WAIT_PEERS:
            org.invitations[token] = invitation.evolve(status=InvitationStatus.READY)
        conduit = org.conduits.get(token)
        if not conduit:
            conduit = org.conduits[token] = Conduit()

        if is_inviter:
            send_channel = conduit.inviter_send_channel
            recv_channel = conduit.inviter_recv_channel
        else:
            send_channel = conduit.invitee_send_channel
            recv_channel = conduit.invitee_recv_channel

        if conduit.state != state:
            if state == ConduitState.STATE_1_WAIT_PEERS:
                # We are asked to reset the conduit
                conduit.state = ConduitState.STATE_1_WAIT_PEERS
                # If a peer is waiting, lure him into thinking we have answered
                # so he will realise the conduit has been reseted
                try:
                    recv_channel.receive_nowait()
                    await send_channel.send(None)
                except trio.WouldBlock:
                    pass
            else:
                raise InvitationInvalidStateError()

        next_state = NEXT_CONDUIT_STATE[conduit.state]
        try:
            # Try to receive in case the peer is already here
            peer_payload = recv_channel.receive_nowait()
            await send_channel.send(payload)
            # Wait for peer to signify us it has finished with the current state
            await recv_channel.receive()
            assert conduit.state == next_state
        except trio.WouldBlock:
            # We are first, block until the peer is here
            await send_channel.send(payload)
            peer_payload = await recv_channel.receive()
            # Make sure peer hasn't reset the conduit while we were waiting
            if conduit.state != state:
                raise InvitationInvalidStateError()
            # Prepare for next state and signify the current state is done to peer
            conduit.state = NEXT_CONDUIT_STATE[conduit.state]
            await send_channel.send(None)

        return peer_payload

    async def new(self, organization_id: OrganizationID, invitation: Invitation) -> None:
        org = self._organizations[organization_id]
        if invitation.token in org.invitations:
            raise InvitationAlreadyExistsError(invitation.token)
        org.invitations[invitation.token] = invitation

    async def delete(
        self,
        organization_id: OrganizationID,
        inviter: UserID,
        token: UUID,
        on: Pendulum,
        reason: InvitationDeletedReason,
    ) -> None:
        org = self._organizations[organization_id]
        invitation = org.invitations.get(token)
        if not invitation or invitation.inviter_user_id != inviter:
            raise InvitationNotFoundError(token)
        if invitation.status == InvitationStatus.DELETED:
            raise InvitationAlreadyDeletedError(token)
        org.invitations[token] = invitation.evolve(
            status=InvitationStatus.DELETED, deleted_on=on, deleted_reason=reason
        )
        await self._send_event(
            "invite.status_changed",
            organization_id=organization_id,
            inviter=inviter,
            token=token,
            status=InvitationStatus.DELETED,
        )

    async def list(self, organization_id: OrganizationID, inviter: UserID) -> List[Invitation]:
        org = self._organizations[organization_id]
        return [
            invitation
            for invitation in org.invitations.values()
            if invitation.inviter_user_id == inviter
        ]

    async def info(self, organization_id: OrganizationID, token: UUID) -> Invitation:
        org = self._organizations[organization_id]
        invitation = org.invitations.get(token)
        if not invitation:
            raise InvitationNotFoundError(token)
        if invitation.status == InvitationStatus.DELETED:
            raise InvitationAlreadyDeletedError(token)
        return invitation
