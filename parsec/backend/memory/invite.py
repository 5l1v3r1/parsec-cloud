# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import attr
from uuid import UUID
from typing import List
from collections import defaultdict

from parsec.api.protocol import OrganizationID, UserID, InvitationStatus, InvitationDeletedReason
from parsec.backend.invite import (
    BaseInviteComponent,
    Invitation,
    InvitationNotFoundError,
    InvitationAlreadyExistsError,
    InvitationAlreadyDeletedError,
)


@attr.s
class OrganizationStore:
    invitations = attr.ib(factory=list)


class MemoryInviteComponent(BaseInviteComponent):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._organizations = defaultdict(OrganizationStore)

    def register_components(self, **other_components):
        pass

    async def new(self, organization_id: OrganizationID, invitation: Invitation) -> None:
        org = self._organizations[organization_id]
        if invitation.token in org.invitations:
            raise InvitationAlreadyExistsError(invitation.token)
        org.invitations[invitation.token] = invitation.token

    async def delete(
        self,
        organization_id: OrganizationID,
        author: UserID,
        token: UUID,
        reason: InvitationDeletedReason,
    ) -> None:
        org = self._organizations[organization_id]
        invitation = org.invitations.get(token)
        if not invitation or invitation.author != author:
            raise InvitationNotFoundError(token)
        if invitation.status == InvitationStatus.DELETED:
            raise InvitationAlreadyDeletedError(token)
        org.invitations[token] = invitation.evolve(
            status=InvitationStatus.DELETED, deleted_reason=reason
        )

    async def list(self, organization_id: OrganizationID, author: UserID) -> List[Invitation]:
        org = self._organizations[organization_id]
        return [invitation for invitation in org.invitations if invitation.author == author]

    async def info(self, organization_id: OrganizationID, token: UUID) -> Invitation:
        org = self._organizations[organization_id]
        invitation = org.get(token)
        if not invitation:
            raise InvitationNotFoundError(token)
        if invitation.status == InvitationStatus.DELETED:
            raise InvitationAlreadyDeletedError(token)
        return invitation
