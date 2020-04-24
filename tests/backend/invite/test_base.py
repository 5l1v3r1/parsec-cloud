# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pytest
from unittest.mock import ANY
from pendulum import Pendulum

from parsec.api.transport import TransportError
from parsec.api.protocol import (
    InvitationType,
    InvitationStatus,
    InvitationDeletedReason,
    HandshakeInvitedOperation,
    HandshakeBadIdentity,
)
from parsec.backend.invite import DeviceInvitation

from tests.common import freeze_time
from tests.backend.common import invite_new, invite_list, invite_delete, invite_info


@pytest.mark.trio
async def test_user_create_and_info(
    backend, alice, alice_backend_sock, backend_invited_sock_factory
):
    with freeze_time("2000-01-02"):
        rep = await invite_new(
            alice_backend_sock, type=InvitationType.USER, invitee_email="zack@example.com"
        )
    assert rep == {"status": "ok", "token": ANY}
    token = rep["token"]

    rep = await invite_list(alice_backend_sock)
    assert rep == {
        "status": "ok",
        "invitations": [
            {
                "type": InvitationType.USER,
                "token": token,
                "created_on": Pendulum(2000, 1, 2),
                "invitee_email": "zack@example.com",
                "status": InvitationStatus.IDLE,
                "deleted_on": None,
                "deleted_reason": None,
            }
        ],
    }

    async with backend_invited_sock_factory(
        backend,
        organization_id=alice.organization_id,
        operation=HandshakeInvitedOperation.CLAIM_USER,
        token=token,
    ) as invited_sock:
        rep = await invite_info(invited_sock)
        assert rep == {
            "status": "ok",
            "type": InvitationType.USER,
            "invitee_email": "zack@example.com",
            "inviter_user_id": alice.user_id,
            "inviter_human_handle": alice.human_handle,
        }


@pytest.mark.trio
async def test_device_create_and_info(
    backend, alice, alice_backend_sock, backend_invited_sock_factory
):
    with freeze_time("2000-01-02"):
        rep = await invite_new(alice_backend_sock, type=InvitationType.DEVICE)
    assert rep == {"status": "ok", "token": ANY}
    token = rep["token"]

    rep = await invite_list(alice_backend_sock)
    assert rep == {
        "status": "ok",
        "invitations": [
            {
                "type": InvitationType.DEVICE,
                "token": token,
                "created_on": Pendulum(2000, 1, 2),
                "status": InvitationStatus.IDLE,
                "deleted_on": None,
                "deleted_reason": None,
            }
        ],
    }

    async with backend_invited_sock_factory(
        backend,
        organization_id=alice.organization_id,
        operation=HandshakeInvitedOperation.CLAIM_DEVICE,
        token=token,
    ) as invited_sock:
        rep = await invite_info(invited_sock)
        assert rep == {
            "status": "ok",
            "type": InvitationType.DEVICE,
            "inviter_user_id": alice.user_id,
            "inviter_human_handle": alice.human_handle,
        }


@pytest.mark.trio
async def test_delete(alice, backend, alice_backend_sock, backend_invited_sock_factory):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id,
        inviter_human_handle=alice.human_handle,
        created_on=Pendulum(2000, 1, 2),
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)

    with freeze_time("2000-01-03"):
        rep = await invite_delete(
            alice_backend_sock, token=invitation.token, reason=InvitationDeletedReason.CANCELLED
        )
    assert rep == {"status": "ok"}

    rep = await invite_list(alice_backend_sock)
    assert rep == {
        "status": "ok",
        "invitations": [
            {
                "type": InvitationType.DEVICE,
                "token": invitation.token,
                "created_on": Pendulum(2000, 1, 2),
                "status": InvitationStatus.DELETED,
                "deleted_on": Pendulum(2000, 1, 3),
                "deleted_reason": InvitationDeletedReason.CANCELLED,
            }
        ],
    }

    # Can no longer use this invitation to connect to the backend
    with pytest.raises(HandshakeBadIdentity):
        async with backend_invited_sock_factory(
            backend,
            organization_id=alice.organization_id,
            operation=HandshakeInvitedOperation.CLAIM_DEVICE,
            token=invitation.token,
        ):
            pass


@pytest.mark.trio
async def test_delete_invitation_while_invitee_connected(
    backend, alice, backend_invited_sock_factory
):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id, inviter_human_handle=alice.human_handle
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)

    other_invitation = DeviceInvitation(
        inviter_user_id=alice.user_id, inviter_human_handle=alice.human_handle
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=other_invitation)

    # Invitation is valid so handshake is allowed
    async with backend_invited_sock_factory(
        backend,
        organization_id=alice.organization_id,
        operation=HandshakeInvitedOperation.CLAIM_DEVICE,
        token=invitation.token,
        freeze_on_transport_error=False,
    ) as invited_sock:
        async with backend_invited_sock_factory(
            backend,
            organization_id=alice.organization_id,
            operation=HandshakeInvitedOperation.CLAIM_DEVICE,
            token=other_invitation.token,
            freeze_on_transport_error=False,
        ) as other_invited_sock:

            # Delete the invitation, invitee connection should be closed automatically
            await backend.invite.delete(
                organization_id=alice.organization_id,
                inviter=alice.user_id,
                token=invitation.token,
                on=Pendulum(2000, 1, 2),
                reason=InvitationDeletedReason.ROTTEN,
            )

            with pytest.raises(TransportError):
                await invite_info(invited_sock)

            # However other invitation shouldn't have been affected
            rep = await invite_info(other_invited_sock)
            assert rep["status"] == "ok"


@pytest.mark.trio
async def test_already_deleted(alice, backend, alice_backend_sock, backend_invited_sock_factory):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id, inviter_human_handle=alice.human_handle
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)

    await backend.invite.delete(
        organization_id=alice.organization_id,
        inviter=alice.user_id,
        token=invitation.token,
        on=Pendulum(2000, 1, 2),
        reason=InvitationDeletedReason.ROTTEN,
    )

    rep = await invite_delete(
        alice_backend_sock, token=invitation.token, reason=InvitationDeletedReason.CANCELLED
    )
    assert rep == {"status": "already_deleted"}


@pytest.mark.trio
async def test_isolated_between_users(
    alice, bob, backend, backend_invited_sock_factory, alice_backend_sock
):
    invitation = DeviceInvitation(
        inviter_user_id=bob.user_id, inviter_human_handle=bob.human_handle
    )
    await backend.invite.new(organization_id=bob.organization_id, invitation=invitation)

    rep = await invite_list(alice_backend_sock)
    assert rep == {"status": "ok", "invitations": []}

    rep = await invite_delete(
        alice_backend_sock, token=invitation.token, reason=InvitationDeletedReason.CANCELLED
    )
    assert rep == {"status": "not_found"}


@pytest.mark.trio
async def test_isolated_between_organizations(
    alice, otheralice, backend, backend_invited_sock_factory, alice_backend_sock
):
    invitation = DeviceInvitation(
        inviter_user_id=otheralice.user_id, inviter_human_handle=otheralice.human_handle
    )
    await backend.invite.new(organization_id=otheralice.organization_id, invitation=invitation)

    rep = await invite_list(alice_backend_sock)
    assert rep == {"status": "ok", "invitations": []}

    rep = await invite_delete(
        alice_backend_sock, token=invitation.token, reason=InvitationDeletedReason.CANCELLED
    )
    assert rep == {"status": "not_found"}

    with pytest.raises(HandshakeBadIdentity):
        async with backend_invited_sock_factory(
            backend,
            organization_id=alice.organization_id,
            operation=HandshakeInvitedOperation.CLAIM_DEVICE,
            token=invitation.token,
        ):
            pass