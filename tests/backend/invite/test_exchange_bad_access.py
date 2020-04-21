# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pytest
import trio
from uuid import uuid4
from pendulum import Pendulum

from parsec.crypto import PrivateKey
from parsec.api.transport import TransportError
from parsec.api.protocol import (
    InvitationType,
    InvitationStatus,
    InvitationDeletedReason,
    HandshakeInvitedOperation,
)
from parsec.backend.invite import DeviceInvitation

from tests.backend.common import (
    invite_list,
    invite_1_invitee_wait_peer,
    invite_1_inviter_wait_peer,
    invite_2a_invitee_send_hashed_nonce,
    invite_2a_inviter_get_hashed_nonce,
    invite_2b_inviter_send_nonce,
    invite_2b_invitee_send_nonce,
    invite_3a_inviter_wait_peer_trust,
    invite_3a_invitee_signify_trust,
    invite_3b_invitee_wait_peer_trust,
    invite_3b_inviter_signify_trust,
    invite_4_inviter_communicate,
    invite_4_invitee_communicate,
)


@pytest.mark.trio
@pytest.mark.parametrize("type", ("deleted_invitation", "unknown_token"))
async def test_inviter_exchange_bad_access(alice, backend, alice_backend_sock, type):
    if type == "deleted_invitation":
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
        token = invitation.token
        status = "already_deleted"
    else:
        token = uuid4()
        status = "not_found"

    inviter_privkey = PrivateKey.generate()
    with trio.fail_after(1):
        rep = await invite_1_inviter_wait_peer(
            alice_backend_sock, token=token, inviter_public_key=inviter_privkey.public_key
        )
    assert rep == {"status": status}

    with trio.fail_after(1):
        rep = await invite_2a_inviter_get_hashed_nonce(alice_backend_sock, token=token)
    assert rep == {"status": status}

    with trio.fail_after(1):
        rep = await invite_2b_inviter_send_nonce(
            alice_backend_sock, token=token, inviter_nonce=b"<inviter_nonce>"
        )
    assert rep == {"status": status}

    with trio.fail_after(1):
        rep = await invite_3a_inviter_wait_peer_trust(alice_backend_sock, token=token)
    assert rep == {"status": status}

    with trio.fail_after(1):
        rep = await invite_3b_inviter_signify_trust(alice_backend_sock, token=token)
    assert rep == {"status": status}

    with trio.fail_after(1):
        rep = await invite_4_inviter_communicate(
            alice_backend_sock, token=token, payload=b"<payload>"
        )
    assert rep == {"status": status}


@pytest.mark.trio
@pytest.mark.parametrize(
    "action",
    (
        "1_wait_peer",
        "2a_send_hashed_nonce",
        "2b_send_nonce",
        "3a_signify_trust",
        "3b_wait_peer_trust",
        "4_communicate",
    ),
)
async def test_invitee_exchange_bad_access(
    alice, backend, backend_invited_sock_factory, action, monitor
):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id, inviter_human_handle=alice.human_handle
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)

    async with backend_invited_sock_factory(
        backend,
        organization_id=alice.organization_id,
        operation=HandshakeInvitedOperation.CLAIM_DEVICE,
        token=invitation.token,
        freeze_on_transport_error=False,
    ) as invited_sock:

        if action == "1_wait_peer":
            invitee_privkey = PrivateKey.generate()
            async_call_ctx = invite_1_invitee_wait_peer.async_call(
                invited_sock, invitee_public_key=invitee_privkey.public_key
            )
        elif action == "2a_send_hashed_nonce":
            async_call_ctx = invite_2a_invitee_send_hashed_nonce.async_call(
                invited_sock, invitee_hashed_nonce=b"<invitee_hashed_nonce>"
            )
        elif action == "2b_send_nonce":
            async_call_ctx = invite_2b_invitee_send_nonce.async_call(
                invited_sock, invitee_nonce=b"<invitee_nonce>"
            )
        elif action == "3a_signify_trust":
            async_call_ctx = invite_3a_invitee_signify_trust.async_call(invited_sock)
        elif action == "3b_wait_peer_trust":
            async_call_ctx = invite_3b_invitee_wait_peer_trust.async_call(invited_sock)
        elif action == "4_communicate":
            async_call_ctx = invite_4_invitee_communicate.async_call(
                invited_sock, payload=b"<payload>"
            )

        await backend.invite.delete(
            organization_id=alice.organization_id,
            inviter=alice.user_id,
            token=invitation.token,
            on=Pendulum(2000, 1, 2),
            reason=InvitationDeletedReason.ROTTEN,
        )
        async with async_call_ctx as async_rep:
            with trio.fail_after(1):
                with pytest.raises(TransportError):
                    await async_rep.do_recv()


@pytest.mark.trio
async def test_exchange_start_change_invitation_status(
    alice, backend, alice_backend_sock, backend_invited_sock_factory
):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id,
        inviter_human_handle=alice.human_handle,
        created_on=Pendulum(2000, 1, 2),
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)

    with trio.CancelScope() as cancel_scope:
        async with backend_invited_sock_factory(
            backend,
            organization_id=alice.organization_id,
            operation=HandshakeInvitedOperation.CLAIM_DEVICE,
            token=invitation.token,
        ) as invited_sock:

            invitee_privkey = PrivateKey.generate()
            async with invite_1_invitee_wait_peer.async_call(
                invited_sock, invitee_public_key=invitee_privkey.public_key
            ):

                rep = await invite_list(alice_backend_sock)
                assert rep == {
                    "status": "ok",
                    "invitations": [
                        {
                            "type": InvitationType.DEVICE,
                            "token": invitation.token,
                            "created_on": Pendulum(2000, 1, 2),
                            "status": InvitationStatus.READY,
                            "deleted_on": None,
                            "deleted_reason": None,
                        }
                    ],
                }

                # All good, just cancel the invitee request
                cancel_scope.cancel()
