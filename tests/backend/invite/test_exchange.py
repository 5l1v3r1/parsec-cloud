# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pytest
from pendulum import Pendulum

from parsec.crypto import PrivateKey
from parsec.api.protocol import HandshakeInvitedOperation
from parsec.backend.invite import DeviceInvitation

from tests.backend.common import (
    invite_1_invitee_wait_peer,
    invite_1_inviter_wait_peer,
    invite_2_invitee_send_hashed_nonce,
    invite_2_inviter_get_hashed_nonce,
    invite_2_inviter_send_nonce,
    invite_2_invitee_send_nonce,
    invite_3_inviter_wait_peer_trust,
    invite_3_invitee_wait_peer_trust,
    invite_3_inviter_signify_trust,
    invite_3_invitee_signify_trust,
    invite_4_inviter_communicate,
    invite_4_invitee_communicate,
)


@pytest.fixture
async def invitation(backend, alice):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id,
        inviter_human_handle=alice.human_handle,
        created_on=Pendulum(2000, 1, 2),
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)
    return invitation


@pytest.fixture
async def invited_sock(backend, backend_invited_sock_factory, alice, invitation):
    async with backend_invited_sock_factory(
        backend,
        organization_id=alice.organization_id,
        operation=HandshakeInvitedOperation.CLAIM_DEVICE,
        token=invitation.token,
    ) as invited_sock:
        yield invited_sock


@pytest.mark.trio
async def test_conduit_exchange_invitee_leader(
    backend, alice, alice_backend_sock, invitation, invited_sock
):
    invitee_privkey = PrivateKey.generate()
    inviter_privkey = PrivateKey.generate()

    # Step 1

    async with invite_1_invitee_wait_peer.async_call(
        invited_sock, invitee_public_key=invitee_privkey.public_key
    ) as invitee_async_rep:
        inviter_rep = await invite_1_inviter_wait_peer(
            alice_backend_sock,
            token=invitation.token,
            inviter_public_key=inviter_privkey.public_key,
        )
        assert inviter_rep == {"status": "ok", "invitee_public_key": invitee_privkey.public_key}
    assert invitee_async_rep.rep == {
        "status": "ok",
        "inviter_public_key": inviter_privkey.public_key,
    }

    # Step 2

    async with invite_2_invitee_send_hashed_nonce.async_call(
        invited_sock, invitee_hashed_nonce=b"<invitee_hashed_nonce>"
    ) as invitee_async_rep:

        inviter_rep = await invite_2_inviter_get_hashed_nonce(
            alice_backend_sock, token=invitation.token
        )
        assert inviter_rep == {"status": "ok", "invitee_hashed_nonce": b"<invitee_hashed_nonce>"}

        async with invite_2_inviter_send_nonce.async_call(
            alice_backend_sock, token=invitation.token, inviter_nonce=b"<inviter_nonce>"
        ) as inviter_async_rep:

            await invitee_async_rep.do_recv()
            assert invitee_async_rep.rep == {"status": "ok", "inviter_nonce": b"<inviter_nonce>"}

            invitee_rep = await invite_2_invitee_send_nonce(
                invited_sock, invitee_nonce=b"<invitee_nonce>"
            )
            assert invitee_rep == {"status": "ok"}

        assert inviter_async_rep.rep == {"status": "ok", "invitee_nonce": b"<invitee_nonce>"}

    # Step 3

    async with invite_3_invitee_signify_trust.async_call(invited_sock) as invitee_async_rep:
        inviter_rep = await invite_3_inviter_wait_peer_trust(
            alice_backend_sock, token=invitation.token
        )
        assert inviter_rep == {"status": "ok"}
    assert invitee_async_rep.rep == {"status": "ok"}

    async with invite_3_invitee_wait_peer_trust.async_call(invited_sock) as invitee_async_rep:
        inviter_rep = await invite_3_inviter_signify_trust(
            alice_backend_sock, token=invitation.token
        )
        assert inviter_rep == {"status": "ok"}
    assert invitee_async_rep.rep == {"status": "ok"}

    # Step 4

    async with invite_4_invitee_communicate.async_call(
        invited_sock, payload=None
    ) as invitee_async_rep:
        inviter_rep = await invite_4_inviter_communicate(
            alice_backend_sock, token=invitation.token, payload=b"<hello from inviter !>"
        )
        assert inviter_rep == {"status": "ok", "payload": None}
    assert invitee_async_rep.rep == {"status": "ok", "payload": b"<hello from inviter !>"}

    async with invite_4_inviter_communicate.async_call(
        alice_backend_sock, token=invitation.token, payload=None
    ) as inviter_async_rep:
        invitee_rep = await invite_4_invitee_communicate(
            invited_sock, payload=b"<hello from invitee !>"
        )
        assert invitee_rep == {"status": "ok", "payload": None}
    assert inviter_async_rep.rep == {"status": "ok", "payload": b"<hello from invitee !>"}


@pytest.mark.trio
async def test_conduit_exchange_inviter_leader(
    backend, alice, alice_backend_sock, invitation, invited_sock
):
    invitee_privkey = PrivateKey.generate()
    inviter_privkey = PrivateKey.generate()

    # Step 1

    async with invite_1_inviter_wait_peer.async_call(
        alice_backend_sock, token=invitation.token, inviter_public_key=inviter_privkey.public_key
    ) as inviter_async_rep:
        invitee_rep = await invite_1_invitee_wait_peer(
            invited_sock, invitee_public_key=invitee_privkey.public_key
        )
        assert invitee_rep == {"status": "ok", "inviter_public_key": inviter_privkey.public_key}
    assert inviter_async_rep.rep == {
        "status": "ok",
        "invitee_public_key": invitee_privkey.public_key,
    }

    # Step 2

    async with invite_2_inviter_get_hashed_nonce.async_call(
        alice_backend_sock, token=invitation.token
    ) as inviter_async_rep:
        async with invite_2_invitee_send_hashed_nonce.async_call(
            invited_sock, invitee_hashed_nonce=b"<invitee_hashed_nonce>"
        ) as invitee_async_rep:

            await inviter_async_rep.do_recv()
            assert inviter_async_rep.rep == {
                "status": "ok",
                "invitee_hashed_nonce": b"<invitee_hashed_nonce>",
            }

            async with invite_2_inviter_send_nonce.async_call(
                alice_backend_sock, token=invitation.token, inviter_nonce=b"<inviter_nonce>"
            ) as inviter_async_rep:

                await invitee_async_rep.do_recv()
                assert invitee_async_rep.rep == {
                    "status": "ok",
                    "inviter_nonce": b"<inviter_nonce>",
                }

                invitee_rep = await invite_2_invitee_send_nonce(
                    invited_sock, invitee_nonce=b"<invitee_nonce>"
                )
                assert invitee_rep == {"status": "ok"}

            assert inviter_async_rep.rep == {"status": "ok", "invitee_nonce": b"<invitee_nonce>"}

    # Step 3

    async with invite_3_inviter_wait_peer_trust.async_call(
        alice_backend_sock, token=invitation.token
    ) as inviter_async_rep:
        invitee_rep = await invite_3_invitee_signify_trust(invited_sock)
        assert invitee_rep == {"status": "ok"}
    assert inviter_async_rep.rep == {"status": "ok"}

    async with invite_3_inviter_signify_trust.async_call(
        alice_backend_sock, token=invitation.token
    ) as inviter_async_rep:
        invitee_rep = await invite_3_invitee_wait_peer_trust(invited_sock)
        assert invitee_rep == {"status": "ok"}
    assert inviter_async_rep.rep == {"status": "ok"}

    # Step 4

    async with invite_4_inviter_communicate.async_call(
        alice_backend_sock, token=invitation.token, payload=None
    ) as inviter_async_rep:
        invitee_rep = await invite_4_invitee_communicate(
            invited_sock, payload=b"<hello from invitee !>"
        )
        assert invitee_rep == {"status": "ok", "payload": None}
    assert inviter_async_rep.rep == {"status": "ok", "payload": b"<hello from invitee !>"}

    async with invite_4_invitee_communicate.async_call(
        invited_sock, payload=None
    ) as invitee_async_rep:
        inviter_rep = await invite_4_inviter_communicate(
            alice_backend_sock, token=invitation.token, payload=b"<hello from inviter !>"
        )
        assert inviter_rep == {"status": "ok", "payload": None}
    assert invitee_async_rep.rep == {"status": "ok", "payload": b"<hello from inviter !>"}
