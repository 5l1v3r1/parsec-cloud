# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import trio
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
@pytest.mark.parametrize("order", ["invitee_first", "inviter_first"])
async def test_conduit_exchange(
    mock_clock, backend, alice, alice_backend_sock, invitation, invited_sock, order
):
    mock_clock.autojump_threshold = 0
    invitee_privkey = PrivateKey.generate()
    inviter_privkey = PrivateKey.generate()

    async def _do_invitee(sleep_before_req_time):
        await trio.sleep(sleep_before_req_time)
        rep = await invite_1_invitee_wait_peer(
            invited_sock, invitee_public_key=invitee_privkey.public_key
        )
        assert rep == {"status": "ok", "inviter_public_key": inviter_privkey.public_key}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_2_invitee_send_hashed_nonce(
            invited_sock, invitee_hashed_nonce=b"<invitee_hashed_nonce>"
        )
        assert rep == {"status": "ok", "inviter_nonce": b"<inviter_nonce>"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_2_invitee_send_nonce(invited_sock, invitee_nonce=b"<invitee_nonce>")
        assert rep == {"status": "ok"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_3_invitee_signify_trust(invited_sock)
        assert rep == {"status": "ok"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_3_invitee_wait_peer_trust(invited_sock)
        assert rep == {"status": "ok"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_4_invitee_communicate(invited_sock, payload=None)
        assert rep == {"status": "ok", "payload": b"<hello from inviter !>"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_4_invitee_communicate(invited_sock, payload=b"<hello from invitee !>")
        assert rep == {"status": "ok", "payload": None}

    async def _do_inviter(sleep_before_req_time):
        await trio.sleep(sleep_before_req_time)
        rep = await invite_1_inviter_wait_peer(
            alice_backend_sock,
            token=invitation.token,
            inviter_public_key=inviter_privkey.public_key,
        )
        assert rep == {"status": "ok", "invitee_public_key": invitee_privkey.public_key}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_2_inviter_get_hashed_nonce(alice_backend_sock, token=invitation.token)
        assert rep == {"status": "ok", "invitee_hashed_nonce": b"<invitee_hashed_nonce>"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_2_inviter_send_nonce(
            alice_backend_sock, token=invitation.token, inviter_nonce=b"<inviter_nonce>"
        )
        assert rep == {"status": "ok", "invitee_nonce": b"<invitee_nonce>"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_3_inviter_wait_peer_trust(alice_backend_sock, token=invitation.token)
        assert rep == {"status": "ok"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_3_inviter_signify_trust(alice_backend_sock, token=invitation.token)
        assert rep == {"status": "ok"}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_4_inviter_communicate(
            alice_backend_sock, token=invitation.token, payload=b"<hello from inviter !>"
        )
        assert rep == {"status": "ok", "payload": None}

        await trio.sleep(sleep_before_req_time)
        rep = await invite_4_inviter_communicate(
            alice_backend_sock, token=invitation.token, payload=None
        )
        assert rep == {"status": "ok", "payload": b"<hello from invitee !>"}

    async with trio.open_nursery() as nursery:
        invitee_sleep_before_req_time = 0 if order == "invitee_first" else 1
        inviter_sleep_before_req_time = 0 if order == "inviter_first" else 1

        nursery.start_soon(_do_invitee, invitee_sleep_before_req_time)
        nursery.start_soon(_do_inviter, inviter_sleep_before_req_time)
