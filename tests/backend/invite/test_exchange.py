# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pytest
import trio
from pendulum import Pendulum

from parsec.crypto import PrivateKey
from parsec.api.protocol import HandshakeInvitedOperation
from parsec.backend.invite import DeviceInvitation

from tests.backend.common import (
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


class PeerControler:
    def __init__(self):
        self._orders_sender, self._orders_receiver = trio.open_memory_channel(0)
        self._orders_ack_sender, self._orders_ack_receiver = trio.open_memory_channel(0)
        self._results_sender, self._results_receiver = trio.open_memory_channel(1)

    async def send_order(self, order, order_arg=None):
        assert self._results_receiver.statistics().current_buffer_used == 0
        await self._orders_sender.send((order, order_arg))
        await self._orders_ack_receiver.receive()

    async def get_result(self):
        return await self._results_receiver.receive()

    async def assert_ok_rep(self):
        rep = await self.get_result()
        assert rep["status"] == "ok"

    async def peer_do(self, action, *args, **kwargs):
        print("START", action.cmd)
        async with action.async_call(*args, **kwargs) as async_rep:
            print("DONE", action.cmd)
            await self._orders_ack_sender.send(None)
        print("REP", action.cmd, async_rep.rep)
        await self._results_sender.send(async_rep.rep)
        return True

    async def peer_next_order(self):
        return await self._orders_receiver.receive()


@pytest.fixture
async def exchange_testbed(backend, alice, alice_backend_sock, invitation, invited_sock):
    inviter_privkey = PrivateKey.generate()
    invitee_privkey = PrivateKey.generate()

    async def _run_inviter(peer_controller):
        while True:
            order, order_arg = await peer_controller.peer_next_order()

            if order == "1_wait_peer":
                await peer_controller.peer_do(
                    invite_1_inviter_wait_peer,
                    alice_backend_sock,
                    token=invitation.token,
                    inviter_public_key=inviter_privkey.public_key,
                )

            elif order == "2a_get_hashed_nonce":
                await peer_controller.peer_do(
                    invite_2a_inviter_get_hashed_nonce, alice_backend_sock, token=invitation.token
                )

            elif order == "2b_send_nonce":
                await peer_controller.peer_do(
                    invite_2b_inviter_send_nonce,
                    alice_backend_sock,
                    token=invitation.token,
                    inviter_nonce=b"<inviter_nonce>",
                )

            elif order == "3a_wait_peer_trust":
                await peer_controller.peer_do(
                    invite_3a_inviter_wait_peer_trust, alice_backend_sock, token=invitation.token
                )

            elif order == "3b_signify_trust":
                await peer_controller.peer_do(
                    invite_3b_inviter_signify_trust, alice_backend_sock, token=invitation.token
                )

            elif order == "4_communicate":
                await peer_controller.peer_do(
                    invite_4_inviter_communicate,
                    alice_backend_sock,
                    token=invitation.token,
                    payload=order_arg,
                )

            else:
                assert False

    async def _run_invitee(peer_controller):
        while True:
            order, order_arg = await peer_controller.peer_next_order()

            if order == "1_wait_peer":
                await peer_controller.peer_do(
                    invite_1_invitee_wait_peer,
                    invited_sock,
                    invitee_public_key=invitee_privkey.public_key,
                )

            elif order == "2a_send_hashed_nonce":
                await peer_controller.peer_do(
                    invite_2a_invitee_send_hashed_nonce,
                    invited_sock,
                    invitee_hashed_nonce=b"<invitee_hashed_nonce>",
                )

            elif order == "2b_send_nonce":
                await peer_controller.peer_do(
                    invite_2b_invitee_send_nonce, invited_sock, invitee_nonce=b"<invitee_nonce>"
                )

            elif order == "3a_signify_trust":
                await peer_controller.peer_do(invite_3a_invitee_signify_trust, invited_sock)

            elif order == "3b_wait_peer_trust":
                await peer_controller.peer_do(invite_3b_invitee_wait_peer_trust, invited_sock)

            elif order == "4_communicate":
                await peer_controller.peer_do(
                    invite_4_invitee_communicate, invited_sock, payload=order_arg
                )

            else:
                assert False

    inviter_ctlr = PeerControler()
    invitee_ctlr = PeerControler()
    async with trio.open_nursery() as nursery:
        nursery.start_soon(_run_inviter, inviter_ctlr)
        nursery.start_soon(_run_invitee, invitee_ctlr)

        yield inviter_privkey, invitee_privkey, inviter_ctlr, invitee_ctlr

        nursery.cancel_scope.cancel()


@pytest.mark.trio
@pytest.mark.parametrize("leader", ("invitee", "inviter"))
async def test_conduit_exchange_good(exchange_testbed, leader):
    inviter_privkey, invitee_privkey, inviter_ctlr, invitee_ctlr = exchange_testbed

    # Step 1
    if leader == "inviter":
        await inviter_ctlr.send_order("1_wait_peer")
        await invitee_ctlr.send_order("1_wait_peer")
    else:
        await invitee_ctlr.send_order("1_wait_peer")
        await inviter_ctlr.send_order("1_wait_peer")
    inviter_rep = await inviter_ctlr.get_result()
    invitee_rep = await invitee_ctlr.get_result()
    assert inviter_rep == {"status": "ok", "invitee_public_key": invitee_privkey.public_key}
    assert invitee_rep == {"status": "ok", "inviter_public_key": inviter_privkey.public_key}

    # Step 2
    if leader == "inviter":
        await inviter_ctlr.send_order("2a_get_hashed_nonce")
        await invitee_ctlr.send_order("2a_send_hashed_nonce")
    else:
        await invitee_ctlr.send_order("2a_send_hashed_nonce")
        await inviter_ctlr.send_order("2a_get_hashed_nonce")

    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "ok", "invitee_hashed_nonce": b"<invitee_hashed_nonce>"}
    await inviter_ctlr.send_order("2b_send_nonce")

    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "ok", "inviter_nonce": b"<inviter_nonce>"}
    await invitee_ctlr.send_order("2b_send_nonce")

    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "ok", "invitee_nonce": b"<invitee_nonce>"}
    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "ok"}

    # Step 3a
    if leader == "inviter":
        await inviter_ctlr.send_order("3a_wait_peer_trust")
        await invitee_ctlr.send_order("3a_signify_trust")
    else:
        await invitee_ctlr.send_order("3a_signify_trust")
        await inviter_ctlr.send_order("3a_wait_peer_trust")
    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "ok"}
    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "ok"}

    # Step 3b
    if leader == "inviter":
        await inviter_ctlr.send_order("3b_signify_trust")
        await invitee_ctlr.send_order("3b_wait_peer_trust")
    else:
        await invitee_ctlr.send_order("3b_wait_peer_trust")
        await inviter_ctlr.send_order("3b_signify_trust")
    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "ok"}
    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "ok"}

    # Step 4
    if leader == "inviter":
        await inviter_ctlr.send_order("4_communicate", b"hello from inviter")
        await invitee_ctlr.send_order("4_communicate", b"hello from invitee")
    else:
        await invitee_ctlr.send_order("4_communicate", b"hello from invitee")
        await inviter_ctlr.send_order("4_communicate", b"hello from inviter")
    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "ok", "payload": b"hello from invitee"}
    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "ok", "payload": b"hello from inviter"}

    if leader == "inviter":
        await inviter_ctlr.send_order("4_communicate", None)
        await invitee_ctlr.send_order("4_communicate", None)
    else:
        await invitee_ctlr.send_order("4_communicate", None)
        await inviter_ctlr.send_order("4_communicate", None)
    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "ok", "payload": None}
    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "ok", "payload": None}


@pytest.mark.trio
async def test_conduit_exchange_reset(exchange_testbed):
    inviter_privkey, invitee_privkey, inviter_ctlr, invitee_ctlr = exchange_testbed

    # Step 1
    await inviter_ctlr.send_order("1_wait_peer")
    await invitee_ctlr.send_order("1_wait_peer")
    await inviter_ctlr.assert_ok_rep()
    await invitee_ctlr.assert_ok_rep()

    # Invitee reset just before step 2a
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("1_wait_peer")
            await inviter_ctlr.send_order("2a_get_hashed_nonce")
        else:
            await inviter_ctlr.send_order("2a_get_hashed_nonce")
            await invitee_ctlr.send_order("1_wait_peer")
        inviter_rep = await inviter_ctlr.get_result()
        assert inviter_rep == {"status": "invalid_state"}
        await inviter_ctlr.send_order("1_wait_peer")
        await inviter_ctlr.assert_ok_rep()
        await invitee_ctlr.assert_ok_rep()

    # Inviter reset just before step 2a
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("2a_send_hashed_nonce")
            await inviter_ctlr.send_order("1_wait_peer")
        else:
            await inviter_ctlr.send_order("1_wait_peer")
            await invitee_ctlr.send_order("2a_send_hashed_nonce")
        invitee_rep = await invitee_ctlr.get_result()
        assert invitee_rep == {"status": "invalid_state"}
        await invitee_ctlr.send_order("1_wait_peer")
        await invitee_ctlr.assert_ok_rep()
        await inviter_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    inviter_rep = await inviter_ctlr.assert_ok_rep()
    # Inviter reset after retreiving invitee hashed nonce
    await inviter_ctlr.send_order("1_wait_peer")
    invitee_rep = await invitee_ctlr.get_result()
    assert invitee_rep == {"status": "invalid_state"}
    await invitee_ctlr.send_order("1_wait_peer")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    # Invitee reset after retreiving inviter nonce
    await invitee_ctlr.send_order("1_wait_peer")
    inviter_rep = await inviter_ctlr.get_result()
    assert inviter_rep == {"status": "invalid_state"}
    await inviter_ctlr.send_order("1_wait_peer")
    await inviter_ctlr.assert_ok_rep()
    await invitee_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await invitee_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Inviter reset just before step 3a
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("3a_signify_trust")
            await inviter_ctlr.send_order("1_wait_peer")
        else:
            await inviter_ctlr.send_order("1_wait_peer")
            await invitee_ctlr.send_order("3a_signify_trust")
        invitee_rep = await invitee_ctlr.get_result()
        assert invitee_rep == {"status": "invalid_state"}
        await invitee_ctlr.send_order("1_wait_peer")
        await invitee_ctlr.assert_ok_rep()
        await inviter_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await invitee_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Invitee reset just before step 3a
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("1_wait_peer")
            await inviter_ctlr.send_order("3a_wait_peer_trust")
        else:
            await inviter_ctlr.send_order("3a_wait_peer_trust")
            await invitee_ctlr.send_order("1_wait_peer")
        inviter_rep = await inviter_ctlr.get_result()
        assert inviter_rep == {"status": "invalid_state"}
        await inviter_ctlr.send_order("1_wait_peer")
        await inviter_ctlr.assert_ok_rep()
        await invitee_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await invitee_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Step 3a
    await inviter_ctlr.send_order("3a_wait_peer_trust")
    await invitee_ctlr.send_order("3a_signify_trust")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Inviter reset just before step 3b
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("3b_wait_peer_trust")
            await inviter_ctlr.send_order("1_wait_peer")
        else:
            await inviter_ctlr.send_order("1_wait_peer")
            await invitee_ctlr.send_order("3b_wait_peer_trust")
        invitee_rep = await invitee_ctlr.get_result()
        assert invitee_rep == {"status": "invalid_state"}
        await invitee_ctlr.send_order("1_wait_peer")
        await invitee_ctlr.assert_ok_rep()
        await inviter_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await invitee_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Step 3a
    await inviter_ctlr.send_order("3a_wait_peer_trust")
    await invitee_ctlr.send_order("3a_signify_trust")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Invitee reset just before step 3b
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("1_wait_peer")
            await inviter_ctlr.send_order("3b_signify_trust")
        else:
            await inviter_ctlr.send_order("3b_signify_trust")
            await invitee_ctlr.send_order("1_wait_peer")
        inviter_rep = await inviter_ctlr.get_result()
        assert inviter_rep == {"status": "invalid_state"}
        await inviter_ctlr.send_order("1_wait_peer")
        await inviter_ctlr.assert_ok_rep()
        await invitee_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await invitee_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Step 3a
    await inviter_ctlr.send_order("3a_wait_peer_trust")
    await invitee_ctlr.send_order("3a_signify_trust")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Step 3b
    await inviter_ctlr.send_order("3b_signify_trust")
    await invitee_ctlr.send_order("3b_wait_peer_trust")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Inviter reset just before step 4
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("4_communicate")
            await inviter_ctlr.send_order("1_wait_peer")
        else:
            await inviter_ctlr.send_order("1_wait_peer")
            await invitee_ctlr.send_order("4_communicate")
        invitee_rep = await invitee_ctlr.get_result()
        assert invitee_rep == {"status": "invalid_state"}
        await invitee_ctlr.send_order("1_wait_peer")
        await invitee_ctlr.assert_ok_rep()
        await inviter_ctlr.assert_ok_rep()

    # Step 2a
    await inviter_ctlr.send_order("2a_get_hashed_nonce")
    await invitee_ctlr.send_order("2a_send_hashed_nonce")
    await inviter_ctlr.assert_ok_rep()
    # Step 2b
    await inviter_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await invitee_ctlr.send_order("2b_send_nonce")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Step 3a
    await inviter_ctlr.send_order("3a_wait_peer_trust")
    await invitee_ctlr.send_order("3a_signify_trust")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Step 3b
    await inviter_ctlr.send_order("3b_signify_trust")
    await invitee_ctlr.send_order("3b_wait_peer_trust")
    await invitee_ctlr.assert_ok_rep()
    await inviter_ctlr.assert_ok_rep()
    # Invitee reset just before step 4
    for leader in ("invitee", "inviter"):
        if leader == "invitee":
            await invitee_ctlr.send_order("1_wait_peer")
            await inviter_ctlr.send_order("4_communicate")
        else:
            await inviter_ctlr.send_order("4_communicate")
            await invitee_ctlr.send_order("1_wait_peer")
        inviter_rep = await inviter_ctlr.get_result()
        assert inviter_rep == {"status": "invalid_state"}
        await inviter_ctlr.send_order("1_wait_peer")
        await inviter_ctlr.assert_ok_rep()
        await invitee_ctlr.assert_ok_rep()
