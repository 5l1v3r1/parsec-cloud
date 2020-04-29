# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pytest
import trio

from parsec.api.protocol import DeviceName, HandshakeInvitedOperation
from parsec.backend.invite import DeviceInvitation
from parsec.core.backend_connection import (
    backend_invited_cmds_factory,
    backend_authenticated_cmds_factory,
)
from parsec.core.types import BackendInvitationAddr, LocalDevice
from parsec.core.invite import claimer_retreive_info, DeviceClaimInitialCtx, DeviceGreetInitialCtx


@pytest.fixture
async def invitation_addr(backend, alice):
    invitation = DeviceInvitation(
        inviter_user_id=alice.user_id, inviter_human_handle=alice.human_handle
    )
    await backend.invite.new(organization_id=alice.organization_id, invitation=invitation)
    return BackendInvitationAddr.build(
        backend_addr=alice.organization_addr,
        organization_id=alice.organization_id,
        operation=HandshakeInvitedOperation.CLAIM_DEVICE,
        token=invitation.token,
    )


@pytest.mark.trio
async def test_good_device_claim(running_backend, alice, alice_backend_cmds, invitation_addr):
    requested_device_name = DeviceName("Foo")
    used_device_name = DeviceName("Bar")
    new_device = None

    # Simulate out-of-bounds canal
    oob_send, oob_recv = trio.open_memory_channel(0)

    async def _run_claimer():
        async with backend_invited_cmds_factory(addr=invitation_addr) as cmds:
            initial_ctx = await claimer_retreive_info(cmds)
            assert isinstance(initial_ctx, DeviceClaimInitialCtx)
            assert initial_ctx.greeter_user_id == alice.user_id
            assert initial_ctx.greeter_human_handle == alice.human_handle

            in_progress_ctx = await initial_ctx.do_wait_peer()

            choices = in_progress_ctx.generate_greeter_sas_choices(size=4)
            assert len(choices) == 4
            assert in_progress_ctx.greeter_sas in choices

            greeter_sas = await oob_recv.receive()
            assert greeter_sas == in_progress_ctx.greeter_sas

            in_progress_ctx = await in_progress_ctx.do_signify_trust()
            await oob_send.send(in_progress_ctx.claimer_sas)

            in_progress_ctx = await in_progress_ctx.do_wait_peer_trust()

            nonlocal new_device
            new_device = await in_progress_ctx.do_claim_device(
                requested_device_name=requested_device_name
            )
            assert isinstance(new_device, LocalDevice)

    async def _run_greeter():
        initial_ctx = DeviceGreetInitialCtx(cmds=alice_backend_cmds, token=invitation_addr.token)

        in_progress_ctx = await initial_ctx.do_wait_peer()

        await oob_send.send(in_progress_ctx.greeter_sas)

        in_progress_ctx = await in_progress_ctx.do_wait_peer_trust()

        choices = in_progress_ctx.generate_claimer_sas_choices(size=5)
        assert len(choices) == 5
        assert in_progress_ctx.claimer_sas in choices

        claimer_sas = await oob_recv.receive()
        assert claimer_sas == in_progress_ctx.claimer_sas

        in_progress_ctx = await in_progress_ctx.do_signify_trust()

        in_progress_ctx = await in_progress_ctx.do_get_claim_requests()

        assert in_progress_ctx.requested_device_name == requested_device_name

        await in_progress_ctx.do_create_new_device(author=alice, device_name=used_device_name)

    with trio.fail_after(1):
        async with trio.open_nursery() as nursery:
            nursery.start_soon(_run_claimer)
            nursery.start_soon(_run_greeter)

    # Make sure new device can connect to the backend
    assert new_device is not None
    async with backend_authenticated_cmds_factory(
        addr=new_device.organization_addr,
        device_id=new_device.device_id,
        signing_key=new_device.signing_key,
    ) as cmds:

        await cmds.ping()
