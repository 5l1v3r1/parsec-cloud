from structlog import get_logger
from async_generator import asynccontextmanager

from parsec.types import DeviceID, BackendOrganizationAddr, BackendAddr
from parsec.crypto import SigningKey
from parsec.core.backend_connection.exceptions import BackendNotAvailable
from parsec.core.backend_connection.transport import (
    transport_pool_factory,
    anonymous_transport_factory,
    administrator_transport_factory,
    TransportError,
)
from parsec.core.backend_connection import cmds


__all__ = (
    "backend_cmds_factory",
    "BackendCmdsPool",
    "backend_anonymous_cmds_factory",
    "BackendAnonymousCmds",
)


logger = get_logger()


class BackendCmdsPool:
    def __init__(self, addr, transport_pool):
        self.addr = addr
        self.transport_pool = transport_pool

    def _expose_cmds_with_retrier(name):
        cmd = getattr(cmds, name)

        async def wrapper(self, *args, **kwargs):
            try:
                async with self.transport_pool.acquire() as transport:
                    return await cmd(transport, *args, **kwargs)

            except BackendNotAvailable:
                async with self.transport_pool.acquire(force_fresh=True) as transport:
                    return await cmd(transport, *args, **kwargs)

        wrapper.__name__ = name

        return wrapper

    ping = _expose_cmds_with_retrier("ping")

    events_subscribe = _expose_cmds_with_retrier("events_subscribe")
    events_listen = _expose_cmds_with_retrier("events_listen")

    beacon_get_rights = _expose_cmds_with_retrier("beacon_get_rights")
    beacon_set_rights = _expose_cmds_with_retrier("beacon_set_rights")
    beacon_poll = _expose_cmds_with_retrier("beacon_poll")

    message_send = _expose_cmds_with_retrier("message_send")
    message_get = _expose_cmds_with_retrier("message_get")

    vlob_group_check = _expose_cmds_with_retrier("vlob_group_check")
    vlob_create = _expose_cmds_with_retrier("vlob_create")
    vlob_read = _expose_cmds_with_retrier("vlob_read")
    vlob_update = _expose_cmds_with_retrier("vlob_update")

    blockstore_create = _expose_cmds_with_retrier("blockstore_create")
    blockstore_read = _expose_cmds_with_retrier("blockstore_read")

    user_get = _expose_cmds_with_retrier("user_get")
    user_find = _expose_cmds_with_retrier("user_find")
    user_invite = _expose_cmds_with_retrier("user_invite")
    user_cancel_invitation = _expose_cmds_with_retrier("user_cancel_invitation")
    user_create = _expose_cmds_with_retrier("user_create")

    device_invite = _expose_cmds_with_retrier("device_invite")
    device_cancel_invitation = _expose_cmds_with_retrier("device_cancel_invitation")
    device_create = _expose_cmds_with_retrier("device_create")
    device_revoke = _expose_cmds_with_retrier("device_revoke")


class BackendAnonymousCmds:
    def __init__(self, addr, transport):
        self.addr = addr
        self.transport = transport

    def _expose_cmds(name):
        cmd = getattr(cmds, name)

        async def wrapper(self, *args, **kwargs):
            return await cmd(self.transport, *args, **kwargs)

        wrapper.__name__ = name

        return wrapper

    ping = _expose_cmds("ping")

    organization_bootstrap = _expose_cmds("organization_bootstrap")

    user_get_invitation_creator = _expose_cmds("user_get_invitation_creator")
    user_claim = _expose_cmds("user_claim")

    device_get_invitation_creator = _expose_cmds("device_get_invitation_creator")
    device_claim = _expose_cmds("device_claim")


class BackendAdministratorCmds:
    def __init__(self, addr, transport):
        self.addr = addr
        self.transport = transport

    def _expose_cmds(name):
        cmd = getattr(cmds, name)

        async def wrapper(self, *args, **kwargs):
            return await cmd(self.transport, *args, **kwargs)

        wrapper.__name__ = name

        return wrapper

    ping = _expose_cmds("ping")
    organization_create = _expose_cmds("organization_create")


@asynccontextmanager
async def backend_cmds_factory(
    addr: BackendOrganizationAddr, device_id: DeviceID, signing_key: SigningKey, max_pool: int = 4
) -> BackendCmdsPool:
    async with transport_pool_factory(addr, device_id, signing_key, max_pool) as transport_pool:
        yield BackendCmdsPool(addr, transport_pool)


@asynccontextmanager
async def backend_anonymous_cmds_factory(addr: BackendOrganizationAddr) -> BackendAnonymousCmds:
    try:
        async with anonymous_transport_factory(addr) as transport:
            yield BackendAnonymousCmds(addr, transport)
    except TransportError as exc:
        raise BackendNotAvailable(exc) from exc


@asynccontextmanager
async def backend_administrator_cmds_factory(
    addr: BackendAddr, token: str
) -> BackendAdministratorCmds:
    try:
        async with administrator_transport_factory(addr, token) as transport:
            yield BackendAdministratorCmds(addr, transport)
    except TransportError as exc:
        raise BackendNotAvailable(exc) from exc
