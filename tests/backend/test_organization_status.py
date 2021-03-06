# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from unittest.mock import ANY
from pendulum import Pendulum
import pytest

from parsec.api.protocol import (
    organization_status_serializer,
    organization_update_serializer,
    ADMINISTRATION_CMDS,
    AUTHENTICATED_CMDS,
    ANONYMOUS_CMDS,
)
from parsec.api.protocol.base import packb, unpackb
from tests.backend.test_organization import organization_create


async def organization_status(sock, organization_id):
    raw_rep = await sock.send(
        organization_status_serializer.req_dumps(
            {"cmd": "organization_status", "organization_id": organization_id}
        )
    )
    raw_rep = await sock.recv()
    return organization_status_serializer.rep_loads(raw_rep)


async def organization_update(sock, organization_id, expiration_date: Pendulum = None):
    raw_rep = await sock.send(
        organization_update_serializer.req_dumps(
            {
                "cmd": "organization_update",
                "organization_id": organization_id,
                "expiration_date": expiration_date,
            }
        )
    )
    raw_rep = await sock.recv()
    return organization_update_serializer.rep_loads(raw_rep)


@pytest.mark.trio
async def test_organization_status_bootstrapped(coolorg, administration_backend_sock):
    rep = await organization_status(administration_backend_sock, coolorg.organization_id)
    assert rep == {"status": "ok", "is_bootstrapped": True, "expiration_date": None}


@pytest.mark.trio
async def test_organization_status_not_bootstrapped(
    organization_factory, administration_backend_sock
):
    # 1) Create organization
    neworg = organization_factory("NewOrg")
    rep = await organization_create(administration_backend_sock, neworg.organization_id)
    assert rep == {"status": "ok", "bootstrap_token": ANY}

    # 2) Check its status
    rep = await organization_status(administration_backend_sock, neworg.organization_id)
    assert rep == {"status": "ok", "is_bootstrapped": False, "expiration_date": None}


@pytest.mark.trio
async def test_organization_update_expiration_date(
    coolorg, organization_factory, administration_backend_sock
):
    rep = await organization_status(administration_backend_sock, coolorg.organization_id)
    assert rep == {"status": "ok", "is_bootstrapped": True, "expiration_date": None}
    rep = await organization_update(
        administration_backend_sock, coolorg.organization_id, expiration_date=Pendulum(2077, 1, 1)
    )
    assert rep == {"status": "ok"}
    rep = await organization_status(administration_backend_sock, coolorg.organization_id)
    assert rep == {"status": "ok", "is_bootstrapped": True, "expiration_date": Pendulum(2077, 1, 1)}
    rep = await organization_update(
        administration_backend_sock, coolorg.organization_id, expiration_date=None
    )
    assert rep == {"status": "ok"}
    rep = await organization_status(administration_backend_sock, coolorg.organization_id)
    assert rep == {"status": "ok", "is_bootstrapped": True, "expiration_date": None}


@pytest.mark.trio
async def test_organization_update_expiration_date_unknown_organization(
    coolorg, organization_factory, administration_backend_sock
):
    rep = await organization_update(
        administration_backend_sock, "dummy", expiration_date=Pendulum(2077, 1, 1)
    )
    assert rep == {"status": "not_found"}


@pytest.mark.trio
async def test_status_unknown_organization(administration_backend_sock):
    rep = await organization_status(administration_backend_sock, organization_id="dummy")
    assert rep == {"status": "not_found"}


@pytest.mark.trio
async def test_non_admin_has_limited_access(alice_backend_sock):
    for cmd in (ADMINISTRATION_CMDS | ANONYMOUS_CMDS) - AUTHENTICATED_CMDS:
        await alice_backend_sock.send(packb({"cmd": cmd}))
        rep = await alice_backend_sock.recv()
        assert unpackb(rep) == {"status": "unknown_command", "reason": "Unknown command"}
