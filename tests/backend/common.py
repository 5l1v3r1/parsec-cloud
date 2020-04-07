# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import trio
from uuid import UUID
from pendulum import now as pendulum_now
from async_generator import asynccontextmanager

from parsec.api.protocol import (
    ping_serializer,
    block_create_serializer,
    block_read_serializer,
    realm_create_serializer,
    realm_status_serializer,
    realm_get_role_certificates_serializer,
    realm_update_roles_serializer,
    realm_start_reencryption_maintenance_serializer,
    realm_finish_reencryption_maintenance_serializer,
    vlob_create_serializer,
    vlob_read_serializer,
    vlob_update_serializer,
    vlob_list_versions_serializer,
    vlob_poll_changes_serializer,
    vlob_maintenance_get_reencryption_batch_serializer,
    vlob_maintenance_save_reencryption_batch_serializer,
    events_subscribe_serializer,
    events_listen_serializer,
    user_get_serializer,
    apiv1_user_find_serializer,
)


VLOB_ID = UUID("10000000000000000000000000000000")
REALM_ID = UUID("20000000000000000000000000000000")
OTHER_VLOB_ID = UUID("30000000000000000000000000000000")


### Ping ###


async def ping(sock, subject="foo"):
    raw_req = ping_serializer.req_dumps({"cmd": "ping", "ping": subject})
    await sock.send(raw_req)
    raw_rep = await sock.recv()
    rep = ping_serializer.rep_loads(raw_rep)
    assert rep == {"status": "ok", "pong": subject}


### Block ###


async def block_create(sock, block_id, realm_id, block, check_rep=True):
    await sock.send(
        block_create_serializer.req_dumps(
            {"cmd": "block_create", "block_id": block_id, "realm_id": realm_id, "block": block}
        )
    )
    raw_rep = await sock.recv()
    rep = block_create_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


async def block_read(sock, block_id):
    await sock.send(block_read_serializer.req_dumps({"cmd": "block_read", "block_id": block_id}))
    raw_rep = await sock.recv()
    return block_read_serializer.rep_loads(raw_rep)


### Realm ###


async def realm_create(sock, role_certificate, check_rep=True):
    raw_rep = await sock.send(
        realm_create_serializer.req_dumps(
            {"cmd": "realm_create", "role_certificate": role_certificate}
        )
    )
    raw_rep = await sock.recv()
    rep = realm_create_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


async def realm_status(sock, realm_id):
    raw_rep = await sock.send(
        realm_status_serializer.req_dumps({"cmd": "realm_status", "realm_id": realm_id})
    )
    raw_rep = await sock.recv()
    return realm_status_serializer.rep_loads(raw_rep)


async def realm_get_role_certificates(sock, realm_id, since=None):
    raw_rep = await sock.send(
        realm_get_role_certificates_serializer.req_dumps(
            {"cmd": "realm_get_role_certificates", "realm_id": realm_id, "since": since}
        )
    )
    raw_rep = await sock.recv()
    return realm_get_role_certificates_serializer.rep_loads(raw_rep)


async def realm_update_roles(sock, role_certificate, recipient_message=None, check_rep=True):
    raw_rep = await sock.send(
        realm_update_roles_serializer.req_dumps(
            {
                "cmd": "realm_update_roles",
                "role_certificate": role_certificate,
                "recipient_message": recipient_message,
            }
        )
    )
    raw_rep = await sock.recv()
    rep = realm_update_roles_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


async def realm_start_reencryption_maintenance(
    sock, realm_id, encryption_revision, timestamp, per_participant_message, check_rep=True
):
    raw_rep = await sock.send(
        realm_start_reencryption_maintenance_serializer.req_dumps(
            {
                "cmd": "realm_start_reencryption_maintenance",
                "realm_id": realm_id,
                "encryption_revision": encryption_revision,
                "timestamp": timestamp,
                "per_participant_message": per_participant_message,
            }
        )
    )
    raw_rep = await sock.recv()
    rep = realm_start_reencryption_maintenance_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


async def realm_finish_reencryption_maintenance(
    sock, realm_id, encryption_revision, check_rep=True
):
    raw_rep = await sock.send(
        realm_finish_reencryption_maintenance_serializer.req_dumps(
            {
                "cmd": "realm_finish_reencryption_maintenance",
                "realm_id": realm_id,
                "encryption_revision": encryption_revision,
            }
        )
    )
    raw_rep = await sock.recv()
    rep = realm_finish_reencryption_maintenance_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


### Vlob ####


async def vlob_create(
    sock, realm_id, vlob_id, blob, timestamp=None, encryption_revision=1, check_rep=True
):
    timestamp = timestamp or pendulum_now()
    await sock.send(
        vlob_create_serializer.req_dumps(
            {
                "cmd": "vlob_create",
                "realm_id": realm_id,
                "vlob_id": vlob_id,
                "timestamp": timestamp,
                "encryption_revision": encryption_revision,
                "blob": blob,
            }
        )
    )
    raw_rep = await sock.recv()
    rep = vlob_create_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


async def vlob_read(sock, vlob_id, version=None, timestamp=None, encryption_revision=1):
    await sock.send(
        vlob_read_serializer.req_dumps(
            {
                "cmd": "vlob_read",
                "vlob_id": vlob_id,
                "version": version,
                "timestamp": timestamp,
                "encryption_revision": encryption_revision,
            }
        )
    )
    raw_rep = await sock.recv()
    return vlob_read_serializer.rep_loads(raw_rep)


async def vlob_update(
    sock, vlob_id, version, blob, encryption_revision=1, timestamp=None, check_rep=True
):
    timestamp = timestamp or pendulum_now()
    await sock.send(
        vlob_update_serializer.req_dumps(
            {
                "cmd": "vlob_update",
                "vlob_id": vlob_id,
                "version": version,
                "timestamp": timestamp,
                "encryption_revision": encryption_revision,
                "blob": blob,
            }
        )
    )
    raw_rep = await sock.recv()
    rep = vlob_update_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep == {"status": "ok"}
    return rep


async def vlob_list_versions(sock, vlob_id, encryption_revision=1):
    await sock.send(
        vlob_list_versions_serializer.req_dumps({"cmd": "vlob_list_versions", "vlob_id": vlob_id})
    )
    raw_rep = await sock.recv()
    return vlob_list_versions_serializer.rep_loads(raw_rep)


async def vlob_poll_changes(sock, realm_id, last_checkpoint):
    raw_rep = await sock.send(
        vlob_poll_changes_serializer.req_dumps(
            {"cmd": "vlob_poll_changes", "realm_id": realm_id, "last_checkpoint": last_checkpoint}
        )
    )
    raw_rep = await sock.recv()
    return vlob_poll_changes_serializer.rep_loads(raw_rep)


async def vlob_maintenance_get_reencryption_batch(sock, realm_id, encryption_revision, size=100):
    raw_rep = await sock.send(
        vlob_maintenance_get_reencryption_batch_serializer.req_dumps(
            {
                "cmd": "vlob_maintenance_get_reencryption_batch",
                "realm_id": realm_id,
                "encryption_revision": encryption_revision,
                "size": size,
            }
        )
    )
    raw_rep = await sock.recv()
    return vlob_maintenance_get_reencryption_batch_serializer.rep_loads(raw_rep)


async def vlob_maintenance_save_reencryption_batch(
    sock, realm_id, encryption_revision, batch, check_rep=True
):
    raw_rep = await sock.send(
        vlob_maintenance_save_reencryption_batch_serializer.req_dumps(
            {
                "cmd": "vlob_maintenance_save_reencryption_batch",
                "realm_id": realm_id,
                "encryption_revision": encryption_revision,
                "batch": batch,
            }
        )
    )
    raw_rep = await sock.recv()
    rep = vlob_maintenance_save_reencryption_batch_serializer.rep_loads(raw_rep)
    if check_rep:
        assert rep["status"] == "ok"
    return rep


### Events ###


async def events_subscribe(sock):
    await sock.send(events_subscribe_serializer.req_dumps({"cmd": "events_subscribe"}))
    raw_rep = await sock.recv()
    rep = events_subscribe_serializer.rep_loads(raw_rep)
    assert rep == {"status": "ok"}


async def events_listen_nowait(sock):
    await sock.send(events_listen_serializer.req_dumps({"cmd": "events_listen", "wait": False}))
    raw_rep = await sock.recv()
    return events_listen_serializer.rep_loads(raw_rep)


class Listen:
    def __init__(self):
        self.rep = None


@asynccontextmanager
async def events_listen(sock):
    await sock.send(events_listen_serializer.req_dumps({"cmd": "events_listen"}))
    listen = Listen()

    yield listen

    with trio.fail_after(1):
        raw_rep = await sock.recv()
    listen.rep = events_listen_serializer.rep_loads(raw_rep)


### User ###


async def user_get(sock, user_id):
    await sock.send(user_get_serializer.req_dumps({"cmd": "user_get", "user_id": user_id}))
    raw_rep = await sock.recv()
    return user_get_serializer.rep_loads(raw_rep)


async def user_find(sock, **kwargs):
    await sock.send(apiv1_user_find_serializer.req_dumps({"cmd": "user_find", **kwargs}))
    raw_rep = await sock.recv()
    return apiv1_user_find_serializer.rep_loads(raw_rep)
