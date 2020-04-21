# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import trio
from uuid import UUID
from functools import partial
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
    invite_new_serializer,
    invite_list_serializer,
    invite_delete_serializer,
    invite_info_serializer,
    invite_1_invitee_wait_peer_serializer,
    invite_1_inviter_wait_peer_serializer,
    invite_2a_invitee_send_hashed_nonce_serializer,
    invite_2a_inviter_get_hashed_nonce_serializer,
    invite_2b_inviter_send_nonce_serializer,
    invite_2b_invitee_send_nonce_serializer,
    invite_3a_inviter_wait_peer_trust_serializer,
    invite_3a_invitee_signify_trust_serializer,
    invite_3b_invitee_wait_peer_trust_serializer,
    invite_3b_inviter_signify_trust_serializer,
    invite_4_inviter_communicate_serializer,
    invite_4_invitee_communicate_serializer,
)


VLOB_ID = UUID("10000000000000000000000000000000")
REALM_ID = UUID("20000000000000000000000000000000")
OTHER_VLOB_ID = UUID("30000000000000000000000000000000")


class CmdSock:
    def __init__(self, cmd, serializer, parse_args=lambda self: {}, check_rep_by_default=False):
        self.cmd = cmd
        self.serializer = serializer
        self.parse_args = parse_args
        self.check_rep_by_default = check_rep_by_default

    async def _do_send(self, sock, args, kwargs):
        req = {"cmd": self.cmd, **self.parse_args(self, *args, **kwargs)}
        raw_req = self.serializer.req_dumps(req)
        await sock.send(raw_req)

    async def _do_recv(self, sock, check_rep):
        raw_rep = await sock.recv()
        rep = self.serializer.rep_loads(raw_rep)

        if check_rep:
            assert rep["status"] == "ok"

        return rep

    async def __call__(self, sock, *args, **kwargs):
        check_rep = kwargs.pop("check_rep", self.check_rep_by_default)
        await self._do_send(sock, args, kwargs)
        return await self._do_recv(sock, check_rep)

    class AsyncCallRepBox:
        def __init__(self, do_recv):
            self._do_recv = do_recv
            self.rep_done = False
            self._rep = None

        @property
        def rep(self):
            assert self.rep_done
            return self._rep

        async def do_recv(self):
            assert not self.rep_done
            self._rep = await self._do_recv()
            self.rep_done = True

    @asynccontextmanager
    async def async_call(self, sock, *args, **kwargs):
        check_rep = kwargs.pop("check_rep", self.check_rep_by_default)
        await self._do_send(sock, args, kwargs)

        box = self.AsyncCallRepBox(do_recv=partial(self._do_recv, sock, check_rep))
        yield box

        if not box.rep_done:
            with trio.fail_after(1):
                await box.do_recv()


### Ping ###


ping = CmdSock(
    "ping",
    ping_serializer,
    parse_args=lambda self, ping="foo": {"ping": ping},
    check_rep_by_default=True,
)


### Block ###


block_create = CmdSock(
    "block_create",
    block_create_serializer,
    parse_args=lambda self, block_id, realm_id, block: {
        "block_id": block_id,
        "realm_id": realm_id,
        "block": block,
    },
    check_rep_by_default=True,
)
block_read = CmdSock(
    "block_read", block_read_serializer, parse_args=lambda self, block_id: {"block_id": block_id}
)


### Realm ###


realm_create = CmdSock(
    "realm_create",
    realm_create_serializer,
    parse_args=lambda self, role_certificate: {"role_certificate": role_certificate},
    check_rep_by_default=True,
)
realm_status = CmdSock(
    "realm_status",
    realm_status_serializer,
    parse_args=lambda self, realm_id: {"realm_id": realm_id},
)
realm_get_role_certificates = CmdSock(
    "realm_get_role_certificates",
    realm_get_role_certificates_serializer,
    parse_args=lambda self, realm_id, since=None: {"realm_id": realm_id, "since": since},
)
realm_update_roles = CmdSock(
    "realm_update_roles",
    realm_update_roles_serializer,
    parse_args=lambda self, role_certificate, recipient_message=None: {
        "role_certificate": role_certificate,
        "recipient_message": recipient_message,
    },
    check_rep_by_default=True,
)
realm_start_reencryption_maintenance = CmdSock(
    "realm_start_reencryption_maintenance",
    realm_start_reencryption_maintenance_serializer,
    parse_args=lambda self, realm_id, encryption_revision, timestamp, per_participant_message: {
        "realm_id": realm_id,
        "encryption_revision": encryption_revision,
        "timestamp": timestamp,
        "per_participant_message": per_participant_message,
    },
    check_rep_by_default=True,
)
realm_finish_reencryption_maintenance = CmdSock(
    "realm_finish_reencryption_maintenance",
    realm_finish_reencryption_maintenance_serializer,
    parse_args=lambda self, realm_id, encryption_revision: {
        "realm_id": realm_id,
        "encryption_revision": encryption_revision,
    },
    check_rep_by_default=True,
)


### Vlob ###


vlob_create = CmdSock(
    "vlob_create",
    vlob_create_serializer,
    parse_args=lambda self, realm_id, vlob_id, blob, timestamp=None, encryption_revision=1: {
        "realm_id": realm_id,
        "vlob_id": vlob_id,
        "blob": blob,
        "timestamp": timestamp or pendulum_now(),
        "encryption_revision": encryption_revision,
    },
    check_rep_by_default=True,
)
vlob_read = CmdSock(
    "vlob_read",
    vlob_read_serializer,
    parse_args=lambda self, vlob_id, version=None, timestamp=None, encryption_revision=1: {
        "vlob_id": vlob_id,
        "version": version,
        "timestamp": timestamp,
        "encryption_revision": encryption_revision,
    },
)
vlob_update = CmdSock(
    "vlob_update",
    vlob_update_serializer,
    parse_args=lambda self, vlob_id, version, blob, encryption_revision=1, timestamp=None: {
        "vlob_id": vlob_id,
        "version": version,
        "blob": blob,
        "encryption_revision": encryption_revision,
        "timestamp": timestamp or pendulum_now(),
    },
    check_rep_by_default=True,
)
vlob_list_versions = CmdSock(
    "vlob_list_versions",
    vlob_list_versions_serializer,
    parse_args=lambda self, vlob_id, encryption_revision=1: {
        "vlob_id": vlob_id,
        "encryption_revision": encryption_revision,
    },
)
vlob_poll_changes = CmdSock(
    "vlob_poll_changes",
    vlob_poll_changes_serializer,
    parse_args=lambda self, realm_id, last_checkpoint: {
        "realm_id": realm_id,
        "last_checkpoint": last_checkpoint,
    },
)
vlob_maintenance_get_reencryption_batch = CmdSock(
    "vlob_maintenance_get_reencryption_batch",
    vlob_maintenance_get_reencryption_batch_serializer,
    parse_args=lambda self, realm_id, encryption_revision, size=100: {
        "realm_id": realm_id,
        "encryption_revision": encryption_revision,
        "size": size,
    },
)
vlob_maintenance_save_reencryption_batch = CmdSock(
    "vlob_maintenance_save_reencryption_batch",
    vlob_maintenance_save_reencryption_batch_serializer,
    parse_args=lambda self, realm_id, encryption_revision, batch: {
        "realm_id": realm_id,
        "encryption_revision": encryption_revision,
        "batch": batch,
    },
    check_rep_by_default=True,
)


### Events ###


events_subscribe = CmdSock("events_subscribe", events_subscribe_serializer)

_events_listen = CmdSock(
    "events_listen", events_listen_serializer, parse_args=lambda self, wait: {"wait": wait}
)


async def events_listen_nowait(sock):
    return await _events_listen(sock, wait=False)


@asynccontextmanager
async def events_listen(sock):
    async with _events_listen.async_call(sock, wait=True) as box:
        yield box


### User ###


user_get = CmdSock(
    "user_get", user_get_serializer, parse_args=lambda self, user_id: {"user_id": user_id}
)
user_find = CmdSock(
    "user_find",
    apiv1_user_find_serializer,
    parse_args=lambda self, query, omit_revoked, page, per_page: {
        "query": query,
        "omit_revoked": omit_revoked,
        "page": page,
        "per_page": per_page,
    },
)


### Invite ###


invite_new = CmdSock(
    "invite_new",
    invite_new_serializer,
    parse_args=lambda self, type, send_email=False, invitee_email=None: {
        "type": type,
        "send_email": send_email,
        "invitee_email": invitee_email,
    },
)
invite_list = CmdSock("invite_list", invite_list_serializer)
invite_delete = CmdSock(
    "invite_delete",
    invite_delete_serializer,
    parse_args=lambda self, token, reason: {"token": token, "reason": reason},
)
invite_info = CmdSock("invite_info", invite_info_serializer)
invite_1_invitee_wait_peer = CmdSock(
    "invite_1_invitee_wait_peer",
    invite_1_invitee_wait_peer_serializer,
    parse_args=lambda self, invitee_public_key: {"invitee_public_key": invitee_public_key},
)
invite_1_inviter_wait_peer = CmdSock(
    "invite_1_inviter_wait_peer",
    invite_1_inviter_wait_peer_serializer,
    parse_args=lambda self, token, inviter_public_key: {
        "token": token,
        "inviter_public_key": inviter_public_key,
    },
)
invite_2a_invitee_send_hashed_nonce = CmdSock(
    "invite_2a_invitee_send_hashed_nonce",
    invite_2a_invitee_send_hashed_nonce_serializer,
    parse_args=lambda self, invitee_hashed_nonce: {"invitee_hashed_nonce": invitee_hashed_nonce},
)
invite_2a_inviter_get_hashed_nonce = CmdSock(
    "invite_2a_inviter_get_hashed_nonce",
    invite_2a_inviter_get_hashed_nonce_serializer,
    parse_args=lambda self, token: {"token": token},
)
invite_2b_inviter_send_nonce = CmdSock(
    "invite_2b_inviter_send_nonce",
    invite_2b_inviter_send_nonce_serializer,
    parse_args=lambda self, token, inviter_nonce: {"token": token, "inviter_nonce": inviter_nonce},
)
invite_2b_invitee_send_nonce = CmdSock(
    "invite_2b_invitee_send_nonce",
    invite_2b_invitee_send_nonce_serializer,
    parse_args=lambda self, invitee_nonce: {"invitee_nonce": invitee_nonce},
)
invite_3a_inviter_wait_peer_trust = CmdSock(
    "invite_3a_inviter_wait_peer_trust",
    invite_3a_inviter_wait_peer_trust_serializer,
    parse_args=lambda self, token: {"token": token},
)
invite_3a_invitee_signify_trust = CmdSock(
    "invite_3a_invitee_signify_trust", invite_3a_invitee_signify_trust_serializer
)
invite_3b_invitee_wait_peer_trust = CmdSock(
    "invite_3b_invitee_wait_peer_trust", invite_3b_invitee_wait_peer_trust_serializer
)
invite_3b_inviter_signify_trust = CmdSock(
    "invite_3b_inviter_signify_trust",
    invite_3b_inviter_signify_trust_serializer,
    parse_args=lambda self, token: {"token": token},
)
invite_4_inviter_communicate = CmdSock(
    "invite_4_inviter_communicate",
    invite_4_inviter_communicate_serializer,
    parse_args=lambda self, token, payload: {"token": token, "payload": payload},
)
invite_4_invitee_communicate = CmdSock(
    "invite_4_invitee_communicate",
    invite_4_invitee_communicate_serializer,
    parse_args=lambda self, payload: {"payload": payload},
)
