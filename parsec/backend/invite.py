# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from parsec.api.protocol import (
    invite_new_serializer,
    invite_delete_serializer,
    invite_list_serializer,
    invite_info_serializer,
    invite_1_wait_peer_serializer,
    invite_2_send_hash_nonce_serializer,
    invite_2_get_hashed_nonce_serializer,
    invite_2_send_nonce_serializer,
    invite_3_wait_peer_trust_serializer,
    invite_3_signify_trust_serializer,
    invite_4_communicate_serializer,
)
from parsec.backend.utils import catch_protocol_errors, api


class InviteError(Exception):
    pass


class BaseInviteComponent:
    @api("invite_new", auth="authenticated")
    @catch_protocol_errors
    async def invite_new(self, client_ctx, msg):
        msg = invite_new_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_new_serializer.rep_dump(rep)

    @api("invite_delete", auth="authenticated")
    @catch_protocol_errors
    async def invite_delete(self, client_ctx, msg):
        msg = invite_delete_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_delete_serializer.rep_dump(rep)

    @api("invite_list", auth="authenticated")
    @catch_protocol_errors
    async def invite_list(self, client_ctx, msg):
        msg = invite_list_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_list_serializer.rep_dump(rep)

    @api("invite_info", auth="anonymous")
    @catch_protocol_errors
    async def invite_info(self, client_ctx, msg):
        msg = invite_info_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_info_serializer.rep_dump(rep)

    @api("invite_1_wait_peer", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_1_wait_peer(self, client_ctx, msg):
        msg = invite_1_wait_peer_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_1_wait_peer_serializer.rep_dump(rep)

    @api("invite_2_send_hash_nonce", auth="anonymous")
    @catch_protocol_errors
    async def invite_2_send_hash_nonce(self, client_ctx, msg):
        msg = invite_2_send_hash_nonce_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_2_send_hash_nonce_serializer.rep_dump(rep)

    @api("invite_2_get_hashed_nonce", auth="authenticated")
    @catch_protocol_errors
    async def invite_2_get_hashed_nonce(self, client_ctx, msg):
        msg = invite_2_get_hashed_nonce_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_2_get_hashed_nonce_serializer.rep_dump(rep)

    @api("invite_2_send_nonce", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_2_send_nonce(self, client_ctx, msg):
        msg = invite_2_send_nonce_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_2_send_nonce_serializer.rep_dump(rep)

    @api("invite_3_wait_peer_trust", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_3_wait_peer_trust(self, client_ctx, msg):
        msg = invite_3_wait_peer_trust_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_3_wait_peer_trust_serializer.rep_dump(rep)

    @api("invite_3_signify_trust", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_3_signify_trust(self, client_ctx, msg):
        msg = invite_3_signify_trust_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_3_signify_trust_serializer.rep_dump(rep)

    @api("invite_4_communicate", auth=["authenticated", "anonymous"])
    @catch_protocol_errors
    async def invite_4_communicate(self, client_ctx, msg):
        msg = invite_4_communicate_serializer.req_load(msg)
        # TODO
        rep = {"status": "not_implemented"}
        return invite_4_communicate_serializer.rep_dump(rep)
