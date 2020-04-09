# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from parsec.serde import BaseSchema, fields, validate
from parsec.api.protocol.base import BaseReqSchema, BaseRepSchema, CmdSerializer


__all__ = (
    "invite_new_serializer",
    "invite_delete_serializer",
    "invite_list_serializer",
    "invite_info_serializer",
    "invite_1_wait_peer_serializer",
    "invite_2_send_hash_nonce_serializer",
    "invite_2_get_hashed_nonce_serializer",
    "invite_2_send_nonce_serializer",
    "invite_3_wait_peer_trust_serializer",
    "invite_3_signify_trust_serializer",
    "invite_4_communicate_serializer",
)


INVITE_TYPES = ["user", "device"]


class InviteNewReqSchema(BaseReqSchema):
    type = fields.String(required=True, validate=validate.OneOf(INVITE_TYPES))
    email = fields.String(required=True)
    send_email = fields.Boolean(required=True)


class InviteNewRepSchema(BaseRepSchema):
    token = fields.String(required=True)


invite_new_serializer = CmdSerializer(InviteNewReqSchema, InviteNewRepSchema)


class InviteDeleteReqSchema(BaseReqSchema):
    token = fields.String(required=True)
    reason = fields.String(
        required=True, validate=validate.OneOf(["finished", "cancelled", "rotten"])
    )


class InviteDeleteRepSchema(BaseRepSchema):
    pass


invite_delete_serializer = CmdSerializer(InviteDeleteReqSchema, InviteDeleteRepSchema)


class InviteListReqSchema(BaseReqSchema):
    pass


class InviteListItemSchema(BaseSchema):
    token = fields.String(required=True)
    type = fields.String(required=True, validate=validate.OneOf(INVITE_TYPES))
    status = fields.String(required=True, validate=validate.OneOf(["idle", "ready"]))
    created = fields.DateTime(required=True)


class InviteListRepSchema(BaseRepSchema):
    invitations = fields.List(fields.Nested(InviteListItemSchema), required=True)


invite_list_serializer = CmdSerializer(InviteListReqSchema, InviteListRepSchema)


class InviteInfoReqSchema(BaseReqSchema):
    pass


class InviteInfoRepSchema(BaseRepSchema):
    type = fields.String(required=True, validate=validate.OneOf(INVITE_TYPES))
    email = fields.String(required=True)  # Only for user
    inviter_human_email = fields.String(required=True)
    inviter_human_label = fields.String(required=True)


invite_info_serializer = CmdSerializer(InviteInfoReqSchema, InviteInfoRepSchema)


class Invite1WaitPeerReqSchema(BaseReqSchema):
    token = fields.String(required=True)
    public_key = fields.PublicKey(required=True)


class Invite1WaitPeerRepSchema(BaseRepSchema):
    peer_public_key = fields.PublicKey(required=True)


invite_1_wait_peer_serializer = CmdSerializer(Invite1WaitPeerReqSchema, Invite1WaitPeerRepSchema)


class Invite2SendHashNonceReqSchema(BaseReqSchema):
    hashed_nonce = fields.String(required=True)


class Invite2SendHashNonceRepSchema(BaseRepSchema):
    nonce = fields.String(required=True)


invite_2_send_hash_nonce_serializer = CmdSerializer(
    Invite2SendHashNonceReqSchema, Invite2SendHashNonceRepSchema
)


class Invite2GetHashedNonceReqSchema(BaseReqSchema):
    pass


class Invite2GetHashedNonceRepSchema(BaseRepSchema):
    nonce = fields.String(required=True)


invite_2_get_hashed_nonce_serializer = CmdSerializer(
    Invite2GetHashedNonceReqSchema, Invite2GetHashedNonceRepSchema
)


class Invite2SendNonceReqSchema(BaseReqSchema):
    nonce = fields.String(required=True)


class Invite2SendNonceRepSchema(BaseRepSchema):
    nonce = fields.String(required=True)


invite_2_send_nonce_serializer = CmdSerializer(Invite2SendNonceReqSchema, Invite2SendNonceRepSchema)


class Invite3WaitPeerTrustReqSchema(BaseReqSchema):
    pass


class Invite3WaitPeerTrustRepSchema(BaseRepSchema):
    pass


invite_3_wait_peer_trust_serializer = CmdSerializer(
    Invite3WaitPeerTrustReqSchema, Invite3WaitPeerTrustRepSchema
)


class Invite3SignifyTrustReqSchema(BaseReqSchema):
    pass


class Invite3SignifyTrustRepSchema(BaseRepSchema):
    pass


invite_3_signify_trust_serializer = CmdSerializer(
    Invite3SignifyTrustReqSchema, Invite3SignifyTrustRepSchema
)


class Invite4CommunicateReqSchema(BaseReqSchema):
    payload = fields.Bytes(allow_none=True, missing=None)


class Invite4CommunicateRepSchema(BaseRepSchema):
    pass


invite_4_communicate_serializer = CmdSerializer(
    Invite4CommunicateReqSchema, Invite4CommunicateRepSchema
)
