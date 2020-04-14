# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from enum import Enum

from parsec.serde import BaseSchema, OneOfSchema, fields
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


class InvitationType(Enum):
    USER = "USER"
    DEVICE = "DEVICE"


InvitationTypeField = fields.enum_field_factory(InvitationType)


class InviteNewUserReqSchema(BaseRepSchema):
    type = fields.CheckedConstant(InvitationType.USER, required=True)
    email = fields.String(required=True)
    send_email = fields.Boolean(required=True)


class InviteNewDeviceReqSchema(BaseRepSchema):
    type = fields.CheckedConstant(InvitationType.DEVICE, required=True)
    send_email = fields.Boolean(required=True)


class InviteNewReqSchema(OneOfSchema):
    type_field = "type"
    type_field_remove = False
    type_schemas = {
        InvitationType.USER: InviteNewUserReqSchema(),
        InvitationType.DEVICE: InviteNewDeviceReqSchema(),
    }

    def get_obj_type(self, obj):
        return obj["type"]


class InviteNewRepSchema(BaseRepSchema):
    token = fields.UUID(required=True)


invite_new_serializer = CmdSerializer(InviteNewReqSchema, InviteNewRepSchema)


class InvitationDeletedReason(Enum):
    FINISHED = "FINISHED"
    CANCELLED = "CANCELLED"
    ROTTEN = "ROTTEN"


InvitationDeletedReasonField = fields.enum_field_factory(InvitationDeletedReason)


class InviteDeleteReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)
    reason = InvitationDeletedReasonField(required=True)


class InviteDeleteRepSchema(BaseRepSchema):
    pass


invite_delete_serializer = CmdSerializer(InviteDeleteReqSchema, InviteDeleteRepSchema)


class InviteListReqSchema(BaseReqSchema):
    pass


class InvitationStatus(Enum):
    IDLE = "IDLE"
    READY = "READY"
    DELETED = "DELETED"


InvitationStatusField = fields.enum_field_factory(InvitationStatus)


class InviteListItemSchema(BaseSchema):
    token = fields.UUID(required=True)
    type = InvitationTypeField(required=True)
    created = fields.DateTime(required=True)
    status = InvitationStatusField(required=True)
    deleted_reason = InvitationDeletedReason(allow_none=True, missing=None)


class InviteListRepSchema(BaseRepSchema):
    invitations = fields.List(fields.Nested(InviteListItemSchema), required=True)


invite_list_serializer = CmdSerializer(InviteListReqSchema, InviteListRepSchema)


class InviteInfoReqSchema(BaseReqSchema):
    pass


class InviteInfoRepSchema(BaseRepSchema):
    type = InvitationTypeField(required=True)
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
