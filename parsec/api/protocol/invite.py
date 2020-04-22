# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from enum import Enum

from parsec.serde import BaseSchema, OneOfSchema, fields
from parsec.api.protocol.base import BaseReqSchema, BaseRepSchema, CmdSerializer
from parsec.api.protocol.types import HumanHandleField, UserIDField


__all__ = (
    "invite_new_serializer",
    "invite_delete_serializer",
    "invite_list_serializer",
    "invite_info_serializer",
    "invite_1_invitee_wait_peer_serializer",
    "invite_1_inviter_wait_peer_serializer",
    "invite_2a_invitee_send_hashed_nonce_serializer",
    "invite_2a_inviter_get_hashed_nonce_serializer",
    "invite_2b_inviter_send_nonce_serializer",
    "invite_2b_invitee_send_nonce_serializer",
    "invite_3a_inviter_wait_peer_trust_serializer",
    "invite_3b_invitee_wait_peer_trust_serializer",
    "invite_3a_invitee_signify_trust_serializer",
    "invite_3b_inviter_signify_trust_serializer",
    "invite_4_inviter_communicate_serializer",
    "invite_4_invitee_communicate_serializer",
)


class InvitationType(Enum):
    USER = "USER"
    DEVICE = "DEVICE"


InvitationTypeField = fields.enum_field_factory(InvitationType)


class InviteNewUserReqSchema(BaseReqSchema):
    type = fields.EnumCheckedConstant(InvitationType.USER, required=True)
    invitee_email = fields.String(required=True)
    send_email = fields.Boolean(required=True)


class InviteNewDeviceReqSchema(BaseReqSchema):
    type = fields.EnumCheckedConstant(InvitationType.DEVICE, required=True)
    send_email = fields.Boolean(required=True)


class InviteNewReqSchema(OneOfSchema):
    type_field = "type"
    type_field_remove = False
    type_schemas = {
        InvitationType.USER.value: InviteNewUserReqSchema(),
        InvitationType.DEVICE.value: InviteNewDeviceReqSchema(),
    }

    def get_obj_type(self, obj):
        return obj["type"].value


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


class InviteListItemUserSchema(BaseSchema):
    type = fields.EnumCheckedConstant(InvitationType.USER, required=True)
    token = fields.UUID(required=True)
    created_on = fields.DateTime(required=True)
    invitee_email = fields.String(required=True)
    status = InvitationStatusField(required=True)
    deleted_on = fields.DateTime(allow_none=True, missing=None)
    deleted_reason = InvitationDeletedReasonField(allow_none=True, missing=None)


class InviteListItemDeviceSchema(BaseSchema):
    type = fields.EnumCheckedConstant(InvitationType.DEVICE, required=True)
    token = fields.UUID(required=True)
    created_on = fields.DateTime(required=True)
    status = InvitationStatusField(required=True)
    deleted_on = fields.DateTime(allow_none=True, missing=None)
    deleted_reason = InvitationDeletedReasonField(allow_none=True, missing=None)


class InviteListItemSchema(OneOfSchema):
    type_field = "type"
    type_field_remove = False
    type_schemas = {
        InvitationType.USER.value: InviteListItemUserSchema(),
        InvitationType.DEVICE.value: InviteListItemDeviceSchema(),
    }

    def get_obj_type(self, obj):
        return obj["type"].value


class InviteListRepSchema(BaseRepSchema):
    invitations = fields.List(fields.Nested(InviteListItemSchema), required=True)


invite_list_serializer = CmdSerializer(InviteListReqSchema, InviteListRepSchema)


class InviteInfoReqSchema(BaseReqSchema):
    pass


class InviteInfoUserRepSchema(BaseRepSchema):
    type = fields.EnumCheckedConstant(InvitationType.USER, required=True)
    invitee_email = fields.String(required=True)
    inviter_user_id = UserIDField(required=True)
    inviter_human_handle = HumanHandleField(allow_none=True, missing=True)


class InviteInfoDeviceRepSchema(BaseRepSchema):
    type = fields.EnumCheckedConstant(InvitationType.DEVICE, required=True)
    inviter_user_id = UserIDField(required=True)
    inviter_human_handle = HumanHandleField(allow_none=True, missing=True)


class InviteInfoRepSchema(OneOfSchema):
    type_field = "type"
    type_field_remove = False
    type_schemas = {
        InvitationType.USER.value: InviteInfoUserRepSchema(),
        InvitationType.DEVICE.value: InviteInfoDeviceRepSchema(),
    }

    def get_obj_type(self, obj):
        return obj["type"].value


invite_info_serializer = CmdSerializer(InviteInfoReqSchema, InviteInfoRepSchema)


class Invite1InviteeWaitPeerReqSchema(BaseReqSchema):
    invitee_public_key = fields.PublicKey(required=True)


class Invite1InviteeWaitPeerRepSchema(BaseRepSchema):
    inviter_public_key = fields.PublicKey(required=True)


invite_1_invitee_wait_peer_serializer = CmdSerializer(
    Invite1InviteeWaitPeerReqSchema, Invite1InviteeWaitPeerRepSchema
)


class Invite1InviterWaitPeerReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)
    inviter_public_key = fields.PublicKey(required=True)


class Invite1InviterWaitPeerRepSchema(BaseRepSchema):
    invitee_public_key = fields.PublicKey(required=True)


invite_1_inviter_wait_peer_serializer = CmdSerializer(
    Invite1InviterWaitPeerReqSchema, Invite1InviterWaitPeerRepSchema
)


class Invite2aInviteeSendHashedNonceHashNonceReqSchema(BaseReqSchema):
    invitee_hashed_nonce = fields.Bytes(required=True)


class Invite2aInviteeSendHashedNonceHashNonceRepSchema(BaseRepSchema):
    inviter_nonce = fields.Bytes(required=True)


invite_2a_invitee_send_hashed_nonce_serializer = CmdSerializer(
    Invite2aInviteeSendHashedNonceHashNonceReqSchema,
    Invite2aInviteeSendHashedNonceHashNonceRepSchema,
)


class Invite2aInviterGetHashedNonceReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)


class Invite2aInviterGetHashedNonceRepSchema(BaseRepSchema):
    invitee_hashed_nonce = fields.Bytes(required=True)


invite_2a_inviter_get_hashed_nonce_serializer = CmdSerializer(
    Invite2aInviterGetHashedNonceReqSchema, Invite2aInviterGetHashedNonceRepSchema
)


class Invite2bInviterSendNonceReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)
    inviter_nonce = fields.Bytes(required=True)


class Invite2bInviterSendNonceRepSchema(BaseRepSchema):
    invitee_nonce = fields.Bytes(required=True)


invite_2b_inviter_send_nonce_serializer = CmdSerializer(
    Invite2bInviterSendNonceReqSchema, Invite2bInviterSendNonceRepSchema
)


class Invite2bInviteeSendNonceReqSchema(BaseReqSchema):
    invitee_nonce = fields.Bytes(required=True)


class Invite2bInviteeSendNonceRepSchema(BaseRepSchema):
    pass


invite_2b_invitee_send_nonce_serializer = CmdSerializer(
    Invite2bInviteeSendNonceReqSchema, Invite2bInviteeSendNonceRepSchema
)


class Invite3aInviterWaitPeerTrustReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)


class Invite3aInviterWaitPeerTrustRepSchema(BaseRepSchema):
    pass


invite_3a_inviter_wait_peer_trust_serializer = CmdSerializer(
    Invite3aInviterWaitPeerTrustReqSchema, Invite3aInviterWaitPeerTrustRepSchema
)


class Invite3bInviteeWaitPeerTrustReqSchema(BaseReqSchema):
    pass


class Invite3bInviteeWaitPeerTrustRepSchema(BaseRepSchema):
    pass


invite_3b_invitee_wait_peer_trust_serializer = CmdSerializer(
    Invite3bInviteeWaitPeerTrustReqSchema, Invite3bInviteeWaitPeerTrustRepSchema
)


class Invite3bInviterSignifyTrustReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)


class Invite3bInviterSignifyTrustRepSchema(BaseRepSchema):
    pass


invite_3b_inviter_signify_trust_serializer = CmdSerializer(
    Invite3bInviterSignifyTrustReqSchema, Invite3bInviterSignifyTrustRepSchema
)


class Invite3aInviteeSignifyTrustReqSchema(BaseReqSchema):
    pass


class Invite3aInviteeSignifyTrustRepSchema(BaseRepSchema):
    pass


invite_3a_invitee_signify_trust_serializer = CmdSerializer(
    Invite3aInviteeSignifyTrustReqSchema, Invite3aInviteeSignifyTrustRepSchema
)


class Invite4InviterCommunicateReqSchema(BaseReqSchema):
    token = fields.UUID(required=True)
    payload = fields.Bytes(allow_none=True, missing=None)


class Invite4InviterCommunicateRepSchema(BaseRepSchema):
    payload = fields.Bytes(allow_none=True, missing=None)


invite_4_inviter_communicate_serializer = CmdSerializer(
    Invite4InviterCommunicateReqSchema, Invite4InviterCommunicateRepSchema
)


class Invite4InviteeCommunicateReqSchema(BaseReqSchema):
    payload = fields.Bytes(allow_none=True, missing=None)


class Invite4InviteeCommunicateRepSchema(BaseRepSchema):
    payload = fields.Bytes(allow_none=True, missing=None)


invite_4_invitee_communicate_serializer = CmdSerializer(
    Invite4InviteeCommunicateReqSchema, Invite4InviteeCommunicateRepSchema
)
