# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import attr
from typing import Optional, Tuple, FrozenDict
from uuid import UUID
from pendulum import Pendulum, now as pendulum_now

from parsec.serde import fields, validate, post_load
from parsec.crypto_types import SecretKey, HashDigest
from parsec.api.protocol import RealmRole, RealmRoleField
from parsec.api.data.base import (
    BaseData,
    BaseSchema,
    BaseSignedData,
    BaseSignedDataSchema,
    DataValidationError,
)
from parsec.core.types import EntryID, EntryIDField, EntryName, EntryNameField


class BlockAccess(BaseData):
    class SCHEMA_CLS(BaseSchema):
        id = fields.UUID(required=True)
        key = fields.SecretKey(required=True)
        offset = fields.Integer(required=True, validate=validate.Range(min=0))
        size = fields.Integer(required=True, validate=validate.Range(min=0))
        # TODO: provide digest as hexa string
        digest = fields.String(required=True, validate=validate.Length(min=1, max=64))

        @post_load
        def make_obj(self, data):
            return BlockAccess(**data)

    id: UUID
    key: SecretKey
    offset: int
    size: int
    digest: HashDigest


class WorkspaceEntry(BaseData):
    class SCHEMA_CLS(BaseSchema):
        name = EntryNameField(validate=validate.Length(min=1, max=256), required=True)
        id = EntryIDField(required=True)
        key = fields.SecretKey(required=True)
        encryption_revision = fields.Int(required=True, validate=validate.Range(min=0))
        encrypted_on = fields.DateTime(required=True)
        role_cached_on = fields.DateTime(required=True)
        role = RealmRoleField(required=True, allow_none=True)

        @post_load
        def make_obj(self, data):
            return WorkspaceEntry(**data)

    name: str
    id: EntryID
    key: SecretKey
    encryption_revision: int
    encrypted_on: Pendulum
    role_cached_on: Pendulum
    role: Optional[RealmRole]

    @classmethod
    def new(cls, name):
        now = pendulum_now()
        return WorkspaceEntry(
            name=name,
            id=EntryID(),
            key=SecretKey.generate(),
            encryption_revision=1,
            encrypted_on=now,
            role_cached_on=now,
            role=RealmRole.OWNER,
        )

    def is_revoked(self) -> bool:
        return self.role is None


class VerifyVersionAndParentMixin:
    @classmethod
    def verify_and_load(
        cls,
        *args,
        expected_id: Optional[EntryID] = None,
        expected_version: Optional[int] = None,
        expected_parent: Optional[EntryID] = None,
        **kwargs,
    ) -> BaseSignedData:
        data = super().verify_and_load(*args, **kwargs)
        if data.author is None:
            raise DataValidationError("Manifest cannot be signed by root verify key")
        if expected_id is not None and data.id != expected_id:
            raise DataValidationError(f"Invalid ID: expected `{expected_id}`, got `{data.id}`")
        if expected_version is not None and data.version != expected_version:
            raise DataValidationError(
                f"Invalid version: expected `{expected_version}`, got `{data.version}`"
            )
        if expected_parent is not None and data.parent != expected_parent:
            raise DataValidationError(
                f"Invalid parent ID: expected `{expected_parent}`, got `{data.parent}`"
            )
        return data


class FolderManifest(BaseSignedData, VerifyVersionAndParentMixin):
    class SCHEMA_CLS(BaseSignedDataSchema):
        type = fields.CheckedConstant("folder_manifest", required=True)
        id = EntryIDField(required=True)
        parent = EntryIDField(required=True)
        version = fields.Integer(required=True, validate=validate.Range(min=1))
        created = fields.DateTime(required=True)
        updated = fields.DateTime(required=True)
        children = fields.FrozenMap(
            EntryNameField(validate=validate.Length(min=1, max=256)),
            EntryIDField(required=True),
            required=True,
        )

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return FolderManifest(**data)

    id: EntryID
    parent: EntryID
    version: int
    created: Pendulum
    updated: Pendulum
    children: FrozenDict[EntryName, EntryID]


class FileManifest(BaseSignedData, VerifyVersionAndParentMixin):
    class SCHEMA_CLS(BaseSignedDataSchema):
        type = fields.CheckedConstant("file_manifest", required=True)
        id = EntryIDField(required=True)
        parent = EntryIDField(required=True)
        version = fields.Integer(required=True, validate=validate.Range(min=1))
        created = fields.DateTime(required=True)
        updated = fields.DateTime(required=True)
        size = fields.Integer(required=True, validate=validate.Range(min=0))
        blocks = fields.FrozenList(fields.Nested(BlockAccess.SCHEMA_CLS), required=True)

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return FileManifest(**data)

    id: EntryID
    parent: EntryID
    version: int
    created: Pendulum
    updated: Pendulum
    size: int
    blocks: Tuple[BlockAccess]


class WorkspaceManifest(BaseSignedData):
    class SCHEMA_CLS(BaseSignedDataSchema):
        type = fields.CheckedConstant("workspace_manifest", required=True)
        id = EntryIDField(required=True)
        version = fields.Integer(required=True, validate=validate.Range(min=1))
        created = fields.DateTime(required=True)
        updated = fields.DateTime(required=True)
        children = fields.FrozenMap(
            EntryNameField(validate=validate.Length(min=1, max=256)),
            EntryIDField(required=True),
            required=True,
        )

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return WorkspaceManifest(**data)

    id: EntryID
    version: int
    created: Pendulum
    updated: Pendulum
    children: FrozenDict[EntryName, EntryID]

    @classmethod
    def verify_and_load(
        cls,
        *args,
        expected_id: Optional[EntryID] = None,
        expected_version: Optional[int] = None,
        **kwargs,
    ) -> "WorkspaceManifest":
        data = super().verify_and_load(*args, **kwargs)
        if data.author is None:
            raise DataValidationError("Manifest cannot be signed by root verify key")
        if expected_id is not None and data.id != expected_id:
            raise DataValidationError(
                f"Invalid entry ID: expected `{expected_id}`, got `{data.id}`"
            )
        if expected_version is not None and data.version != expected_version:
            raise DataValidationError(
                f"Invalid version: expected `{expected_version}`, got `{data.version}`"
            )
        return data


class UserManifest(BaseSignedData):
    class SCHEMA_CLS(BaseSignedDataSchema):
        type = fields.CheckedConstant("user_manifest", required=True)
        id = EntryIDField(required=True)
        version = fields.Integer(required=True, validate=validate.Range(min=1))
        created = fields.DateTime(required=True)
        updated = fields.DateTime(required=True)
        last_processed_message = fields.Integer(required=True, validate=validate.Range(min=0))
        workspaces = fields.List(fields.Nested(WorkspaceEntry.SCHEMA_CLS), required=True)

        @post_load
        def make_obj(self, data):
            data.pop("type")
            return UserManifest(**data)

    id: EntryID
    version: int
    created: Pendulum
    updated: Pendulum
    last_processed_message: int
    workspaces: Tuple[WorkspaceEntry] = attr.ib(converter=tuple)

    @classmethod
    def verify_and_load(
        cls,
        *args,
        expected_id: Optional[EntryID] = None,
        expected_version: Optional[int] = None,
        **kwargs,
    ) -> "UserManifest":
        data = super().verify_and_load(*args, **kwargs)
        if data.author is None:
            raise DataValidationError("Manifest cannot be signed by root verify key")
        if expected_id is not None and data.id != expected_id:
            raise DataValidationError(
                f"Invalid entry ID: expected `{expected_id}`, got `{data.id}`"
            )
        if expected_version is not None and data.version != expected_version:
            raise DataValidationError(
                f"Invalid version: expected `{expected_version}`, got `{data.version}`"
            )
        return data

    def get_workspace_entry(self, workspace_id: EntryID) -> WorkspaceEntry:
        return next((w for w in self.workspaces if w.id == workspace_id), None)
