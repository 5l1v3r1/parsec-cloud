import attr
import random
import string

from parsec.utils import to_jsonb64
from parsec.schema import BaseCmdSchema, UnknownCheckedSchema, fields


TRUST_SEED_LENGTH = 12


def generate_trust_seed():
    # Use SystemRandom to get cryptographically secure seeds
    return "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(TRUST_SEED_LENGTH)
    )


@attr.s
class VlobAtom:
    id = attr.ib()
    read_trust_seed = attr.ib(factory=generate_trust_seed)
    write_trust_seed = attr.ib(factory=generate_trust_seed)
    blob = attr.ib(default=b"")
    version = attr.ib(default=1)
    is_sink = attr.ib(default=False)


class CheckEntrySchema(UnknownCheckedSchema):
    id = fields.String(required=True)
    rts = fields.String(required=True)
    version = fields.Integer(required=True)


class cmd_GROUP_CHECK_Schema(BaseCmdSchema):
    to_check = fields.List(fields.Nested(CheckEntrySchema()), required=True)


class cmd_CREATE_Schema(BaseCmdSchema):
    id = fields.String(required=True)
    rts = fields.String(required=True)
    wts = fields.String(required=True)
    blob = fields.Base64Bytes(required=True)
    notify_beacons = fields.List(fields.String())


class cmd_READ_Schema(BaseCmdSchema):
    id = fields.String(required=True)
    version = fields.Integer(validate=lambda n: n >= 1)
    rts = fields.String(required=True)


class cmd_UPDATE_Schema(BaseCmdSchema):
    id = fields.String(required=True)
    version = fields.Integer(validate=lambda n: n > 1)
    wts = fields.String(required=True)
    blob = fields.Base64Bytes(required=True)
    notify_beacons = fields.List(fields.String())


class BaseVlobComponent:
    def __init__(self, signal_ns):
        self._signal_vlob_updated = signal_ns.signal("vlob_updated")

    async def api_vlob_group_check(self, client_ctx, msg):
        msg = cmd_GROUP_CHECK_Schema().load_or_abort(msg)
        changed = await self.group_check(**msg)
        return {"status": "ok", "changed": changed}

    async def api_vlob_create(self, client_ctx, msg):
        msg = cmd_CREATE_Schema().load_or_abort(msg)
        await self.create(**msg)
        return {"status": "ok"}

    async def api_vlob_read(self, client_ctx, msg):
        msg = cmd_READ_Schema().load_or_abort(msg)
        atom = await self.read(**msg)
        return {
            "status": "ok",
            "id": atom.id,
            "blob": to_jsonb64(atom.blob),
            "version": atom.version,
        }

    async def api_vlob_update(self, client_ctx, msg):
        msg = cmd_UPDATE_Schema().load_or_abort(msg)
        await self.update(**msg)
        return {"status": "ok"}

    async def group_check(self, to_check):
        raise NotImplementedError()

    async def create(self, id, rts, wts, blob, notify_beacons=()):
        raise NotImplementedError()

    async def read(self, id, rts, version=None):
        raise NotImplementedError()

    async def update(self, id, wts, version, blob, notify_beacons=()):
        raise NotImplementedError()
