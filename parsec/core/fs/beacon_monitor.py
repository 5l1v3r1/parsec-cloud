import trio
import pickle

from parsec.core.base import BaseAsyncComponent

try:
    from parsec.utils import sym_decrypt, verify
except ImportError:

    def sym_decrypt(key, content):
        return content

    def verify(content):
        return "alice@test", content


# We could also mark the local db entries outdated we update occurs to
# only bother about them when they're really needed


class BeaconMonitor(BaseAsyncComponent):
    def __init__(self, device, local_db, signal_ns):
        super().__init__()
        self._device = device
        self._local_db = local_db
        self._task_cancel_scope = None
        self._workspaces = {}
        self.signal_ns = signal_ns

    async def _init(self, nursery):
        self._task_cancel_scope = await nursery.start(self._task)

    async def _teardown(self):
        self._task_cancel_scope.cancel()

    def _retreive_beacon_key(self, beacon_id):
        root_manifest = self._local_db.get(self._device.user_manifest_access)
        if root_manifest["beacon_id"] == beacon_id:
            return self._device.user_manifest_access["key"]
        for child_access in root_manifest["children"].values():
            child_manifest = self._local_db.get(child_access)
            if child_manifest.get("beacon_id") == beacon_id:
                return child_access["key"]

    async def _task(self, *, task_status=trio.TASK_STATUS_IGNORED):
        def _on_workspace_loaded(sender, path, beacon_id):
            self._workspaces[beacon_id] = path
            self.signal_ns.signal("backend.beacon.listen").send(None, beacon_id=beacon_id)

        def _on_workspace_unloaded(sender, path, beacon_id):
            del self._workspaces[beacon_id]
            self.signal_ns.signal("backend.beacon.unlisten").send(None, beacon_id=beacon_id)

        entry_updated_signal = self.signal_ns.signal("fs.entry.updated")

        def _on_beacon_updated(sender, id, msg, author, date):
            import pdb

            pdb.set_trace()
            if author == self._device.device_id:
                return

            key = self._retreive_beacon_key(id)
            if not key:
                # Don't know about this workspaces, no need to udate it then
                return
            print("beacon update", id, "by", author)

            # Verify is normally async, so we must move this into the task
            msg_sign_author, raw_msg = verify(sym_decrypt(key, msg))
            assert author == msg_sign_author
            msg = pickle.loads(raw_msg)

            entry_updated_signal.send(id=msg["id"])

        self.signal_ns.signal("fs.workspace.loaded").connect(_on_workspace_loaded, weak=True)
        self.signal_ns.signal("fs.workspace.unloaded").connect(_on_workspace_unloaded, weak=True)
        self.signal_ns.signal("backend.beacon.updated").connect(_on_beacon_updated, weak=True)

        with trio.open_cancel_scope() as cancel_scope:
            task_status.started(cancel_scope)
            await trio.sleep_forever()
