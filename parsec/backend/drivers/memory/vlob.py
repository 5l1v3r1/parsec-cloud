from parsec.backend.vlob import VlobAtom, BaseVlobComponent
from parsec.backend.exceptions import TrustSeedError, VersionError, NotFoundError, ParsecError


class MemoryVlob:
    def __init__(self, *args, **kwargs):
        atom = VlobAtom(*args, **kwargs)
        self.id = atom.id
        self.read_trust_seed = atom.read_trust_seed
        self.write_trust_seed = atom.write_trust_seed
        self.blob_versions = [atom.blob]
        self.is_sink = atom.is_sink


class MemoryVlobComponent(BaseVlobComponent):
    def __init__(self, signal_ns):
        self._signal_vlob_updated = signal_ns.signal("vlob_updated")
        self.vlobs = {}

    async def group_check(self, to_check):
        changed = []
        for item in to_check:
            id = item["id"]
            rts = item["rts"]
            version = item["version"]
            if version == 0:
                changed.append({"id": id, "version": version})
            else:
                vlob = await self.read(id, rts)
                if vlob.version != version:
                    changed.append({"id": id, "version": vlob.version})
        return changed

    async def create(self, id, rts, wts, blob, notify_beacons=(), author="anonymous"):
        # TODO
        # for beacon_id in notify_beacons:
        #     await self._update_sink_vlob(beacon_id, id.encode("utf-8"))

        vlob = MemoryVlob(id, rts, wts, blob)
        self.vlobs[vlob.id] = vlob
        return VlobAtom(
            id=vlob.id,
            read_trust_seed=vlob.read_trust_seed,
            write_trust_seed=vlob.write_trust_seed,
            blob=vlob.blob_versions[0],
        )

        self._signal_vlob_updated.send(author, subject=id)

    async def read(self, id, rts, version=None):
        try:
            vlob = self.vlobs[id]
            if vlob.read_trust_seed != rts:
                raise TrustSeedError()

        except KeyError:
            raise NotFoundError("Vlob not found.")

        version = version or len(vlob.blob_versions)
        try:
            return VlobAtom(
                id=vlob.id,
                read_trust_seed=vlob.read_trust_seed,
                write_trust_seed=vlob.write_trust_seed,
                blob=vlob.blob_versions[version - 1],
                version=version,
            )

        except IndexError:
            raise VersionError("Wrong blob version.")

    async def update(self, id, wts, version, blob, notify_beacons=(), author="anonymous"):
        try:
            vlob = self.vlobs[id]
            if vlob.write_trust_seed != wts:
                raise TrustSeedError("Invalid write trust seed.")

        except KeyError:
            raise NotFoundError("Vlob not found.")

        if version - 1 == len(vlob.blob_versions):
            vlob.blob_versions.append(blob)
        else:
            raise VersionError("Wrong blob version.")

        self._signal_vlob_updated.send(author, subject=id)
        # TODO
        # for sink_id in notify_sinks:
        #     await self._update_sink_vlob(sink_id, id.encode("utf-8"))

    # async def _notify_beacons(self, sink_id, data):
    #     try:
    #         vlob = self.vlobs[sink_id]
    #         if not vlob.is_sink:
    #             raise ParsecError("not_a_sink", "Not a sink vlob")
    #         vlob.blob_versions.append(data)

    #     except KeyError:
    #         self.vlobs[sink_id] = MemoryVlob(
    #             id=sink_id, read_trust_seed=sink_id, blob=data, is_sink=True
    #         )

    #     self._signal_vlob_updated.send(author, subject=sink_id)
