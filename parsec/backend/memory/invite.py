# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from parsec.backend.invite import BaseInviteComponent


class MemoryInviteComponent(BaseInviteComponent):
    def register_components(self, **other_components):
        pass
