# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import trio
from async_generator import asynccontextmanager

from parsec.event_bus import EventBus
from parsec.backend.config import BackendConfig
from parsec.backend.events import EventsComponent
from parsec.backend.blockstore import blockstore_factory
from parsec.backend.postgresql.handler import PGHandler
from parsec.backend.postgresql.organization import PGOrganizationComponent
from parsec.backend.postgresql.ping import PGPingComponent
from parsec.backend.postgresql.user import PGUserComponent
from parsec.backend.postgresql.message import PGMessageComponent
from parsec.backend.postgresql.realm import PGRealmComponent
from parsec.backend.postgresql.vlob import PGVlobComponent
from parsec.backend.postgresql.block import PGBlockComponent


@asynccontextmanager
async def components_factory(config: BackendConfig, event_bus: EventBus):
    dbh = PGHandler(config.db_url, config.db_min_connections, config.db_max_connections, event_bus)

    user = PGUserComponent(dbh, event_bus)
    organization = PGOrganizationComponent(dbh, user)
    message = PGMessageComponent(dbh)
    realm = PGRealmComponent(dbh)
    vlob = PGVlobComponent(dbh)
    ping = PGPingComponent(dbh)
    blockstore = blockstore_factory(config.blockstore_config, postgresql_dbh=dbh)
    block = PGBlockComponent(dbh, blockstore, vlob)
    events = EventsComponent(event_bus, realm)

    async with trio.open_nursery() as nursery:
        dbh.init(nursery)
        try:
            yield {
                "user": user,
                "message": message,
                "realm": realm,
                "vlob": vlob,
                "ping": ping,
                "blockstore": blockstore,
                "block": block,
                "organization": organization,
                "events": events,
            }

        finally:
            dbh.teardown()
