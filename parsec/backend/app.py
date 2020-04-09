# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from typing import Optional
import trio
from structlog import get_logger
from logging import DEBUG as LOG_LEVEL_DEBUG
from pendulum import now as pendulum_now
from async_generator import asynccontextmanager

from parsec.event_bus import EventBus
from parsec.logging import get_log_level
from parsec.crypto import VerifyKey, PublicKey
from parsec.api.version import ApiVersion
from parsec.api.transport import TransportError, TransportClosedByPeer, Transport
from parsec.api.protocol import (
    packb,
    unpackb,
    ProtocolError,
    MessageSerializationError,
    InvalidMessageError,
    ServerHandshake,
    OrganizationID,
    UserID,
    DeviceName,
    DeviceID,
)
from parsec.backend.utils import CancelledByNewRequest, collect_apis
from parsec.backend.config import BackendConfig
from parsec.backend.memory import components_factory as mocked_components_factory
from parsec.backend.postgresql import components_factory as postgresql_components_factory
from parsec.backend.user import UserNotFoundError
from parsec.backend.organization import OrganizationNotFoundError


logger = get_logger()


class BaseClientContext:
    __slots__ = ("transport",)

    def __init__(self, transport: Transport):
        self.transport = transport

    @property
    def api_version(self) -> ApiVersion:
        return self.transport.handshake.backend_api_version

    @property
    def api_auth(self) -> str:
        return self.transport.handshake.answer_type


class AuthenticatedClientContext(BaseClientContext):
    __slots__ = (
        "organization_id",
        "is_admin",
        "device_id",
        "public_key",
        "verify_key",
        "event_bus_ctx",
        "channels",
        "realms",
        "conn_id",
        "logger",
    )

    def __init__(
        self,
        transport: Transport,
        organization_id: OrganizationID,
        is_admin: bool,
        device_id: DeviceID,
        public_key: PublicKey,
        verify_key: VerifyKey,
    ):
        super().__init__(transport)
        self.organization_id = organization_id
        self.is_admin = is_admin
        self.device_id = device_id
        self.public_key = public_key
        self.verify_key = verify_key

        self.event_bus_ctx = None
        self.channels = trio.open_memory_channel(100)
        self.realms = set()

        self.conn_id = self.transport.conn_id
        self.logger = self.transport.logger = self.transport.logger.bind(
            organization_id=str(self.organization_id), client_id=str(self.device_id)
        )

    def __repr__(self):
        return (
            f"AuthenticatedClientContext(conn={self.conn_id}, "
            f"org={self.organization_id}, "
            f"device={self.device_id})"
        )

    @property
    def user_id(self) -> UserID:
        return self.device_id.user_id

    @property
    def device_name(self) -> DeviceName:
        return self.device_id.device_name

    @property
    def send_events_channel(self):
        send_channel, _ = self.channels
        return send_channel

    @property
    def receive_events_channel(self):
        _, receive_channel = self.channels
        return receive_channel


class APIV1_AnonymousClientContext(BaseClientContext):
    __slots__ = ("organization_id", "conn_id", "logger")

    def __init__(self, transport: Transport, organization_id: OrganizationID):
        super().__init__(transport)
        self.organization_id = organization_id

        self.conn_id = self.transport.conn_id
        self.logger = self.transport.logger = self.transport.logger.bind(
            organization_id=str(self.organization_id), client_id="<anonymous>"
        )

    def __repr__(self):
        return f"APIV1_AnonymousClientContext(conn={self.conn_id}, org={self.organization_id})"


class AnonymousClientContext(BaseClientContext):
    __slots__ = ("organization_id", "operation", "token", "conn_id", "logger")

    def __init__(
        self, transport: Transport, organization_id: OrganizationID, operation: str, token: str
    ):
        super().__init__(transport)
        self.organization_id = organization_id
        self.operation = operation
        self.token = token

        self.conn_id = self.transport.conn_id
        self.logger = self.transport.logger = self.transport.logger.bind(
            organization_id=str(self.organization_id), client_id="<anonymous>"
        )

    def __repr__(self):
        return f"AnonymousClientContext(conn={self.conn_id}, org={self.organization_id})"


class APIV1_AdministrationClientContext(BaseClientContext):
    __slots__ = ("conn_id", "logger")

    def __init__(self, transport: Transport):
        super().__init__(transport)

        self.conn_id = self.transport.conn_id
        self.logger = self.transport.logger = self.transport.logger.bind(
            client_id="<administration>"
        )

    def __repr__(self):
        return f"APIV1_AdministrationClientContext(conn={self.conn_id})"


def _filter_binary_fields(data):
    return {k: v if not isinstance(v, bytes) else b"[...]" for k, v in data.items()}


@asynccontextmanager
async def backend_app_factory(config: BackendConfig, event_bus: Optional[EventBus] = None):
    event_bus = event_bus or EventBus()

    if config.db_url == "MOCKED":
        components_factory = mocked_components_factory
    else:
        components_factory = postgresql_components_factory

    async with components_factory(config=config, event_bus=event_bus) as components:
        yield BackendApp(
            config=config,
            event_bus=event_bus,
            user=components["user"],
            invite=components["invite"],
            organization=components["organization"],
            message=components["message"],
            realm=components["realm"],
            vlob=components["vlob"],
            ping=components["ping"],
            blockstore=components["blockstore"],
            block=components["block"],
            events=components["events"],
        )


class BackendApp:
    def __init__(
        self,
        config,
        event_bus,
        user,
        invite,
        organization,
        message,
        realm,
        vlob,
        ping,
        blockstore,
        block,
        events,
    ):
        self.config = config
        self.event_bus = event_bus

        self.user = user
        self.invite = invite
        self.organization = organization
        self.message = message
        self.realm = realm
        self.vlob = vlob
        self.ping = ping
        self.blockstore = blockstore
        self.block = block
        self.events = events

        self.apis = collect_apis(
            user, invite, organization, message, realm, vlob, ping, blockstore, block, events
        )

    async def _do_handshake(self, transport):
        context = None
        error_infos = None
        try:
            handshake = transport.handshake = ServerHandshake()
            challenge_req = handshake.build_challenge_req()
            await transport.send(challenge_req)
            answer_req = await transport.recv()

            handshake.process_answer_req(answer_req)

            if handshake.answer_type == "authenticated":
                organization_id = handshake.answer_data["organization_id"]
                device_id = handshake.answer_data["device_id"]
                expected_rvk = handshake.answer_data["rvk"]
                try:
                    organization = await self.organization.get(organization_id)
                    user, device = await self.user.get_user_with_device(organization_id, device_id)

                except (OrganizationNotFoundError, UserNotFoundError, KeyError) as exc:
                    result_req = handshake.build_bad_identity_result_req()
                    error_infos = {
                        "reason": str(exc),
                        "handshake_type": "authenticated",
                        "organization_id": organization_id,
                        "device_id": device_id,
                    }

                else:
                    if organization.root_verify_key != expected_rvk:
                        result_req = handshake.build_rvk_mismatch_result_req()
                        error_infos = {
                            "reason": "Bad root verify key",
                            "handshake_type": "authenticated",
                            "organization_id": organization_id,
                            "device_id": device_id,
                        }

                    elif (
                        organization.expiration_date is not None
                        and organization.expiration_date <= pendulum_now()
                    ):
                        result_req = handshake.build_organization_expired_result_req()
                        error_infos = {
                            "reason": "Expired organization",
                            "handshake_type": "authenticated",
                            "organization_id": organization_id,
                            "device_id": device_id,
                        }

                    elif user.revoked_on and user.revoked_on <= pendulum_now():
                        result_req = handshake.build_revoked_device_result_req()
                        error_infos = {
                            "reason": "Revoked device",
                            "handshake_type": "authenticated",
                            "organization_id": organization_id,
                            "device_id": device_id,
                        }

                    else:
                        context = AuthenticatedClientContext(
                            transport,
                            organization_id,
                            user.is_admin,
                            device_id,
                            user.public_key,
                            device.verify_key,
                        )
                        result_req = handshake.build_result_req(device.verify_key)

            elif handshake.answer_type == "anonymous":
                organization_id = handshake.answer_data["organization_id"]
                try:
                    organization = await self.organization.get(organization_id)

                except OrganizationNotFoundError:
                    result_req = handshake.build_bad_identity_result_req()
                    error_infos = {
                        "reason": "Bad organization",
                        "handshake_type": "anonymous",
                        "organization_id": organization_id,
                    }

                else:
                    if (
                        organization.expiration_date is not None
                        and organization.expiration_date <= pendulum_now()
                    ):
                        result_req = handshake.build_organization_expired_result_req()
                        error_infos = {
                            "reason": "Expired organization",
                            "handshake_type": "anonymous",
                            "organization_id": organization_id,
                        }

                    elif handshake.client_api_version.version == 1:
                        expected_rvk = handshake.answer_data["rvk"]
                        if expected_rvk and organization.root_verify_key != expected_rvk:
                            result_req = handshake.build_rvk_mismatch_result_req()
                            error_infos = {
                                "reason": "Bad root verify key",
                                "handshake_type": "anonymous",
                                "organization_id": organization_id,
                            }
                        else:
                            context = APIV1_AnonymousClientContext(
                                transport, organization_id=organization_id
                            )
                            result_req = handshake.build_result_req()

                    else:  # v2
                        context = AnonymousClientContext(
                            transport,
                            organization_id=organization_id,
                            operation=handshake.answer_data["operation"],
                            token=handshake.answer_data["token"],
                        )
                        result_req = handshake.build_result_req()

            elif handshake.answer_type == "administration":
                if handshake.answer_data["token"] == self.config.administration_token:
                    context = APIV1_AdministrationClientContext(transport)
                    result_req = handshake.build_result_req()
                else:
                    result_req = handshake.build_bad_administration_token_result_req()
                    error_infos = {"reason": "Bad token", "handshake_type": "administration"}

            else:
                assert False

        except ProtocolError as exc:
            result_req = handshake.build_bad_protocol_result_req(str(exc))
            error_infos = {"reason": str(exc), "handshake_type": handshake.answer_type}

        await transport.send(result_req)
        return context, error_infos

    async def handle_client(self, stream):
        selected_logger = logger

        try:
            transport = await Transport.init_for_server(stream)

        except TransportClosedByPeer as exc:
            selected_logger.info("Connection dropped: client has left", reason=str(exc))
            return

        except TransportError as exc:
            # A crash during transport setup could mean the client tried to
            # access us from a web browser (hence sending http request).

            content_body = b"This service requires use of the WebSocket protocol"
            content = (
                b"HTTP/1.1 426 OK\r\n"
                b"Upgrade: WebSocket\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: Upgrade\r\n"
                b"Content-Type: text/html; charset=UTF-8\r\n"
                b"\r\n"
            ) % len(content_body)

            try:
                await stream.send_all(content + content_body)
                await stream.aclose()

            except trio.BrokenResourceError:
                # Stream is really dead, nothing else to do...
                pass

            selected_logger.info("Connection dropped: websocket error", reason=str(exc))
            return

        selected_logger = transport.logger

        try:
            client_ctx, error_infos = await self._do_handshake(transport)
            if not client_ctx:
                # Invalid handshake
                await stream.aclose()
                selected_logger.info("Connection dropped: bad handshake", **error_infos)
                return

            selected_logger = client_ctx.logger
            selected_logger.info("Connection established")

            if hasattr(client_ctx, "event_bus_ctx"):
                with self.event_bus.connection_context() as client_ctx.event_bus_ctx:
                    with trio.CancelScope() as cancel_scope:

                        def _on_revoked(event, organization_id, user_id):
                            if (
                                organization_id == client_ctx.organization_id
                                and user_id == client_ctx.user_id
                            ):
                                cancel_scope.cancel()

                        client_ctx.event_bus_ctx.connect("user.revoked", _on_revoked)
                        await self._handle_client_loop(transport, client_ctx)

            else:
                await self._handle_client_loop(transport, client_ctx)

            await transport.aclose()

        except TransportClosedByPeer as exc:
            selected_logger.info("Connection dropped: client has left", reason=str(exc))

        except (TransportError, MessageSerializationError) as exc:
            rep = {"status": "invalid_msg_format", "reason": "Invalid message format"}
            try:
                await transport.send(packb(rep))
            except TransportError:
                pass
            await transport.aclose()
            selected_logger.info("Connection dropped: invalid data", reason=str(exc))

    async def _handle_client_loop(self, transport, client_ctx):
        # Retreive the allowed commands according to api version and auth type
        api_cmds = self.apis[client_ctx.api_version.version][client_ctx.api_auth]

        raw_req = None
        while True:
            # raw_req can be already defined if we received a new request
            # while processing a command
            raw_req = raw_req or await transport.recv()
            req = unpackb(raw_req)
            if get_log_level() <= LOG_LEVEL_DEBUG:
                client_ctx.logger.debug("Request", req=_filter_binary_fields(req))
            try:
                cmd = req.get("cmd", "<missing>")
                if not isinstance(cmd, str):
                    raise KeyError()

                cmd_func = api_cmds[cmd]

            except KeyError:
                rep = {"status": "unknown_command", "reason": "Unknown command"}

            else:
                try:
                    rep = await cmd_func(client_ctx, req)

                except InvalidMessageError as exc:
                    rep = {
                        "status": "bad_message",
                        "errors": exc.errors,
                        "reason": "Invalid message.",
                    }

                except ProtocolError as exc:
                    rep = {"status": "bad_message", "reason": str(exc)}

                except CancelledByNewRequest as exc:
                    # Long command handling such as message_get can be cancelled
                    # when the peer send a new request
                    raw_req = exc.new_raw_req
                    continue

            if get_log_level() <= LOG_LEVEL_DEBUG:
                client_ctx.logger.debug("Response", rep=_filter_binary_fields(req))
            else:
                client_ctx.logger.info("Request", cmd=cmd, status=rep["status"])
            raw_rep = packb(rep)
            await transport.send(raw_rep)
            raw_req = None
