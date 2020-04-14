# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pytest

from parsec.api.protocol import packb, unpackb, OrganizationID
from parsec.api.version import API_VERSION
from parsec.api.transport import Transport
from parsec.api.protocol.handshake import (
    AnonymousOperation,
    AuthenticatedClientHandshake,
    AnonymousClientHandshake,
    HandshakeRVKMismatch,
    HandshakeBadIdentity,
    HandshakeOrganizationExpired,
    ApiVersion,
)


@pytest.mark.trio
async def test_handshake_invalid_format(backend, server_factory):
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        await transport.recv()  # Get challenge
        req = {"handshake": "dummy", "client_api_version": API_VERSION}
        await transport.send(packb(req))
        result_req = await transport.recv()
        assert unpackb(result_req) == {
            "handshake": "result",
            "result": "bad_protocol",
            "help": "{'handshake': ['Invalid value, should be `answer`']}",
        }


@pytest.mark.trio
async def test_handshake_incompatible_version(backend, server_factory):
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        incompatible_version = ApiVersion(API_VERSION.version + 1, 0)
        await transport.recv()  # Get challenge
        req = {
            "handshake": "answer",
            "type": "anonymous",
            "client_api_version": incompatible_version,
            "organization_id": OrganizationID("Org"),
            "token": "whatever",
        }
        await transport.send(packb(req))
        result_req = await transport.recv()
        assert unpackb(result_req) == {
            "handshake": "result",
            "result": "bad_protocol",
            "help": "No overlap between client API versions {3.0} and backend API versions {2.0, 1.2}",
        }


@pytest.mark.trio
async def test_authenticated_handshake_good(backend, server_factory, alice):
    ch = AuthenticatedClientHandshake(
        organization_id=alice.organization_id,
        device_id=alice.device_id,
        user_signkey=alice.signing_key,
        root_verify_key=alice.root_verify_key,
    )

    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        ch.process_result_req(result_req)

        assert ch.client_api_version == API_VERSION
        assert ch.backend_api_version == API_VERSION


@pytest.mark.trio
async def test_authenticated_handshake_bad_rvk(backend, server_factory, alice, otherorg):
    ch = AuthenticatedClientHandshake(
        organization_id=alice.organization_id,
        device_id=alice.device_id,
        user_signkey=alice.signing_key,
        root_verify_key=otherorg.root_verify_key,
    )
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeRVKMismatch):
            ch.process_result_req(result_req)


@pytest.mark.xfail(reason="API not implemented yet")
@pytest.mark.trio
@pytest.mark.parametrize("operation", AnonymousOperation)
async def test_anonymous_handshake_good(backend, server_factory, coolorg, alice, operation):
    if operation == AnonymousOperation.CLAIM_USER:
        token = await backend.invite.new_user(
            organization_id=coolorg.organization_id,
            author=alice.device_id,
            email="zack@example.com",
        )  # TODO
    else:  # claim_device
        token = await backend.invite.new_device(
            organization_id=coolorg.organization_id, author=alice.device_id
        )  # TODO

    ch = AnonymousClientHandshake(
        organization_id=coolorg.organization_id, operation=operation, token=token
    )
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        ch.process_result_req(result_req)

        assert ch.client_api_version == API_VERSION
        assert ch.backend_api_version == API_VERSION


@pytest.mark.xfail(reason="API not implemented yet")
@pytest.mark.trio
@pytest.mark.parametrize("operation", AnonymousOperation)
async def test_anonymous_handshake_bad_token(backend, server_factory, coolorg, otherorg, operation):
    ch = AnonymousClientHandshake(
        organization_id=coolorg.organization_id, operation=operation, token="123abc"
    )
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeRVKMismatch):
            ch.process_result_req(result_req)


@pytest.mark.xfail(reason="API not implemented yet")
@pytest.mark.trio
async def test_anonymous_handshake_bad_operation(backend, server_factory, coolorg):
    ch = AnonymousClientHandshake(
        organization_id=coolorg.organization_id, operation="DUMMY_OPERATION", token="123abc"
    )
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeRVKMismatch):
            ch.process_result_req(result_req)


@pytest.mark.xfail(reason="API not implemented yet")
@pytest.mark.trio
async def test_anonymous_handshake_bad_token_type(backend, server_factory, coolorg, alice):
    token = await backend.invite.new_user(
        organization_id=coolorg.organization_id, author=alice.device_id, email="zack@example.com"
    )  # TODO

    ch = AnonymousClientHandshake(
        organization_id=coolorg.organization_id,
        operation=AnonymousOperation.CLAIM_DEVICE,
        token=token,
    )
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeRVKMismatch):
            ch.process_result_req(result_req)


@pytest.mark.trio
@pytest.mark.parametrize("type", ["anonymous", "authenticated"])
async def test_handshake_unknown_organization(
    backend, server_factory, organization_factory, alice, type
):
    bad_org = organization_factory()
    if type == "anonymous":
        ch = AnonymousClientHandshake(
            organization_id=bad_org.organization_id,
            operation=AnonymousOperation.CLAIM_USER,
            token="whatever",
        )
    else:  # authenticated
        ch = AuthenticatedClientHandshake(
            organization_id=bad_org.organization_id,
            device_id=alice.device_id,
            user_signkey=alice.signing_key,
            root_verify_key=bad_org.root_verify_key,
        )

    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeBadIdentity):
            ch.process_result_req(result_req)


@pytest.mark.trio
@pytest.mark.parametrize("type", ["anonymous", "authenticated"])
async def test_handshake_expired_organization(backend, server_factory, expiredorg, alice, type):
    if type == "anonymous":
        ch = AnonymousClientHandshake(
            organization_id=expiredorg.organization_id,
            operation=AnonymousOperation.CLAIM_USER,
            token="whatever",
        )
    else:  # authenticated
        ch = AuthenticatedClientHandshake(
            organization_id=expiredorg.organization_id,
            device_id=alice.device_id,
            user_signkey=alice.signing_key,
            root_verify_key=expiredorg.root_verify_key,
        )

    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeOrganizationExpired):
            ch.process_result_req(result_req)


@pytest.mark.trio
async def test_authenticated_handshake_unknown_device(backend, server_factory, mallory):
    ch = AuthenticatedClientHandshake(
        organization_id=mallory.organization_id,
        device_id=mallory.device_id,
        user_signkey=mallory.signing_key,
        root_verify_key=mallory.root_verify_key,
    )
    async with server_factory(backend.handle_client) as server:
        stream = server.connection_factory()
        transport = await Transport.init_for_client(stream, server.addr.hostname)

        challenge_req = await transport.recv()
        answer_req = ch.process_challenge_req(challenge_req)

        await transport.send(answer_req)
        result_req = await transport.recv()
        with pytest.raises(HandshakeBadIdentity):
            ch.process_result_req(result_req)
