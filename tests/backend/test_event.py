import pytest
import trio


@pytest.mark.trio
async def test_event_subscribe(backend, alice_backend_sock):
    sock = alice_backend_sock

    await sock.send({"cmd": "event_subscribe", "event": "ping", "ping": "foo"})
    rep = await sock.recv()
    assert rep == {"status": "ok"}


@pytest.mark.trio
async def test_event_subscribe_unkown_event(backend, alice_backend_sock):
    sock = alice_backend_sock

    await sock.send({"cmd": "event_subscribe", "event": "foo"})
    rep = await sock.recv()
    assert rep == {"status": "bad_message", "errors": {"event": ["Unsupported value: foo"]}}


async def subscribe_ping(sock, ping):
    await sock.send({"cmd": "event_subscribe", "event": "ping", "ping": ping})
    rep = await sock.recv()
    assert rep == {"status": "ok"}


async def ping(sock, subject):
    await sock.send({"cmd": "ping", "ping": subject})
    rep = await sock.recv()
    assert rep == {"status": "ok", "pong": subject}


@pytest.mark.trio
async def test_event_unsubscribe(backend, alice_backend_sock):
    sock = alice_backend_sock

    await subscribe_ping(sock, "foo")

    await sock.send({"cmd": "event_unsubscribe", "event": "ping", "ping": "foo"})
    rep = await sock.recv()
    assert rep == {"status": "ok"}


@pytest.mark.trio
async def test_event_unsubscribe_ping_bad_msg(backend, alice_backend_sock):
    sock = alice_backend_sock

    await subscribe_ping(sock, "foo")
    await sock.send({"cmd": "event_unsubscribe", "event": "ping", "ping": "bar"})
    rep = await sock.recv()
    assert rep == {"status": "not_subscribed", "reason": "Not subscribed to ('ping', 'bar')"}


@pytest.mark.trio
async def test_event_unsubscribe_bad_event(backend, alice_backend_sock):
    sock = alice_backend_sock

    await sock.send({"cmd": "event_unsubscribe", "event": "message.received"})
    rep = await sock.recv()
    assert rep == {"status": "not_subscribed", "reason": "Not subscribed to 'message.received'"}


@pytest.mark.trio
async def test_event_unsubscribe_unknown_event(backend, alice_backend_sock):
    sock = alice_backend_sock

    await sock.send({"cmd": "event_unsubscribe", "event": "unknown"})
    rep = await sock.recv()
    assert rep == {"status": "bad_message", "errors": {"event": ["Unsupported value: unknown"]}}


@pytest.mark.trio
async def test_ignore_own_events(backend, alice_backend_sock):
    sock = alice_backend_sock

    await subscribe_ping(sock, "foo")

    await ping(sock, "foo")

    await sock.send({"cmd": "event_listen", "wait": False})
    rep = await sock.recv()
    assert rep == {"status": "no_events"}


@pytest.mark.trio
async def test_event_listen(backend, alice_backend_sock, bob_backend_sock):
    alice_sock, bob_sock = alice_backend_sock, bob_backend_sock

    await alice_sock.send({"cmd": "event_listen", "wait": False})
    rep = await alice_sock.recv()
    assert rep == {"status": "no_events"}

    await subscribe_ping(alice_sock, "foo")

    await alice_sock.send({"cmd": "event_listen"})

    await ping(bob_sock, "bar")
    await ping(bob_sock, "foo")

    with trio.fail_after(1):
        rep = await alice_sock.recv()
    assert rep == {"status": "ok", "author": "bob@dev1", "event": "ping", "ping": "foo"}

    await ping(bob_sock, "foo")

    await alice_sock.send({"cmd": "event_listen", "wait": False})
    rep = await alice_sock.recv()
    assert rep == {"status": "ok", "author": "bob@dev1", "event": "ping", "ping": "foo"}

    await alice_sock.send({"cmd": "event_listen", "wait": False})
    rep = await alice_sock.recv()
    assert rep == {"status": "no_events"}


# TODO: test private events
