from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from io import BytesIO
import json
from os import environ
import pdb
import sys
import traceback
from importlib import import_module
from getpass import getpass
import asyncio
import click
from logbook import WARNING
from effect2 import Effect, do

from parsec.tools import logger_stream
from parsec.server import WebSocketServer
from parsec.backend import (InMemoryMessageService, MockedGroupService, MockedUserVlobService,
                            MockedVlobService, InMemoryPubKeyService)
from parsec.core import app_factory, run_app
from parsec.core.backend import BackendComponent
from parsec.core.identity import IdentityComponent
from parsec.core.fs import FSComponent
from parsec.core.privkey import EPrivkeyLoad
from parsec.core.privkey import PrivKeyComponent
from parsec.core.synchronizer import SynchronizerComponent
from parsec.core.block import in_memory_block_dispatcher_factory, s3_block_dispatcher_factory
from parsec.core.identity import EIdentityLoad
from parsec.ui.shell import start_shell


# TODO: remove me once RSA key loading and backend handling are easier
JOHN_DOE_IDENTITY = 'John_Doe'
JOHN_DOE_PRIVATE_KEY = b"""
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDCqVQVdVhJqW9rrbObvDZ4ET6FoIyVn6ldWhOJaycMeFYBN3t+
cGr9/xHPGrYXK63nc8x4IVxhfXZ7JwrQ+AJv935S3rAV6JhDKDfDFrkzUVZmcc/g
HhjiP7rTAt4RtACvhZwrDuj3Pc4miCpGN/T3tbOKG889JN85nABKR9WkdwIDAQAB
AoGBAJFU3Dr9FgJA5rfMwpiV51CzByu61trqjgbtNkLVZhzwRr23z5Jxmd+yLHik
J6ia6sYvdUuHFLKQegGt/2xOjXn8UBpa725gLojHn2umtJDL7amTlBwiJfNXuZrF
BSKK9+xZnNDWMq1IuCqPeintbve+MNSc62JYuGGtXSz9L5f5AkEA/xBkUksBfEUl
65oEPgxvMKHNjLq48otRmCaG+i3MuQqTYQ+c8Z/l26yQL4OV2b36a8/tTaLhwhAZ
Ibtv05NKfQJBAMNgMbOsUWpY8A1Cec79Oj6RVe79E5ciZ4mW3lx5tjJRyNxwlQag
u+T6SwBIa6xMfLBQeizzxqXqxAyW/riQ6QMCQQCadUu7Re6tWZaAGTGufYsr8R/v
s/dh8ZpEwDgG8otCFzRul6zb6Y+huttJ2q55QIGQnka/N/7srSD6+23Zux1lAkBx
P30PzL6UimD7DqFUnev5AH1zPjbwz/x8AHt71wEJQebQAGIhqWHAZGS9ET14bg2I
ld172QI4glCJi6yyhyzJAkBzfmHZEE8FyLCz4z6b+Z2ghMds2Xz7RwgVqCIXt9Ku
P7Bq0eXXgyaBo+jpr3h4K7QnPh+PaHSlGqSfczZ6GIpx
-----END RSA PRIVATE KEY-----
"""
JOHN_DOE_PUBLIC_KEY = b"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCqVQVdVhJqW9rrbObvDZ4ET6F
oIyVn6ldWhOJaycMeFYBN3t+cGr9/xHPGrYXK63nc8x4IVxhfXZ7JwrQ+AJv935S
3rAV6JhDKDfDFrkzUVZmcc/gHhjiP7rTAt4RtACvhZwrDuj3Pc4miCpGN/T3tbOK
G889JN85nABKR9WkdwIDAQAB
-----END PUBLIC KEY-----
"""

DEFAULT_CORE_UNIX_SOCKET = '/tmp/parsec'


@click.group()
def cli():
    pass


@click.command()
@click.argument('id')
@click.argument('args', nargs=-1)
@click.option('socket_path', '--socket', '-s', default=DEFAULT_CORE_UNIX_SOCKET,
              help='Path to the UNIX socket (default: %s).' % DEFAULT_CORE_UNIX_SOCKET)
def cmd(id, args, socket_path, per_cmd_connection):
    from socket import socket, AF_UNIX, SOCK_STREAM
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(socket)
    try:
        msg = '%s %s' % (id, args)
        sock.send(msg.encode())
        resp = sock.recv(4096)
        print(resp)
    finally:
        sock.close()


@click.command()
@click.option('--socket', '-s', default=DEFAULT_CORE_UNIX_SOCKET,
              help='Path to the UNIX socket (default: %s).' % DEFAULT_CORE_UNIX_SOCKET)
def shell(socket):
    start_shell(socket)


def run_with_pdb(cmd, *args, **kwargs):
    # Stolen from pdb.main
    pdb_context = pdb.Pdb()
    try:
        ret = pdb_context.runcall(cmd, **kwargs)
        print("The program finished")
        return ret
    except pdb.Restart:
        print("Restarting %s with arguments: %s, %s" % (cmd.__name__, args, kwargs))
        # Yes, that's a hack
        return run_with_pdb(cmd, *args, **kwargs)
    except SystemExit:
        # In most cases SystemExit does not warrant a post-mortem session.
        print("The program exited via sys.exit(). Exit status:", end=' ')
        print(sys.exc_info()[1])
    except SyntaxError:
        traceback.print_exc()
        sys.exit(1)
    except:
        traceback.print_exc()
        print("Uncaught exception. Entering post mortem debugging")
        print("Running 'cont' or 'step' will restart the program")
        t = sys.exc_info()[2]
        pdb_context.interaction(None, t)
        print("Post mortem debugger finished.")


@click.command(name='add-privkey')
@click.option('socket_path', '--socket', '-s', default=DEFAULT_CORE_UNIX_SOCKET,
              help='Path to the UNIX socket (default: %s).' % DEFAULT_CORE_UNIX_SOCKET)
@click.argument('identity')
@click.argument('password')
@click.argument('keyfile', type=click.File())
def add_privkey(socket_path, identity, password, keyfile):

    async def _send_cmd(socket_path, msg):
        reader, writer = await asyncio.open_unix_connection(path=socket_path)
        writer.write(msg.encode())
        writer.write(b'\n')
        raw_resp = await reader.readline()
        resp = json.loads(raw_resp.decode())
        if resp != {'status': 'ok'}:
            raise SystemExit('%s' % resp['label'])
        writer.close()

    msg = {'cmd': 'privkey_add',
           'id': identity,
           'key': keyfile.read(),
           'password': password}
    msg = json.dumps(msg)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_send_cmd(socket_path, msg))


@click.command(name='gen-privkey')
@click.argument('output_keyfile', type=click.File('wb'))
def gen_privkey(output_keyfile):
    key = rsa.generate_private_key(backend=default_backend(),
                                   public_exponent=65537,
                                   key_size=2048)
    pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption())
    identity_key = BytesIO(pem)
    output_keyfile.write(identity_key.read())


@click.command()
@click.option('--socket', '-s', default=DEFAULT_CORE_UNIX_SOCKET,
              help='Path to the UNIX socket exposing the core API (default: %s).' %
              DEFAULT_CORE_UNIX_SOCKET)
@click.option('--backend-host', '-H', default='ws://localhost:6777')
@click.option('--backend-watchdog', '-W', type=click.INT, default=None)
@click.option('--block-store', '-B')
@click.option('--debug', '-d', is_flag=True)
@click.option('--pdb', is_flag=True)
@click.option('--identity', '-i', default=None)
@click.option('--password', '-p', default=None)
@click.option('--I-am-John', is_flag=True, help='Log as dummy John Doe user')
def core(**kwargs):
    if kwargs.pop('pdb'):
        return run_with_pdb(_core, **kwargs)
    else:
        return _core(**kwargs)


def _core(socket, backend_host, backend_watchdog, block_store, debug, identity, password, i_am_john):
    loop = asyncio.get_event_loop()
    if block_store:
        if block_store.startswith('s3:'):
            try:
                # from parsec.core.block_service_s3 import S3BlockService
                _, region, bucket, key_id, key_secret = block_store.split(':')
            except ImportError as exc:
                raise SystemExit('Parsec needs boto3 to support S3 block storage (error: %s).' %
                                 exc)
            except ValueError:
                raise SystemExit('Invalid --block-store value '
                                 ' (should be `s3:<region>:<bucket>:<id>:<secret>`.')
            raise NotImplementedError('Not yet :-(')
            block_dispatcher = s3_block_dispatcher_factory(region, bucket, key_id, key_secret)
            store_type = 's3:%s:%s' % (region, bucket)
        else:
            raise SystemExit('Unknown block store `%s` (only `s3:<region>:<bucket>:<id>:<secret>`'
                             ' is supported so far.' % block_store)
    else:
        store_type = 'mocked in memory'
        block_dispatcher = in_memory_block_dispatcher_factory()
    privkey_component = PrivKeyComponent()
    backend_component = BackendComponent(backend_host, backend_watchdog)
    fs_component = FSComponent()
    identity_component = IdentityComponent()
    synchronizer_component = SynchronizerComponent()
    app = app_factory(
        privkey_component.get_dispatcher(), backend_component.get_dispatcher(),
        fs_component.get_dispatcher(), synchronizer_component.get_dispatcher(),
        identity_component.get_dispatcher(), block_dispatcher)
    if (identity or password) and (not identity or not password):
        raise SystemExit('--identity and --password params should be provided together.')
    # TODO: remove me once RSA key loading and backend handling are easier
    if i_am_john:
        identity = JOHN_DOE_IDENTITY
        password = 'secret'
        from io import BytesIO
        identity_key = BytesIO(JOHN_DOE_PRIVATE_KEY)

        @do
        def load_identity():
            yield Effect(EIdentityLoad(identity, identity_key.read()))
            print('Welcome back M. Doe')
        loop.run_until_complete(app.async_perform(load_identity()))
    elif identity:
        @do
        def load_privkey():
            password = getpass()
            yield Effect(EPrivkeyLoad(identity, password))
            print('Connected as %s' % identity)
        loop.run_until_complete(app.async_perform(load_privkey()))
    if debug:
        loop.set_debug(True)
    else:
        logger_stream.level = WARNING
    print('Starting parsec core on %s (connecting to backend %s and block store %s)' %
          (socket, backend_host, store_type))
    run_app(socket, app=app, loop=loop)
    print('Bye ;-)')


@click.command()
@click.option('--pubkeys', default=None)
@click.option('--host', '-H', default=None, help='Host to listen on (default: localhost)')
@click.option('--port', '-P', default=None, type=int, help=('Port to listen on (default: 6777)'))
@click.option('--no-client-auth', is_flag=True,
              help='Disable authentication handshake on client connection (default: false)')
@click.option('--store', '-s', default=None, help="Store configuration (default: in memory)")
@click.option('--debug', '-d', is_flag=True)
@click.option('--pdb', is_flag=True)
def backend(**kwargs):
    if kwargs.pop('pdb'):
        return run_with_pdb(_backend, **kwargs)
    else:
        return _backend(**kwargs)


def _backend(host, port, pubkeys, no_client_auth, store, debug):
    host = host or environ.get('HOST', 'localhost')
    port = port or int(environ.get('PORT', 6777))
    # TODO load pubkeys attribute
    pubkey_svc = InMemoryPubKeyService()
    if no_client_auth:
        server = WebSocketServer()
    else:
        server = WebSocketServer(pubkey_svc.handshake)
    server.register_service(pubkey_svc)
    if store:
        if store.startswith('postgres://'):
            store_type = 'PostgreSQL'
            from parsec.backend import postgresql
            server.register_service(postgresql.PostgreSQLService(store))
            server.register_service(postgresql.PostgreSQLMessageService())
            server.register_service(postgresql.PostgreSQLGroupService())
            server.register_service(postgresql.PostgreSQLUserVlobService())
            server.register_service(postgresql.PostgreSQLVlobService())
        else:
            raise SystemExit('Unknown store `%s` (should be a postgresql db url).' % store)
    else:
        store_type = 'mocked in memory'
        server.register_service(InMemoryMessageService())
        server.register_service(MockedGroupService())
        server.register_service(MockedUserVlobService())
        server.register_service(MockedVlobService())
    loop = asyncio.get_event_loop()

    # TODO: remove me once RSA key loading and backend handling are easier
    @server.post_bootstrap
    async def post_boostrap():
        await pubkey_svc.add_pubkey(JOHN_DOE_IDENTITY, JOHN_DOE_PUBLIC_KEY)
    if debug:
        loop.set_debug(True)
    else:
        logger_stream.level = WARNING
    print('Starting parsec backend on %s:%s with store %s' % (host, port, store_type))
    server.start(host, port, loop=loop)
    print('Bye ;-)')


cli.add_command(cmd)
cli.add_command(shell)
cli.add_command(add_privkey)
cli.add_command(gen_privkey)
cli.add_command(core)
cli.add_command(backend)


def _add_command_if_can_import(path, name=None):
    module_path, field = path.rsplit('.', 1)
    try:
        module = import_module(module_path)
        cli.add_command(getattr(module, field), name=name)
    except (ImportError, AttributeError):
        pass


_add_command_if_can_import('parsec.backend.postgresql.cli', 'postgresql')
_add_command_if_can_import('parsec.ui.fuse.cli', 'fuse')


if __name__ == '__main__':
    cli()
