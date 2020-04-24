# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from typing import Tuple
import nacl.utils
from nacl.hash import blake2b
from nacl.bindings import crypto_scalarmult

from parsec.crypto import PrivateKey, PublicKey


class InviteeStateMachine:
    pass


class InviterStateMachine:
    pass


def _generate_nonce() -> bytes:
    return nacl.utils.random(size=64)


def _hash_nonce(nonce: bytes, shared_secret_key: bytes):
    return blake2b(nonce, key=shared_secret_key)


def _build_shared_secret_key(privkey: PrivateKey, pubkey: PublicKey):
    return crypto_scalarmult(privkey.encode(), pubkey.encode())


def _generate_sas(
    invitee_nonce: bytes, inviter_nonce: bytes, shared_secret_key: bytes
) -> Tuple[int, int]:
    # Computes combined HMAC
    combined_nonce = invitee_nonce + inviter_nonce
    # Digest size of 5 bytes so we can split it beween two 20bits SAS
    combined_hmac = blake2b(
        combined_nonce, digest_size=5, key=shared_secret_key, encoder=nacl.encoding.RawEncoder
    )

    # Big endian number extracted from bits [0, 20[
    invitee_sas = combined_hmac[0] << 12 | combined_hmac[1] << 4 | combined_hmac[2] >> 4

    # Big endian number extracted from bits [20, 40[
    inviter_sas = (combined_hmac[2] & 0xF) << 16 | combined_hmac[3] << 8 | combined_hmac[4]

    return invitee_sas, inviter_sas


async def inviter_do_exchange(cmds, invitation):
    inviter_privkey = PrivateKey()
    inviter_nonce = _generate_nonce()

    # Step 1
    invitee_pubkey = await cmds.invite_1_inviter_wait_peer(
        token=invitation.token, inviter_public_key=inviter_privkey.public_key
    )
    shared_secret_key = _build_shared_secret_key(inviter_privkey, invitee_pubkey)

    # Step 2
    invitee_hashed_nonce = await cmds.invite_2a_inviter_get_hashed_nonce(token=invitation.token)
    invitee_nonce = await cmds.invite_2b_inviter_send_nonce(
        token=invitation.token, inviter_nonce=inviter_nonce
    )
    assert _hash_nonce(invitee_nonce) == invitee_hashed_nonce

    invitee_sas, inviter_sas = _generate_sas(
        invitee_nonce=invitee_nonce,
        inviter_nonce=inviter_nonce,
        shared_secret_key=shared_secret_key,
    )

    yield  # TODO: wait for user

    # Step 3
    await cmds.invite_3a_inviter_wait_peer_trust(token=invitation.token)
    await cmds.invite_3b_inviter_signify_trust(token=invitation.token)

    # Step 4
    req = {}
    rep = await cmds.invite_4_inviter_communicate(token=invitation.token, payload=req)
    return rep


async def invitee_do_exchange(cmds, invitation):
    invitee_privkey = PrivateKey()
    invitee_nonce = _generate_nonce()

    # Step 1
    inviter_pubkey = await cmds.invite_1_invitee_wait_peer(
        invitee_public_key=invitee_privkey.public_key
    )
    shared_secret_key = _build_shared_secret_key(invitee_privkey, inviter_pubkey)

    # Step 2
    invitee_hashed_nonce = _hash_nonce(invitee_nonce, shared_secret_key=shared_secret_key)
    inviter_nonce = await cmds.invite_2a_invitee_send_hashed_nonce(
        invitee_hashed_nonce=invitee_hashed_nonce
    )
    await cmds.invite_2b_invitee_send_nonce(invitee_nonce=invitee_nonce)

    invitee_sas, inviter_sas = _generate_sas(
        invitee_nonce=invitee_nonce,
        inviter_nonce=inviter_nonce,
        shared_secret_key=shared_secret_key,
    )

    yield  # TODO: wait for user

    # Step 3
    await cmds.invite_3a_invitee_signify_trust()
    await cmds.invite_3b_invitee_wait_peer_trust()

    # Step 4
    req = {}
    rep = await cmds.invite_4_invitee_communicate(payload=req)
    return rep
