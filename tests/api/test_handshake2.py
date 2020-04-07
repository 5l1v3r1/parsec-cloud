# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from parsec.api.protocol.handshake import ServerHandshake, AnonymousClientHandshake
from parsec.api.version import API_V2_VERSION


def test_anonymous_handshake(coolorg):
    token = "abcd1234"

    sh = ServerHandshake()

    ch = AnonymousClientHandshake(
        operation="bootstrap_organization", organization_id=coolorg.organization_id, token=token
    )
    assert sh.state == "stalled"

    challenge_req = sh.build_challenge_req()
    assert sh.state == "challenge"

    answer_req = ch.process_challenge_req(challenge_req)

    sh.process_answer_req(answer_req)
    assert sh.state == "answer"
    assert sh.answer_type == "anonymous"
    assert sh.answer_data == {
        "client_api_version": API_V2_VERSION,
        "organization_id": coolorg.organization_id,
        "operation": "bootstrap_organization",
        "token": token,
    }
    result_req = sh.build_result_req()
    assert sh.state == "result"

    ch.process_result_req(result_req)
    assert sh.client_api_version == API_V2_VERSION
