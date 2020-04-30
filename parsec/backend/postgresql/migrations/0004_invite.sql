-- Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS


-------------------------------------------------------
--  Migration
-------------------------------------------------------


CREATE TYPE invitation_type AS ENUM ('USER', 'DEVICE');
CREATE TYPE invitation_status AS ENUM ('IDLE', 'READY', 'DELETED');
CREATE TYPE invitation_deleted_reason AS ENUM ('FINISHED', 'CANCELLED', 'ROTTEN');


CREATE TABLE invitation (
    _id SERIAL PRIMARY KEY,
    organization INTEGER REFERENCES organization (_id) NOT NULL,
    token UUID NOT NULL,
    type invitation_type NOT NULL,

    greeter INTEGER REFERENCES user_ (_id) NOT NULL,
    greeter_human INTEGER REFERENCES human (_id),
    claimer_email VARCHAR(255),  -- Required for when type=USER
    created_on TIMESTAMPTZ NOT NULL,

    status invitation_status NOT NULL,
	deleted_on TIMESTAMPTZ,
	deleted_reason invitation_deleted_reason,

    greeter_to_claimer_msg BYTEA,
    claimer_to_greeter_msg BYTEA,

    UNIQUE(organization, token)
);
