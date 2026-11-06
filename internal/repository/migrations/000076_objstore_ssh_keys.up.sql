-- SSH public keys that may open a bucket over SFTP (internal/objstore/sftpd). The password of an SFTP login is
-- the bucket's own secret key; these keys are the alternative. Removing a bucket removes its keys.
-- NOTE: numbered after 000075 (functions runtime, branch feat/vpn-functions-lambda): apply that branch first.
CREATE TABLE IF NOT EXISTS objstore_ssh_keys (
    id           uuid         PRIMARY KEY,
    bucket       varchar(63)  NOT NULL REFERENCES objstore_buckets(bucket) ON DELETE CASCADE,
    name         varchar(64)  NOT NULL,
    fingerprint  varchar(80)  NOT NULL,
    public_key   text         NOT NULL,
    created_by   uuid,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    CONSTRAINT uq_objstore_ssh_keys_fp   UNIQUE (bucket, fingerprint),
    CONSTRAINT uq_objstore_ssh_keys_name UNIQUE (bucket, name)
);
