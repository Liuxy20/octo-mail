-- One-time replay guard for short-lived OCTO gateway assertions.

CREATE TABLE IF NOT EXISTS gateway_assertion_nonces (
    issuer     text NOT NULL,
    nonce      text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, nonce)
);

CREATE INDEX IF NOT EXISTS gateway_assertion_nonces_expiry
    ON gateway_assertion_nonces (expires_at);
