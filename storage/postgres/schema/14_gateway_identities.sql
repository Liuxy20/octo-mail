-- Trusted OCTO gateway identities.
--
-- A binding is exact to issuer + OCTO subject + Space. It resolves to one
-- human owner principal and that Space's internal browser-default account inside
-- one octo-mail tenant. The default account is not an Agent mailbox and is not
-- eligible for Bot authorization. Request authentication still verifies account
-- ownership on every use.

CREATE TABLE IF NOT EXISTS gateway_identities (
    id                 bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    issuer             text NOT NULL,
    subject            text NOT NULL,
    space_id           text NOT NULL,
    tenant_id          bigint NOT NULL REFERENCES tenants(id),
    owner_principal_id bigint NOT NULL REFERENCES principals(id),
    default_account_id bigint NOT NULL REFERENCES accounts(id),
    disabled           boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject, space_id)
);

CREATE INDEX IF NOT EXISTS gateway_identities_owner
    ON gateway_identities (tenant_id, owner_principal_id)
    WHERE NOT disabled;
