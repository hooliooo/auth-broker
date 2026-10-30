-- The registry's installations and their keys; app kinds stay in reviewed files.
--
-- Writers serialize on registry_head: each write transaction first takes the next version
-- there, holding the row until it commits, and stamps every row it writes with that version.
-- Versions therefore become visible in order, and a reader that has seen version N has seen
-- every write up to N. Rows are never deleted: a removed installation or a revoked key keeps its
-- row, with a new version, so readers following the versions see the removal.
create table if not exists registry_head (
    singleton boolean primary key default true check (singleton),
    version bigint not null
);
insert into registry_head (singleton, version) values (true, 0) on conflict do nothing;

create table if not exists installations (
    -- A DNS label, never reused: it is also the installation's Keycloak organization alias.
    id text primary key check (id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    kind text not null,
    tenant text not null,
    enabled boolean not null,
    -- A web-app installation's origin, and the hosts its kind's edge knows it by: with its
    -- port, and without it when the port is the scheme's default. Null for a native one.
    origin text,
    host text,
    bare_host text,
    api_url text,
    login_per_minute bigint check (login_per_minute > 0),
    removed boolean not null default false,
    version bigint not null,
    check ((origin is null) = (host is null)),
    check (bare_host is null or host is not null)
);
-- The rules a file registry checks as a whole, here checked on every write.
create unique index if not exists installations_origin
    on installations (origin) where not removed;
create unique index if not exists installations_host
    on installations (kind, host) where not removed;
create unique index if not exists installations_bare_host
    on installations (kind, bare_host) where not removed;
create index if not exists installations_version on installations (version);
create index if not exists installations_kind_version on installations (kind, version);

create table if not exists installation_keys (
    -- The first 16 characters of the base64url SHA-256 of the key, as requests name it.
    key_id text primary key,
    -- Unique for ever, revoked or not: a retired key never comes back.
    public_key bytea not null unique check (length(public_key) = 32),
    installation_id text not null references installations (id),
    revoked boolean not null default false,
    version bigint not null
);
-- Who enrolled the key: provisioning:<client>, key:<key id> for another of the installation's
-- keys, user:<subject> for an installation admin, or import.
alter table installation_keys add column if not exists enrolled_by text;
create index if not exists installation_keys_installation
    on installation_keys (installation_id) where not revoked;
create index if not exists installation_keys_version on installation_keys (version);

-- What the organization sync may read, if its role exists: nothing it could change.
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'organization_sync') then
        grant select on registry_head, installations to organization_sync;
    end if;
end
$$;
