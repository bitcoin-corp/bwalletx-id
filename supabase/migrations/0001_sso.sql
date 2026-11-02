-- b*X single sign-on hub (id.bwalletx.com): challenges, authorization codes, hub sessions, session epochs, rate limits.
--
-- Everything lives in its own schema, `sso`, which the Supabase REST API does not expose. RLS is ON for every table;
-- anon, authenticated and PUBLIC get no access at all. Codes and cookie tokens are stored only as SHA-256 hashes.
--
-- The hub connects as its own least-privilege role, `sso_hub` (REQUIRED). This file creates it NOLOGIN; it can touch
-- the five tables below and run sso.cleanup(), nothing else. SSO_DATABASE_URL must use sso_hub, never postgres
-- (a superuser bypasses RLS and can read every other table on the server). In production the hub refuses to start
-- as any other role.
--
-- Run (owner):
--   ssh hetzner "docker exec -i supabase-db psql -U postgres -d postgres" < supabase/migrations/0001_sso.sql
-- Then give the role a login and a password (choose it in psql; never put it in git or in shell history):
--   ssh -t hetzner "docker exec -it supabase-db psql -U postgres -d postgres"
--   postgres=# alter role sso_hub login;
--   postgres=# \password sso_hub
-- and set SSO_DATABASE_URL=postgres://sso_hub:<password>@<host>:<port>/postgres in the hub's Vercel env.
--
-- Expired rows: sso.cleanup() deletes them. If pg_cron is installed, this file schedules it every 15 minutes
-- (job "sso_cleanup"); otherwise the hub prunes as it goes, and the owner can run `select sso.cleanup();` by hand.
--
-- Re-running this file is safe (IF NOT EXISTS / CREATE OR REPLACE everywhere).

begin;

-- The hub's role. NOLOGIN until the owner sets a password (above).
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'sso_hub') then
    create role sso_hub nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls;
  end if;
end $$;

create schema if not exists sso;
revoke all on schema sso from public;

create table if not exists sso.challenges (
  nonce         text        primary key,
  identity_key  text        not null default '',   -- '' = keyless challenge (one wallet sheet); bound at verify
  origin        text        not null,
  message       text        not null,              -- "Sign in to id.bwalletx.com · challenge <nonce> · <ISO time>"
  expires_at    timestamptz not null               -- 2 minutes
);
create index if not exists challenges_expires_idx on sso.challenges (expires_at);

create table if not exists sso.codes (
  code_hash       text        primary key,          -- sha256(code), base64url
  client_id       text        not null,
  redirect_uri    text        not null,
  code_challenge  text        not null,             -- PKCE S256
  sid             text        not null,
  identity_key    text        not null,
  expires_at      timestamptz not null              -- 60 s
);
create index if not exists codes_expires_idx on sso.codes (expires_at);

create table if not exists sso.sessions (
  sid           text        primary key,
  token_hash    text        not null unique,        -- sha256(cookie token), rotates daily and on every fresh sign-in
  identity_key  text        not null,
  paymail       text,
  handle        text,
  epoch         bigint      not null,
  auth_time     timestamptz not null,               -- last wallet sign-in
  created_at    timestamptz not null default now(),
  rotated_at    timestamptz not null default now(),
  expires_at    timestamptz not null                -- 30 days, sliding
);
create index if not exists sessions_identity_created_idx on sso.sessions (identity_key, created_at desc);
create index if not exists sessions_expires_idx on sso.sessions (expires_at);

create table if not exists sso.epochs (
  identity_key  text        primary key,
  epoch         bigint      not null default 0,     -- bumped by "Sign out of all b*X sites"
  updated_at    timestamptz not null default now()
);

-- Fixed-window rate limits: one row per bucket ("verify:ip:<sha256(ip)>", "token:key:<identity key>"…) per window.
create table if not exists sso.rate_limits (
  bucket        text        not null,
  window_start  timestamptz not null,
  hits          integer     not null default 0,
  expires_at    timestamptz not null,
  primary key (bucket, window_start)
);
create index if not exists rate_limits_expires_idx on sso.rate_limits (expires_at);

-- Delete everything that has expired. Sessions are kept a day past expiry (a site may still ask /session/epoch).
create or replace function sso.cleanup() returns void
language sql
security invoker
set search_path = sso, pg_temp
as $$
  delete from sso.challenges  where expires_at < now();
  delete from sso.codes       where expires_at < now();
  delete from sso.sessions    where expires_at < now() - interval '1 day';
  delete from sso.rate_limits where expires_at < now();
$$;

alter table sso.challenges  enable row level security;
alter table sso.codes       enable row level security;
alter table sso.sessions    enable row level security;
alter table sso.epochs      enable row level security;
alter table sso.rate_limits enable row level security;

revoke all on all tables in schema sso from public;
revoke all on function sso.cleanup() from public;

-- Supabase's API roles get nothing (they don't exist on a plain Postgres, so check first).
do $$
declare r text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on schema sso from %I', r);
      execute format('revoke all on all tables in schema sso from %I', r);
      execute format('revoke all on function sso.cleanup() from %I', r);
    end if;
  end loop;
end $$;

-- sso_hub: these five tables and sso.cleanup() only. RLS stays on; a policy lets this role (and no other) through.
grant usage on schema sso to sso_hub;
grant select, insert, update, delete on table sso.challenges, sso.codes, sso.sessions, sso.epochs, sso.rate_limits to sso_hub;
grant execute on function sso.cleanup() to sso_hub;

do $$
declare t text;
begin
  foreach t in array array['challenges', 'codes', 'sessions', 'epochs', 'rate_limits'] loop
    execute format('drop policy if exists sso_hub_all on sso.%I', t);
    execute format('create policy sso_hub_all on sso.%I for all to sso_hub using (true) with check (true)', t);
  end loop;
end $$;

-- Every 15 minutes, if pg_cron is installed (it is available on the Hetzner Supabase but not enabled by default).
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    if exists (select 1 from cron.job where jobname = 'sso_cleanup') then
      perform cron.unschedule('sso_cleanup');
    end if;
    perform cron.schedule('sso_cleanup', '*/15 * * * *', 'select sso.cleanup()');
  end if;
end $$;

commit;
