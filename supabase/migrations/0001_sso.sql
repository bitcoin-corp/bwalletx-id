-- b*X single sign-on hub (id.bwalletx.com): challenges, authorization codes, hub sessions, session epochs.
--
-- Server-only tables. RLS is ON with NO policies, and anon/authenticated get no access at all, so nothing reaches them
-- through the Supabase REST API. The hub connects with a server-only URL (SSO_DATABASE_URL).
-- Codes and cookie tokens are stored only as SHA-256 hashes.
--
-- Run (owner):
--   ssh hetzner "docker exec -i supabase-db psql -U postgres -d postgres" < supabase/migrations/0001_sso.sql
--
-- Optional least privilege: create a login role for the hub yourself (choose the password in psql, never in git):
--   create role sso_hub login password '…';
-- then re-run this file (or just the grant block at the end) and use that role in SSO_DATABASE_URL.

begin;

create table if not exists public.sso_challenges (
  nonce         text        primary key,
  identity_key  text        not null default '',   -- '' = keyless challenge (one wallet sheet); bound at verify
  origin        text        not null,
  message       text        not null,
  expires_at    timestamptz not null
);
create index if not exists sso_challenges_expires_idx on public.sso_challenges (expires_at);

create table if not exists public.sso_codes (
  code_hash       text        primary key,          -- sha256(code), base64url
  client_id       text        not null,
  redirect_uri    text        not null,
  code_challenge  text        not null,             -- PKCE S256
  sid             text        not null,
  identity_key    text        not null,
  expires_at      timestamptz not null              -- 60 s
);
create index if not exists sso_codes_expires_idx on public.sso_codes (expires_at);

create table if not exists public.sso_sessions (
  sid           text        primary key,
  token_hash    text        not null unique,        -- sha256(cookie token), rotates daily
  identity_key  text        not null,
  paymail       text,
  handle        text,
  epoch         bigint      not null,
  auth_time     timestamptz not null,
  created_at    timestamptz not null default now(),
  rotated_at    timestamptz not null default now(),
  expires_at    timestamptz not null                -- 30 days, sliding
);
create index if not exists sso_sessions_identity_idx on public.sso_sessions (identity_key);
create index if not exists sso_sessions_expires_idx on public.sso_sessions (expires_at);

create table if not exists public.sso_epochs (
  identity_key  text        primary key,
  epoch         bigint      not null default 0,     -- bumped by "Sign out of all b*X sites"
  updated_at    timestamptz not null default now()
);

alter table public.sso_challenges enable row level security;
alter table public.sso_codes      enable row level security;
alter table public.sso_sessions   enable row level security;
alter table public.sso_epochs     enable row level security;

revoke all on table public.sso_challenges, public.sso_codes, public.sso_sessions, public.sso_epochs from public;

do $$
declare r text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on table public.sso_challenges, public.sso_codes, public.sso_sessions, public.sso_epochs from %I', r);
    end if;
  end loop;
  -- The hub's own role, if the owner created one: these four tables only. RLS stays on; a policy lets this role (and
  -- no other) through. Supabase's postgres / service_role bypass RLS anyway.
  if exists (select 1 from pg_roles where rolname = 'sso_hub') then
    execute 'grant select, insert, update, delete on table public.sso_challenges, public.sso_codes, public.sso_sessions, public.sso_epochs to sso_hub';
    foreach r in array array['sso_challenges', 'sso_codes', 'sso_sessions', 'sso_epochs'] loop
      execute format('drop policy if exists sso_hub_all on public.%I', r);
      execute format('create policy sso_hub_all on public.%I for all to sso_hub using (true) with check (true)', r);
    end loop;
  end if;
end $$;

commit;
