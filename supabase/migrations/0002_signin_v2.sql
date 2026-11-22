-- Hub sign-in v2 (security review 22 Nov 2026, HIGH-1): pending sign-ins that the WALLET approves by POSTing straight
-- to the hub. Additive: nothing is dropped. sso.challenges (v1, page-delivered signatures) is no longer used by the hub;
-- it stays until a later cleanup migration.
--
-- Run after 0001 (owner):
--   ssh hetzner "docker exec -i supabase-db psql -U postgres -d postgres" < supabase/migrations/0002_signin_v2.sql
-- Re-running this file is safe.

begin;

create table if not exists sso.pending_signins (
  request_id    text        primary key,            -- public: in the wallet link
  browser_hash  text        not null unique,        -- sha256(the browser's __Host-bwx_signin cookie secret)
  user_code     text        not null unique,        -- BCDF-GHJK, shown on the page and in the wallet
  client_id     text,                               -- the site the sign-in continues to, or null
  authorize     text,                               -- the site's /authorize request as JSON (no prompt), re-checked when used
  message       text        not null,               -- the exact text the wallet signs
  status        text        not null default 'pending' check (status in ('pending', 'approved', 'used', 'failed')),
  identity_key  text,                               -- set when the wallet approves
  attempts      integer     not null default 0,     -- bad wallet attempts; 5 = failed
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null                -- 5 minutes
);
create index if not exists pending_signins_expires_idx on sso.pending_signins (expires_at);

alter table sso.pending_signins enable row level security;
revoke all on table sso.pending_signins from public;

do $$
declare r text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on table sso.pending_signins from %I', r);
    end if;
  end loop;
end $$;

grant select, insert, update, delete on table sso.pending_signins to sso_hub;
drop policy if exists sso_hub_all on sso.pending_signins;
create policy sso_hub_all on sso.pending_signins for all to sso_hub using (true) with check (true);

-- cleanup() now also clears expired pending sign-ins.
create or replace function sso.cleanup() returns void
language sql
security invoker
set search_path = sso, pg_temp
as $$
  delete from sso.challenges      where expires_at < now();
  delete from sso.pending_signins where expires_at < now();
  delete from sso.codes           where expires_at < now();
  delete from sso.sessions        where expires_at < now() - interval '1 day';
  delete from sso.rate_limits     where expires_at < now();
$$;
revoke all on function sso.cleanup() from public;
grant execute on function sso.cleanup() to sso_hub;

commit;
