-- ============================================================
-- WORLD CUP 2026 OFFICE PREDICTIONS — SUPABASE SCHEMA
-- Run this entire file once in: Supabase Dashboard > SQL Editor
--
-- !!! BEFORE RUNNING: change the admin PIN on the line marked
-- !!! "CHANGE ME" near the bottom of this file.
-- ============================================================

-- ------------------------------------------------------------
-- 1. TABLES
-- ------------------------------------------------------------

-- One row per colleague's bracket.
-- "token" is the secret that lets its owner edit it. It is never
-- exposed to other players (column-level grant below).
create table if not exists entries (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(trim(name)) between 1 and 40),
  token       uuid not null default gen_random_uuid(),
  predictions jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Singleton row holding real tournament results, same JSON shape
-- as predictions: { groups: {A:[...4 ids], ...}, thirds: [...8 letters], ko: {"73": teamId, ...} }
create table if not exists results (
  id         int primary key default 1 check (id = 1),
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- Singleton row for app settings.
create table if not exists settings (
  id       int primary key default 1 check (id = 1),
  locked   boolean not null default false,
  deadline timestamptz not null default '2026-06-11 19:00:00+00' -- first kickoff
);

-- Private admin secret. No grants to anon at all.
create table if not exists admin_secret (
  id  int primary key default 1 check (id = 1),
  pin text not null
);

insert into results  (id, data) values (1, '{}') on conflict do nothing;
insert into settings (id)       values (1)       on conflict do nothing;

-- ------------------------------------------------------------
-- 2. ROW LEVEL SECURITY + COLUMN-LEVEL GRANTS
-- ------------------------------------------------------------

alter table entries      enable row level security;
alter table results      enable row level security;
alter table settings     enable row level security;
alter table admin_secret enable row level security;

-- Everyone may READ entries, results, settings (read-only app data).
create policy "read entries"  on entries  for select using (true);
create policy "read results"  on results  for select using (true);
create policy "read settings" on settings for select using (true);
-- No policy on admin_secret = nobody can read it via the API. Good.

-- Strip default table-wide grants, then re-grant only safe columns.
revoke all on entries      from anon, authenticated;
revoke all on results      from anon, authenticated;
revoke all on settings     from anon, authenticated;
revoke all on admin_secret from anon, authenticated;

grant select (id, name, predictions, created_at, updated_at)
  on entries to anon, authenticated;          -- note: token NOT granted
grant select on results  to anon, authenticated;
grant select on settings to anon, authenticated;

-- All writes go through the SECURITY DEFINER functions below.
-- No insert/update/delete grants on any table to anon.

-- ------------------------------------------------------------
-- 3. HELPER: is the game locked?
-- ------------------------------------------------------------
create or replace function game_locked() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(
    (select locked or now() > deadline from settings where id = 1),
    true);
$$;

-- ------------------------------------------------------------
-- 4. PLAYER FUNCTIONS (called by the app with the anon key)
-- ------------------------------------------------------------

-- Create a bracket. Returns the id + secret token.
-- The app stores the token in the player's localStorage.
create or replace function create_entry(p_name text)
returns table (entry_id uuid, entry_token uuid)
language plpgsql security definer set search_path = public as $$
begin
  if game_locked() then
    raise exception 'Predictions are locked.';
  end if;
  if (select count(*) from entries) >= 200 then
    raise exception 'Entry limit reached.';
  end if;
  return query
    insert into entries (name) values (trim(p_name))
    returning id, token;
end;
$$;

-- Save predictions. Requires the secret token.
create or replace function save_entry(p_id uuid, p_token uuid, p_predictions jsonb)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if game_locked() then
    raise exception 'Predictions are locked.';
  end if;
  if pg_column_size(p_predictions) > 50000 then
    raise exception 'Payload too large.';
  end if;
  update entries
     set predictions = p_predictions, updated_at = now()
   where id = p_id and token = p_token;
  if not found then
    raise exception 'Bracket not found or wrong token.';
  end if;
end;
$$;

-- Rename a bracket (same token rule).
create or replace function rename_entry(p_id uuid, p_token uuid, p_name text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if game_locked() then
    raise exception 'Predictions are locked.';
  end if;
  update entries set name = trim(p_name), updated_at = now()
   where id = p_id and token = p_token;
  if not found then
    raise exception 'Bracket not found or wrong token.';
  end if;
end;
$$;

-- ------------------------------------------------------------
-- 5. ADMIN FUNCTIONS (PIN checked server-side)
-- ------------------------------------------------------------

create or replace function check_pin(p_pin text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from admin_secret where id = 1 and pin = p_pin);
$$;

create or replace function admin_save_results(p_pin text, p_data jsonb)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not check_pin(p_pin) then raise exception 'Wrong PIN.'; end if;
  update results set data = p_data, updated_at = now() where id = 1;
end;
$$;

create or replace function admin_set_lock(p_pin text, p_locked boolean)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not check_pin(p_pin) then raise exception 'Wrong PIN.'; end if;
  update settings set locked = p_locked where id = 1;
end;
$$;

create or replace function admin_delete_entry(p_pin text, p_id uuid)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not check_pin(p_pin) then raise exception 'Wrong PIN.'; end if;
  delete from entries where id = p_id;
end;
$$;

-- Allow anon to call the functions (logic inside enforces rules).
grant execute on function create_entry(text)                    to anon, authenticated;
grant execute on function save_entry(uuid, uuid, jsonb)         to anon, authenticated;
grant execute on function rename_entry(uuid, uuid, text)        to anon, authenticated;
grant execute on function check_pin(text)                       to anon, authenticated;
grant execute on function admin_save_results(text, jsonb)       to anon, authenticated;
grant execute on function admin_set_lock(text, boolean)         to anon, authenticated;
grant execute on function admin_delete_entry(text, uuid)        to anon, authenticated;
revoke execute on function game_locked() from anon, authenticated;

-- ------------------------------------------------------------
-- 6. ADMIN PIN  >>> CHANGE ME <<<
-- ------------------------------------------------------------
insert into admin_secret (id, pin) values (1, 'CHANGE-THIS-PIN')
  on conflict (id) do update set pin = excluded.pin;
