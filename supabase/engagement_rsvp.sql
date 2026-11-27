-- Engagement RSVP for sweekruti-siddhanth-engagement.vercel.app
-- Lives in the wedding_management Supabase project, kept apart from the wedding tables.
--
-- Guests never read or write the tables directly: RLS is on with no policies, and the
-- anon role can only call two functions:
--   submit_engagement_rsvp  – save or update one reply (one per phone number)
--   engagement_rsvp_list    – the couple's list of replies, behind a password

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.engagement_rsvps (
  id            uuid primary key default gen_random_uuid(),
  phone         text not null unique,
  full_name     text not null check (char_length(full_name) between 2 and 80),
  attending     boolean not null,
  guest_count   int not null check (guest_count between 0 and 10),
  dietary       text not null default 'none'
                check (dietary in ('none', 'veg', 'jain', 'no-onion-garlic', 'other')),
  dietary_notes text check (char_length(dietary_notes) <= 200),
  message       text check (char_length(message) <= 500),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists public.engagement_rsvp_settings (
  id            int primary key default 1 check (id = 1),
  respond_by    date not null,
  password_hash text not null
);

alter table public.engagement_rsvps enable row level security;
alter table public.engagement_rsvp_settings enable row level security;
revoke all on public.engagement_rsvps, public.engagement_rsvp_settings from anon, authenticated;

-- Save a reply. Replying again with the same phone number updates the earlier reply.
create or replace function public.submit_engagement_rsvp(
  p_full_name text, p_phone text, p_attending boolean, p_guest_count int,
  p_dietary text default 'none', p_dietary_notes text default null, p_message text default null
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_phone text := regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g');
  v_name  text := btrim(coalesce(p_full_name, ''));
  v_by    date;
  v_new   boolean;
begin
  select respond_by into v_by from engagement_rsvp_settings where id = 1;
  if v_by is not null and (now() at time zone 'Asia/Kolkata')::date > v_by then
    raise exception 'RSVP_CLOSED' using errcode = 'P0001';
  end if;
  -- Indian numbers: keep the last 10 digits so +91 / 0 prefixes match the same reply
  if char_length(v_phone) > 10 and (v_phone like '91%' or v_phone like '0%') then
    v_phone := right(v_phone, 10);
  end if;
  if char_length(v_phone) < 10 or char_length(v_phone) > 15 then
    raise exception 'BAD_PHONE' using errcode = 'P0001';
  end if;
  if char_length(v_name) < 2 or char_length(v_name) > 80 then
    raise exception 'BAD_NAME' using errcode = 'P0001';
  end if;
  if p_attending is null then
    raise exception 'BAD_ATTENDING' using errcode = 'P0001';
  end if;
  if p_attending and (p_guest_count is null or p_guest_count < 1 or p_guest_count > 10) then
    raise exception 'BAD_GUESTS' using errcode = 'P0001';
  end if;

  insert into engagement_rsvps as r (phone, full_name, attending, guest_count, dietary, dietary_notes, message)
  values (
    v_phone, v_name, p_attending,
    case when p_attending then p_guest_count else 0 end,
    case when p_attending and p_dietary in ('veg','jain','no-onion-garlic','other') then p_dietary else 'none' end,
    nullif(btrim(left(coalesce(p_dietary_notes, ''), 200)), ''),
    nullif(btrim(left(coalesce(p_message, ''), 500)), '')
  )
  on conflict (phone) do update set
    full_name = excluded.full_name, attending = excluded.attending, guest_count = excluded.guest_count,
    dietary = excluded.dietary, dietary_notes = excluded.dietary_notes, message = excluded.message,
    updated_at = now()
  returning (xmax = 0) into v_new;

  return json_build_object('ok', true, 'updated', not v_new);
end $$;

-- The couple's view of every reply, with totals. Needs the password set in engagement_rsvp_settings.
create or replace function public.engagement_rsvp_list(p_password text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_hash text;
begin
  select password_hash into v_hash from engagement_rsvp_settings where id = 1;
  if v_hash is null or p_password is null or crypt(p_password, v_hash) <> v_hash then
    perform pg_sleep(1);  -- slow down guessing
    raise exception 'BAD_PASSWORD' using errcode = 'P0001';
  end if;
  return json_build_object(
    'respond_by', (select respond_by from engagement_rsvp_settings where id = 1),
    'totals', (select json_build_object(
        'replies',   count(*),
        'attending', count(*) filter (where attending),
        'declined',  count(*) filter (where not attending),
        'guests',    coalesce(sum(guest_count) filter (where attending), 0))
      from engagement_rsvps),
    'replies', coalesce((select json_agg(json_build_object(
        'name', full_name, 'phone', phone, 'attending', attending, 'guests', guest_count,
        'dietary', dietary, 'dietary_notes', dietary_notes, 'message', message,
        'created_at', created_at, 'updated_at', updated_at) order by updated_at desc)
      from engagement_rsvps), '[]'::json)
  );
end $$;

revoke all on function public.submit_engagement_rsvp(text, text, boolean, int, text, text, text) from public;
revoke all on function public.engagement_rsvp_list(text) from public;
grant execute on function public.submit_engagement_rsvp(text, text, boolean, int, text, text, text) to anon, authenticated;
grant execute on function public.engagement_rsvp_list(text) to anon, authenticated;

-- Settings row (respond-by date and the replies-page password) is added separately,
-- so the password never goes into this file:
--   insert into engagement_rsvp_settings (id, respond_by, password_hash)
--   values (1, '2026-12-03', crypt('<password>', gen_salt('bf')));

-- 2026-11-25: food preference is now only Veg or Non-veg, and required when attending.
-- Applied as migration "engagement_rsvp_veg_nonveg": the dietary check became
--   check (dietary in ('none', 'veg', 'non-veg'))
-- and submit_engagement_rsvp raises BAD_DIET unless an attending guest picks 'veg' or 'non-veg'
-- (dietary_notes is no longer filled in).

-- 2026-11-26: no reply deadline. Migration "engagement_rsvp_no_deadline" made respond_by nullable
-- and set it to null, so submit_engagement_rsvp never closes. Set a date again to close replies.

-- 2026-11-27: engagement enhancements
--  * engagement_rsvps_backup_20261127: a copy of the replies taken before these changes
--    (RLS on, no grants, so it is not readable through the API).
--  * normalize_engagement_phone(text): Indian numbers (10 digits, +91, 91, 0 or 091 prefix) are stored
--    as 10 digits exactly as before; other countries as +<country code><number>; anything else is rejected.
--  * submit_engagement_rsvp now uses normalize_engagement_phone (same signature, same behaviour for India).
--  * engagement_rsvp_info(): public, read-only { respond_by, closed, max_guests } for the form.
--    To set a deadline:   update public.engagement_rsvp_settings set respond_by = '2026-12-03' where id = 1;
--    To remove it again:  update public.engagement_rsvp_settings set respond_by = null where id = 1;
