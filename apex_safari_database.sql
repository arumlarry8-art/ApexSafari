-- ================================================================
-- APEX SAFARI — SUPABASE DATABASE SCHEMA
-- Run this entire file in Supabase SQL Editor
-- supabase.com → Your Project → SQL Editor → New Query → Paste → Run
-- ================================================================

-- ── ENABLE EXTENSIONS ──────────────────────────────────────────
create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";

-- ── HUNTERS TABLE ───────────────────────────────────────────────
-- Stores all hunter profiles (links to Supabase auth.users)
create table if not exists public.hunters (
  id            uuid references auth.users(id) on delete cascade primary key,
  username      text unique not null,
  email         text unique not null,
  country       text default 'Unknown',
  level         text default 'beginner' check (level in ('beginner','intermediate','advanced','elite')),
  role          text default 'hunter' check (role in ('hunter','admin')),
  certified     boolean default false,
  rank          integer default 9999,
  earnings      numeric(12,2) default 0,
  bugs_found    integer default 0,
  test_passed   boolean default false,
  test_score    integer default 0,
  test_attempts integer default 0,
  subscription  text default 'free' check (subscription in ('free','pro','enterprise')),
  banned        boolean default false,
  ban_reason    text,
  created_at    timestamptz default now(),
  last_seen     timestamptz default now()
);

-- ── BOUNTIES TABLE ──────────────────────────────────────────────
-- Tracks every bounty a hunter reports
create table if not exists public.bounties (
  id              uuid default uuid_generate_v4() primary key,
  hunter_id       uuid references public.hunters(id) on delete cascade,
  program_name    text not null,
  platform        text not null,
  amount_usd      numeric(10,2) not null,
  platform_fee    numeric(10,2) not null,
  hunter_keeps    numeric(10,2) not null,
  payment_method  text check (payment_method in ('mpesa','paypal')),
  payment_proof   text,  -- URL to uploaded screenshot in Supabase Storage
  fee_proof       text,  -- URL to fee payment screenshot
  status          text default 'pending' check (status in ('pending','verified','rejected')),
  verified_by     uuid references public.hunters(id),
  verified_at     timestamptz,
  notes           text,
  created_at      timestamptz default now()
);

-- ── TEST ATTEMPTS TABLE ─────────────────────────────────────────
-- Stores every entry test attempt with full details
create table if not exists public.test_attempts (
  id           uuid default uuid_generate_v4() primary key,
  hunter_id    uuid references public.hunters(id) on delete cascade,
  attempt_num  integer not null,
  total_score  integer default 0,
  max_score    integer default 16,
  passed       boolean default false,
  answers      jsonb default '[]', -- array of {step, question, answer, score, verdict}
  started_at   timestamptz default now(),
  completed_at timestamptz
);

-- ── SCOPE ANALYSES TABLE ────────────────────────────────────────
-- Saves every scope analysis a hunter runs
create table if not exists public.scope_analyses (
  id           uuid default uuid_generate_v4() primary key,
  hunter_id    uuid references public.hunters(id) on delete cascade,
  program_name text,
  platform     text,
  analysis     text not null,
  screenshot_count integer default 0,
  created_at   timestamptz default now()
);

-- ── COMMUNITY POSTS TABLE ───────────────────────────────────────
create table if not exists public.posts (
  id         uuid default uuid_generate_v4() primary key,
  hunter_id  uuid references public.hunters(id) on delete cascade,
  content    text not null,
  category   text default 'General',
  likes      integer default 0,
  pinned     boolean default false,
  created_at timestamptz default now()
);

-- ── TEAMS TABLE ─────────────────────────────────────────────────
create table if not exists public.teams (
  id          uuid default uuid_generate_v4() primary key,
  name        text unique not null,
  leader_id   uuid references public.hunters(id),
  description text,
  earnings    numeric(12,2) default 0,
  created_at  timestamptz default now()
);

create table if not exists public.team_members (
  team_id    uuid references public.teams(id) on delete cascade,
  hunter_id  uuid references public.hunters(id) on delete cascade,
  split_pct  numeric(5,2) default 0,
  joined_at  timestamptz default now(),
  primary key (team_id, hunter_id)
);

-- ── SECURITY EVENTS TABLE ───────────────────────────────────────
-- Logs all security events for admin review
create table if not exists public.security_events (
  id         uuid default uuid_generate_v4() primary key,
  event_type text not null,
  severity   text check (severity in ('info','warning','critical','success')),
  ip_address text,
  user_agent text,
  hunter_id  uuid references public.hunters(id),
  details    text,
  created_at timestamptz default now()
);

-- ── ANNOUNCEMENTS TABLE ─────────────────────────────────────────
create table if not exists public.announcements (
  id         uuid default uuid_generate_v4() primary key,
  title      text not null,
  content    text not null,
  type       text default 'update' check (type in ('update','congrats','warning','event')),
  created_by uuid references public.hunters(id),
  created_at timestamptz default now()
);

-- ── HALL OF FAME TABLE ──────────────────────────────────────────
create table if not exists public.hall_of_fame (
  id          uuid default uuid_generate_v4() primary key,
  hunter_id   uuid references public.hunters(id),
  finding     text not null,
  bounty_usd  numeric(10,2) not null,
  category    text not null,
  featured_by uuid references public.hunters(id),
  created_at  timestamptz default now()
);

-- ================================================================
-- ROW LEVEL SECURITY (RLS)
-- Protects data — users can only see what they should see
-- ================================================================

alter table public.hunters          enable row level security;
alter table public.bounties         enable row level security;
alter table public.test_attempts    enable row level security;
alter table public.scope_analyses   enable row level security;
alter table public.posts            enable row level security;
alter table public.teams            enable row level security;
alter table public.team_members     enable row level security;
alter table public.security_events  enable row level security;
alter table public.announcements    enable row level security;
alter table public.hall_of_fame     enable row level security;

-- Hunters: can read all profiles, edit only their own
create policy "hunters_read_all"   on public.hunters for select using (true);
create policy "hunters_update_own" on public.hunters for update using (auth.uid() = id);
create policy "hunters_insert_own" on public.hunters for insert with check (auth.uid() = id);

-- Bounties: hunters see own, admins see all
create policy "bounties_own"  on public.bounties for select using (
  hunter_id = auth.uid() or
  exists (select 1 from public.hunters where id = auth.uid() and role = 'admin')
);
create policy "bounties_insert" on public.bounties for insert with check (hunter_id = auth.uid());

-- Test attempts: hunters see own only
create policy "tests_own" on public.test_attempts for select using (hunter_id = auth.uid());
create policy "tests_insert" on public.test_attempts for insert with check (hunter_id = auth.uid());

-- Scope analyses: hunters see own only
create policy "scope_own"    on public.scope_analyses for select using (hunter_id = auth.uid());
create policy "scope_insert" on public.scope_analyses for insert with check (hunter_id = auth.uid());

-- Posts: everyone can read, only owner can edit
create policy "posts_read_all" on public.posts for select using (true);
create policy "posts_insert"   on public.posts for insert with check (hunter_id = auth.uid());

-- Security events: admins only
create policy "security_admin_only" on public.security_events for select using (
  exists (select 1 from public.hunters where id = auth.uid() and role = 'admin')
);
create policy "security_insert" on public.security_events for insert with check (true);

-- Announcements: everyone reads, admins write
create policy "announce_read"  on public.announcements for select using (true);
create policy "announce_write" on public.announcements for insert with check (
  exists (select 1 from public.hunters where id = auth.uid() and role = 'admin')
);

-- Hall of fame: everyone reads, admins write
create policy "hof_read"  on public.hall_of_fame for select using (true);
create policy "hof_write" on public.hall_of_fame for insert with check (
  exists (select 1 from public.hunters where id = auth.uid() and role = 'admin')
);

-- Teams: everyone reads
create policy "teams_read" on public.teams for select using (true);
create policy "teams_insert" on public.teams for insert with check (leader_id = auth.uid());

-- ================================================================
-- FUNCTIONS & TRIGGERS
-- Auto-updates that keep data consistent
-- ================================================================

-- Auto-create hunter profile when user signs up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
begin
  insert into public.hunters (id, username, email, country, level, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)),
    new.email,
    coalesce(new.raw_user_meta_data->>'country', 'Unknown'),
    coalesce(new.raw_user_meta_data->>'level', 'beginner'),
    coalesce(new.raw_user_meta_data->>'role', 'hunter')
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Auto-update hunter earnings and rank after bounty verified
create or replace function public.update_hunter_earnings()
returns trigger language plpgsql as $$
begin
  if new.status = 'verified' and old.status != 'verified' then
    update public.hunters
    set
      earnings   = earnings + new.hunter_keeps,
      bugs_found = bugs_found + 1,
      last_seen  = now()
    where id = new.hunter_id;
  end if;
  return new;
end;
$$;

create trigger on_bounty_verified
  after update on public.bounties
  for each row execute procedure public.update_hunter_earnings();

-- Auto-update rank after earnings change (simple ranking)
create or replace function public.refresh_rankings()
returns trigger language plpgsql as $$
begin
  update public.hunters h
  set rank = r.rank
  from (
    select id, row_number() over (order by earnings desc, bugs_found desc) as rank
    from public.hunters
    where role = 'hunter' and banned = false
  ) r
  where h.id = r.id;
  return new;
end;
$$;

create trigger on_earnings_change
  after update of earnings on public.hunters
  for each row execute procedure public.refresh_rankings();

-- Auto-update test stats after attempt
create or replace function public.update_test_stats()
returns trigger language plpgsql as $$
begin
  if new.completed_at is not null then
    update public.hunters
    set
      test_attempts = test_attempts + 1,
      test_passed   = new.passed,
      test_score    = new.total_score,
      certified     = new.passed
    where id = new.hunter_id;
  end if;
  return new;
end;
$$;

create trigger on_test_completed
  after update of completed_at on public.test_attempts
  for each row execute procedure public.update_test_stats();

-- Log last seen on any activity
create or replace function public.update_last_seen()
returns trigger language plpgsql as $$
begin
  update public.hunters set last_seen = now() where id = new.hunter_id;
  return new;
end;
$$;

create trigger on_bounty_activity after insert on public.bounties
  for each row execute procedure public.update_last_seen();
create trigger on_post_activity after insert on public.posts
  for each row execute procedure public.update_last_seen();

-- ================================================================
-- SEED DATA — Initial platform data
-- ================================================================

-- Insert platform announcements
insert into public.announcements (title, content, type) values
  ('Welcome to Apex Safari', 'The world''s most elite bug bounty intelligence platform is now live. Only the best hunters reach the Apex.', 'update'),
  ('Safari Intelligence', 'Apex Safari is powered by Safari Intelligence — the global AI cybersecurity ecosystem.', 'update');

-- ================================================================
-- STORAGE BUCKETS
-- For payment screenshots and profile photos
-- Run in Supabase Dashboard → Storage → Create bucket
-- ================================================================
-- Bucket: "payment-proofs"   → Private (hunters upload, admin reads)
-- Bucket: "scope-screenshots" → Private (hunters upload, own read)
-- Bucket: "avatars"           → Public (profile photos)

-- ================================================================
-- ADMIN SETUP INSTRUCTIONS
-- ================================================================
-- After running this SQL:
-- 1. Go to Authentication → Users → Invite User
-- 2. Enter: cybersafari54@gmail.com
-- 3. After Larry signs up, run this to make him admin:
--    UPDATE public.hunters SET role = 'admin' WHERE email = 'cybersafari54@gmail.com';
-- 4. Enable MFA: Authentication → MFA → Enable TOTP
-- ================================================================

select 'Apex Safari database setup complete! 🦁' as status;
