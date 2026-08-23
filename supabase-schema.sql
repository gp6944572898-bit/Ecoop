-- v2: реляционная схема + защита прав доступа.
-- Выполни в Supabase → SQL Editor → New query → Run.
-- Если у тебя уже есть старая таблица app_state — её можно оставить
-- (не используется новой версией) или удалить: drop table if exists app_state;

create table if not exists projects (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text default '',
  created_by text not null,
  created_at timestamptz not null default now()
);

create table if not exists project_participants (
  project_id uuid not null references projects(id) on delete cascade,
  address text not null,
  joined_at timestamptz not null default now(),
  primary key (project_id, address)
);

create table if not exists tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text default '',
  reward numeric not null check (reward > 0),
  status text not null default 'open' check (status in ('open', 'submitted', 'approved')),
  created_at timestamptz not null default now()
);

-- submitted_at хранится как bigint (мс с эпохи) — а не timestamptz —
-- потому что это число участвует в подписи и хэше и должно совпадать
-- бит-в-бит с тем, что было подписано на устройстве пользователя.
create table if not exists submissions (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references tasks(id) on delete cascade,
  address text not null,
  text_body text not null,
  submitted_at bigint not null,
  signature text not null,
  is_active boolean not null default true
);

create table if not exists votes (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references tasks(id) on delete cascade,
  submission_id uuid not null references submissions(id) on delete cascade,
  address text not null,
  approve boolean not null,
  voted_at bigint not null,
  signature text not null,
  unique (submission_id, address)
);

create table if not exists chain_blocks (
  index integer primary key,
  timestamp bigint not null,
  previous_hash text not null,
  hash text not null,
  events jsonb not null default '[]'::jsonb
);

-- генезис-блок (детерминированный, timestamp=0, чтобы хэш был предсказуем)
insert into chain_blocks (index, timestamp, previous_hash, hash, events)
values (0, 0, repeat('0', 64), 'dacbd4e036cc29454b71f0cd02960a4f2d8357ad6bdcb8c74fd95d498c384a7', '[]'::jsonb)
on conflict (index) do nothing;

-- ---------- Row Level Security ----------

alter table projects enable row level security;
alter table project_participants enable row level security;
alter table tasks enable row level security;
alter table submissions enable row level security;
alter table votes enable row level security;
alter table chain_blocks enable row level security;

-- Читать может кто угодно — реестр публичный и прозрачный.
create policy "projects_select" on projects for select using (true);
create policy "participants_select" on project_participants for select using (true);
create policy "tasks_select" on tasks for select using (true);
create policy "submissions_select" on submissions for select using (true);
create policy "votes_select" on votes for select using (true);
create policy "chain_select" on chain_blocks for select using (true);

-- Создавать проекты, задачи и присоединяться к проекту — можно напрямую.
-- Подделка здесь не даёт украсть монеты, только "зашумляет" список.
create policy "projects_insert" on projects for insert with check (true);
create policy "participants_insert" on project_participants for insert with check (true);
create policy "tasks_insert" on tasks for insert with check (true);

-- А вот решения, голоса и блоки с наградами — НЕЛЬЗЯ писать напрямую.
-- Только через Edge Function с сервисным ключом (он обходит RLS и
-- проверяет ECDSA-подпись перед записью). Никаких insert/update-политик
-- для anon-роли на этих трёх таблицах намеренно нет — прямой путь закрыт.
