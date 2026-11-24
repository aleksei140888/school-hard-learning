-- Idempotent: applied on every server start.

create table if not exists teachers (
  id         bigserial primary key,
  login      text not null unique,
  pass_hash  text not null,
  last       text not null,
  first      text not null,
  about      text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists classes (
  id   bigserial primary key,
  name text not null
);
create unique index if not exists classes_name on classes (lower(name));

create table if not exists students (
  id         bigserial primary key,
  class_id   bigint not null references classes on delete cascade,
  last       text not null,
  first      text not null,
  login      text not null unique,
  pin_hash   text not null,
  created_at timestamptz not null default now()
);

-- class_id or date empty = draft, students do not see it.
create table if not exists lessons (
  id         bigserial primary key,
  class_id   bigint references classes on delete set null,
  teacher_id bigint references teachers on delete set null,
  topic      text not null,
  date       date,
  video_url  text not null default '',
  material   jsonb not null default '[]',
  tasks      jsonb not null default '{}',
  created_at timestamptz not null default now()
);

-- topic is copied so an answer stays readable after its lesson is deleted.
create table if not exists answers (
  id         bigserial primary key,
  student_id bigint not null references students on delete cascade,
  lesson_id  bigint references lessons on delete set null,
  topic      text not null,
  kind       text not null check (kind in ('text', 'pc', 'phone')),
  text       text not null,
  file_key   text,
  file_name  text,
  created_at timestamptz not null default now()
);

create table if not exists comments (
  id         bigserial primary key,
  student_id bigint not null references students on delete cascade,
  lesson_id  bigint not null references lessons on delete cascade,
  author     text not null check (author in ('student', 'teacher')),
  text       text not null,
  created_at timestamptz not null default now()
);

create table if not exists grades (
  student_id bigint not null references students on delete cascade,
  lesson_id  bigint not null references lessons on delete cascade,
  value      smallint not null check (value between 1 and 12),
  updated_at timestamptz not null default now(),
  primary key (student_id, lesson_id)
);

create index if not exists answers_student on answers (student_id);
create index if not exists answers_lesson on answers (lesson_id);
create index if not exists comments_thread on comments (student_id, lesson_id);
create index if not exists lessons_class_date on lessons (class_id, date);
