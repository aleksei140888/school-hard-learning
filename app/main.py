import hashlib
import hmac
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import quote
from zoneinfo import ZoneInfo

import anthropic
import boto3
from botocore.config import Config
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from psycopg import errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).parent.parent
SETUP_CODE = os.environ.get("SETUP_CODE", "")
MAX_FILE = 20 * 1024 * 1024
FILE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".mp4", ".mov", ".webm",
            ".pdf", ".txt", ".csv", ".md", ".json"}
KINDS = {"text", "pc", "phone"}
AI_DAILY_LIMIT = 50
LOGIN_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alikes: i l o 0 1
TS = "(extract(epoch from {}created_at) * 1000)::bigint as ts"

pool = ConnectionPool(os.environ["DATABASE_URL"], open=False, min_size=1, max_size=5,
                      kwargs={"row_factory": dict_row})

BUCKET = os.environ.get("S3_BUCKET", "")
s3 = boto3.client(
    "s3",
    endpoint_url=os.environ["S3_ENDPOINT"],
    region_name=os.environ.get("S3_REGION", "us-east-1"),
    aws_access_key_id=os.environ["S3_KEY"],
    aws_secret_access_key=os.environ["S3_SECRET"],
    # checksum options: newer boto3 defaults break some S3-compatible stores
    config=Config(signature_version="s3v4", request_checksum_calculation="when_required",
                  response_checksum_validation="when_required"),
) if BUCKET else None

ai = anthropic.Anthropic(timeout=120) if os.environ.get("ANTHROPIC_API_KEY") else None


# ---------- db ----------

def q(sql, *a):
    with pool.connection() as c:
        return c.execute(sql, a or None).fetchall()


def q1(sql, *a):
    with pool.connection() as c:
        return c.execute(sql, a or None).fetchone()


def run(sql, *a):
    with pool.connection() as c:
        return c.execute(sql, a or None).rowcount


def today() -> date:
    return datetime.now(ZoneInfo("Europe/Kyiv")).date()


def clean(s: str) -> str:
    return " ".join(s.split())


def class_id(name: str) -> int:
    name = clean(name)
    row = q1("select id from classes where lower(name) = lower(%s)", name)
    return row["id"] if row else q1("insert into classes (name) values (%s) returning id", name)["id"]


# ---------- secrets ----------

def hash_secret(s: str) -> str:
    salt = secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.scrypt(s.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def check_secret(s: str, stored: str) -> bool:
    salt, h = stored.split(":")
    got = hashlib.scrypt(s.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
    return hmac.compare_digest(got, h)


DUMMY_HASH = hash_secret(secrets.token_hex(8))

# ponytail: in-memory and per login only. One Render instance, so it holds;
# move to a table (and add per-IP limits) when running more than one instance.
fails: dict[str, list[float]] = {}


def throttle(key: str):
    now = time.time()
    recent = [t for t in fails.get(key, []) if now - t < 900]
    if len(recent) >= 5:
        raise HTTPException(429, "Забагато невдалих спроб. Спробуй за 15 хвилин.")
    return recent


def record_fail(key: str, recent: list[float]):
    if len(fails) > 10000:
        fails.clear()
    fails[key] = recent + [time.time()]


# ---------- app ----------

@asynccontextmanager
async def lifespan(app):
    pool.open()
    # ponytail: schema.sql is idempotent and applied on every start;
    # switch to a migration tool once a column has to change on live data.
    with pool.connection() as c:
        c.execute((ROOT / "schema.sql").read_text())
    yield
    pool.close()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def limit_body(request: Request, call_next):
    # ponytail: trusts Content-Length; a chunked upload without it is not capped here.
    n = request.headers.get("content-length", "0")
    if not n.isdigit() or int(n) > MAX_FILE + 1_000_000:
        return JSONResponse({"detail": "Файл більший за 20 МБ."}, 413)
    return await call_next(request)


app.add_middleware(SessionMiddleware, secret_key=os.environ["SECRET_KEY"], max_age=30 * 86400,
                   same_site="lax", https_only=bool(os.environ.get("RENDER")))


@app.exception_handler(errors.UniqueViolation)
async def on_unique(request, exc):
    return JSONResponse({"detail": "Такий логін уже зайнятий."}, 409)


@app.exception_handler(errors.ForeignKeyViolation)
async def on_fk(request, exc):
    return JSONResponse({"detail": "Не знайдено."}, 404)


def user(request: Request) -> dict:
    s = request.session
    role, u = s.get("role"), None
    if role == "teacher":
        u = q1("select id, login, last, first, about, pass_hash as h from teachers where id = %s", s.get("id"))
    elif role == "student":
        u = q1(f"""select s.id, s.last, s.first, s.class_id, c.name as cls, s.pin_hash as h, {TS.format('s.')}
                   from students s join classes c on c.id = s.class_id where s.id = %s""", s.get("id"))
    # "v" ties the session to the current password/PIN: a reset logs old sessions out
    if not u or u.pop("h")[:8] != s.get("v"):
        s.clear()
        raise HTTPException(401, {"setup": not q1("select 1 as x from teachers limit 1")})
    return {**u, "role": role}


def teacher(u: dict = Depends(user)) -> dict:
    if u["role"] != "teacher":
        raise HTTPException(403, "Лише для вчителя.")
    return u


def student(u: dict = Depends(user)) -> dict:
    if u["role"] != "student":
        raise HTTPException(403, "Лише для учня.")
    return u


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/api/health")
def health():
    q1("select 1 as x")
    return {"ok": True}


# ---------- auth ----------

class LoginIn(BaseModel):
    role: Literal["teacher", "student"]
    login: str = Field(max_length=64)
    password: str = Field(max_length=128)


@app.post("/api/login")
def login(body: LoginIn, request: Request):
    name = body.login.strip().lower()
    key = body.role + ":" + name
    recent = throttle(key)
    table, col = ("teachers", "pass_hash") if body.role == "teacher" else ("students", "pin_hash")
    row = q1(f"select id, {col} as h from {table} where login = %s", name)
    if not check_secret(body.password, row["h"] if row else DUMMY_HASH) or not row:
        record_fail(key, recent)
        raise HTTPException(401, "Невірний логін або пароль.")
    fails.pop(key, None)
    request.session.update(role=body.role, id=row["id"], v=row["h"][:8])
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


class TeacherIn(BaseModel):
    login: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    last: str = Field(min_length=2, max_length=100)
    first: str = Field(min_length=2, max_length=100)
    about: str = Field("", max_length=200)
    setup_code: str = Field("", max_length=200)


@app.post("/api/teachers")
def add_teacher(body: TeacherIn, request: Request):
    """A logged-in teacher adds a colleague; the very first teacher needs SETUP_CODE."""
    s = request.session
    by_teacher = s.get("role") == "teacher" and q1("select 1 as x from teachers where id = %s", s.get("id"))
    if not by_teacher:
        if q1("select 1 as x from teachers limit 1") or not SETUP_CODE \
                or not hmac.compare_digest(body.setup_code.encode(), SETUP_CODE.encode()):
            raise HTTPException(403, "Невірний код першого запуску.")
    h = hash_secret(body.password)
    row = q1("insert into teachers (login, pass_hash, last, first, about) values (%s, %s, %s, %s, %s) returning id",
             body.login.strip().lower(), h, clean(body.last), clean(body.first), clean(body.about))
    if not by_teacher:
        s.update(role="teacher", id=row["id"], v=h[:8])
    return {"ok": True}


class ProfileIn(BaseModel):
    last: str = Field(min_length=2, max_length=100)
    first: str = Field(min_length=2, max_length=100)
    about: str = Field("", max_length=200)
    password: str = Field("", max_length=128)


@app.put("/api/me")
def update_profile(body: ProfileIn, request: Request, u: dict = Depends(teacher)):
    run("update teachers set last = %s, first = %s, about = %s where id = %s",
        clean(body.last), clean(body.first), clean(body.about), u["id"])
    if body.password:
        if len(body.password) < 8:
            raise HTTPException(422, "Пароль має містити щонайменше 8 символів.")
        h = hash_secret(body.password)
        run("update teachers set pass_hash = %s where id = %s", h, u["id"])
        request.session["v"] = h[:8]
    return {"ok": True}


# ---------- state ----------

@app.get("/api/state")
def state(u: dict = Depends(user)):
    """Everything the current user may see, in one response.
    ponytail: whole-school payload for a teacher; paginate answers when this gets slow."""
    t = u["role"] == "teacher"
    sid = u["id"]
    lessons_sql = f"""select l.id, l.topic, c.name as cls, l.date, l.video_url, l.material, l.tasks, {TS.format('l.')}
                      from lessons l left join classes c on c.id = l.class_id"""
    answers_sql = f"""select a.id, a.student_id, s.last, s.first, c.name as cls, a.lesson_id, a.topic, a.kind,
                             a.text, a.file_name, {TS.format('a.')}
                      from answers a join students s on s.id = a.student_id join classes c on c.id = s.class_id"""
    comments_sql = f"select id, student_id, lesson_id, author, text, {TS.format('')} from comments"
    grades_sql = "select student_id, lesson_id, value from grades"
    out = {"role": u["role"], "me": {k: v for k, v in u.items() if k not in ("role", "class_id")},
           "today": today(), "uploads": bool(s3), "ai": bool(ai)}
    if t:
        out |= {
            "classes": [r["name"] for r in q("select name from classes order by name")],
            "students": q(f"""select s.id, s.last, s.first, c.name as cls, s.login, {TS.format('s.')}
                              from students s join classes c on c.id = s.class_id"""),
            "lessons": q(lessons_sql + " order by l.created_at desc"),
            "answers": q(answers_sql + " order by a.created_at desc"),
            "comments": q(comments_sql),
            "grades": q(grades_sql),
        }
    else:
        out |= {
            "lessons": q(lessons_sql + " where l.class_id = %s and l.date <= %s order by l.date desc",
                         u["class_id"], today()),
            "answers": q(answers_sql + " where a.student_id = %s order by a.created_at desc", sid),
            "comments": q(comments_sql + " where student_id = %s", sid),
            "grades": q(grades_sql + " where student_id = %s", sid),
        }
    return out


# ---------- students ----------

class StudentsIn(BaseModel):
    cls: str = Field(min_length=1, max_length=20)
    names: list[str] = Field(min_length=1, max_length=60)


def new_pin() -> str:
    return f"{secrets.randbelow(10000):04d}"


@app.post("/api/students")
def add_students(body: StudentsIn, u: dict = Depends(teacher)):
    """Creates students and returns their logins and PINs. PINs are shown only here."""
    cid = class_id(body.cls)
    created, skipped = [], 0
    for raw in body.names:
        parts = clean(raw)[:200].split(" ")
        last, first = parts[0], " ".join(parts[1:])
        if not first or q1("""select 1 as x from students where class_id = %s
                              and lower(last) = lower(%s) and lower(first) = lower(%s)""", cid, last, first):
            skipped += 1
            continue
        pin = new_pin()
        while True:
            code = "".join(secrets.choice(LOGIN_ALPHABET) for _ in range(6))
            if q1("""insert into students (class_id, last, first, login, pin_hash) values (%s, %s, %s, %s, %s)
                     on conflict (login) do nothing returning id""", cid, last, first, code, hash_secret(pin)):
                break
        created.append({"last": last, "first": first, "login": code, "pin": pin})
    return {"created": created, "skipped": skipped}


@app.post("/api/students/{sid}/pin")
def reset_pin(sid: int, u: dict = Depends(teacher)):
    pin = new_pin()
    row = q1("update students set pin_hash = %s where id = %s returning login", hash_secret(pin), sid)
    if not row:
        raise HTTPException(404, "Учня не знайдено.")
    fails.pop("student:" + row["login"], None)
    return {"login": row["login"], "pin": pin}


@app.delete("/api/students/{sid}")
def delete_student(sid: int, u: dict = Depends(teacher)):
    """Removes the student with their answers, grades, comments and uploaded files."""
    keys = [r["file_key"] for r in q("select file_key from answers where student_id = %s and file_key is not null", sid)]
    run("delete from students where id = %s", sid)
    if s3:
        for k in keys:
            s3.delete_object(Bucket=BUCKET, Key=k)
    return {"ok": True}


# ---------- lessons ----------

class Section(BaseModel):
    h: str
    p: str


class Task(BaseModel):
    title: str
    desc: str


class LessonOut(BaseModel):
    material: list[Section]
    text: Task
    pc: Task
    phone: Task


def generate_lesson(topic: str, cls: str) -> dict:
    prompt = f"""Ти — вчитель інформатики в Україні. Тема уроку: "{topic}", клас: {cls} (підбери складність за віком). Пиши українською.

material — рівно 4 розділи теорії: що це; ключові поняття; приклад; типові помилки й підсумок. У кожному: h — заголовок, p — 2-4 речення для учня з прикладом. Код пиши простим текстом.

Три практичні завдання (title — назва, desc — до 60 слів):
text — письмове завдання без комп'ютера;
pc — практична робота за комп'ютером (кроки й очікуваний результат);
phone — завдання лише зі смартфона (застосунок, мобільний сайт або онлайн-редактор)."""
    try:
        r = ai.messages.parse(model="claude-haiku-5-5", max_tokens=16000,
                              messages=[{"role": "user", "content": prompt}], output_format=LessonOut)
    except (anthropic.APIError, ValueError) as e:
        raise HTTPException(502, "Не вдалося згенерувати урок. Спробуй ще раз.") from e
    o = r.parsed_output
    if r.stop_reason == "refusal" or o is None or not o.material:
        raise HTTPException(502, "Модель не склала урок за цією темою. Переформулюй тему.")
    return {"material": [s.model_dump() for s in o.material],
            "tasks": {k: getattr(o, k).model_dump() for k in ("text", "pc", "phone")}}


class GenerateIn(BaseModel):
    topic: str = Field(min_length=1, max_length=200)
    cls: str = Field(min_length=1, max_length=20)
    date: date
    video_url: str = Field("", max_length=500)


@app.post("/api/lessons/generate")
def create_lesson(body: GenerateIn, u: dict = Depends(teacher)):
    if not ai:
        raise HTTPException(503, "Генерацію не налаштовано: немає ключа Claude API.")
    n = q1("select count(*) as n from lessons where teacher_id = %s and created_at > now() - interval '1 day'", u["id"])
    if n["n"] >= AI_DAILY_LIMIT:
        raise HTTPException(429, f"Ліміт: {AI_DAILY_LIMIT} уроків на добу.")
    topic = clean(body.topic)
    g = generate_lesson(topic, clean(body.cls))
    v = body.video_url.strip()
    row = q1("""insert into lessons (class_id, teacher_id, topic, date, video_url, material, tasks)
                values (%s, %s, %s, %s, %s, %s, %s) returning id""",
             class_id(body.cls), u["id"], topic, body.date, v if v.startswith("https://") else "",
             Jsonb(g["material"]), Jsonb(g["tasks"]))
    return {"id": row["id"]}


class ScheduleIn(BaseModel):
    cls: str = Field(max_length=20)
    date: date | None


@app.patch("/api/lessons/{lid}")
def schedule_lesson(lid: int, body: ScheduleIn, u: dict = Depends(teacher)):
    cid = class_id(body.cls) if clean(body.cls) else None
    if not run("update lessons set class_id = %s, date = %s where id = %s", cid, body.date, lid):
        raise HTTPException(404, "Урок не знайдено.")
    return {"ok": True}


@app.delete("/api/lessons/{lid}")
def delete_lesson(lid: int, u: dict = Depends(teacher)):
    run("delete from lessons where id = %s", lid)
    return {"ok": True}


def visible_lesson(lid: int, u: dict) -> dict:
    row = q1("select id, topic from lessons where id = %s and class_id = %s and date <= %s",
             lid, u["class_id"], today())
    if not row:
        raise HTTPException(404, "Урок не знайдено.")
    return row


# ---------- answers, files ----------

@app.post("/api/answers")
def add_answer(lesson_id: int = Form(), kind: str = Form(), text: str = Form(""),
               file: UploadFile | None = File(None), u: dict = Depends(student)):
    if kind not in KINDS:
        raise HTTPException(422, "Невідомий формат завдання.")
    lesson = visible_lesson(lesson_id, u)
    text = text.strip()[:20000]
    if file is not None and not file.filename:
        file = None
    if not text and not file:
        raise HTTPException(422, "Порожня відповідь.")
    key = name = None
    if file:
        if not s3:
            raise HTTPException(503, "Завантаження файлів не налаштовано.")
        name = Path(file.filename).name[:200]
        ext = Path(name).suffix.lower()
        if ext not in FILE_EXT:
            raise HTTPException(415, "Такий тип файлу не приймається.")
        if (file.size or 0) > MAX_FILE:
            raise HTTPException(413, "Файл більший за 20 МБ.")
        key = f"answers/{u['id']}/{uuid.uuid4().hex}{ext}"
        s3.upload_fileobj(file.file, BUCKET, key,
                          ExtraArgs={"ContentType": file.content_type or "application/octet-stream"})
    run("""insert into answers (student_id, lesson_id, topic, kind, text, file_key, file_name)
           values (%s, %s, %s, %s, %s, %s, %s)""",
        u["id"], lesson["id"], lesson["topic"], kind, text or "(файл)", key, name)
    return {"ok": True}


@app.get("/api/files/{aid}")
def get_file(aid: int, u: dict = Depends(user)):
    row = q1("select student_id, file_key, file_name from answers where id = %s", aid)
    if not row or not row["file_key"] or not s3 or (u["role"] == "student" and row["student_id"] != u["id"]):
        raise HTTPException(404, "Файл не знайдено.")
    url = s3.generate_presigned_url("get_object", ExpiresIn=300, Params={
        "Bucket": BUCKET, "Key": row["file_key"],
        "ResponseContentDisposition": "attachment; filename*=UTF-8''" + quote(row["file_name"] or "file"),
    })
    return RedirectResponse(url, 302)


# ---------- comments, grades ----------

class CommentIn(BaseModel):
    lesson_id: int
    text: str = Field(min_length=1, max_length=5000)
    student_id: int | None = None


@app.post("/api/comments")
def add_comment(body: CommentIn, u: dict = Depends(user)):
    if u["role"] == "student":
        sid = u["id"]
        visible_lesson(body.lesson_id, u)
    elif body.student_id is None:
        raise HTTPException(422, "Не вказано учня.")
    else:
        sid = body.student_id
    run("insert into comments (student_id, lesson_id, author, text) values (%s, %s, %s, %s)",
        sid, body.lesson_id, u["role"], body.text.strip())
    return {"ok": True}


class GradeIn(BaseModel):
    student_id: int
    lesson_id: int
    value: int = Field(ge=1, le=12)


@app.put("/api/grades")
def set_grade(body: GradeIn, u: dict = Depends(teacher)):
    run("""insert into grades (student_id, lesson_id, value) values (%s, %s, %s)
           on conflict (student_id, lesson_id) do update set value = excluded.value, updated_at = now()""",
        body.student_id, body.lesson_id, body.value)
    return {"ok": True}
