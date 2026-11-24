"""End-to-end check of the rules that matter: who can see and change what.
Run: pytest  (uses an embedded Postgres, a fake file store and a fake lesson generator)"""
import io
import os
from datetime import timedelta

import pgserver
import pytest
from fastapi.testclient import TestClient


class FakeS3:
    def __init__(self):
        self.objects = {}

    def upload_fileobj(self, f, bucket, key, ExtraArgs=None):
        self.objects[key] = f.read()

    def generate_presigned_url(self, op, ExpiresIn, Params):
        return "https://files.example/" + Params["Key"]

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)


@pytest.fixture(scope="module")
def m(tmp_path_factory):
    pg = pgserver.get_server(tmp_path_factory.mktemp("pg"))
    os.environ.update(DATABASE_URL=pg.get_uri(), SECRET_KEY="test", SETUP_CODE="first-run")
    import app.main as m
    m.s3, m.BUCKET, m.ai = FakeS3(), "b", object()
    m.generate_lesson = lambda topic, cls: {
        "material": [{"h": "Що це", "p": topic}],
        "tasks": {k: {"title": k, "desc": "d"} for k in ("text", "pc", "phone")}}
    with TestClient(m.app):  # runs startup: applies schema.sql
        yield m
    pg.cleanup()


def client(m):
    return TestClient(m.app, follow_redirects=False)


def login(c, role, login, password):
    return c.post("/api/login", json={"role": role, "login": login, "password": password})


def test_everything(m):
    T = {"login": "Teacher1", "password": "password1", "last": "Коваль", "first": "Олена Іванівна"}
    anon, t = client(m), client(m)

    # --- first teacher needs the setup code; afterwards the code is useless ---
    r = anon.get("/api/state")
    assert r.status_code == 401 and r.json()["detail"]["setup"] is True
    assert anon.post("/api/teachers", json=T | {"setup_code": "wrong"}).status_code == 403
    assert t.post("/api/teachers", json=T | {"setup_code": "first-run"}).status_code == 200
    assert t.get("/api/state").json()["role"] == "teacher"  # logged in right away
    assert anon.post("/api/teachers", json=T | {"login": "evil", "setup_code": "first-run"}).status_code == 403
    assert anon.get("/api/state").json()["detail"]["setup"] is False
    assert login(client(m), "teacher", "teacher1", "password1").status_code == 200  # login is case-insensitive
    assert t.post("/api/teachers", json=T | {"login": "teacher1"}).status_code == 409
    assert t.post("/api/teachers", json=T | {"login": "teacher2"}).status_code == 200

    # --- students: created by the teacher, duplicates skipped ---
    r = t.post("/api/students", json={"cls": "5-А", "names": ["Петренко  Іван", "Шевченко Оля", "Безімені"]}).json()
    assert len(r["created"]) == 2 and r["skipped"] == 1
    ivan, olya = r["created"]
    assert t.post("/api/students", json={"cls": "5-а", "names": ["петренко іван"]}).json()["skipped"] == 1
    other = t.post("/api/students", json={"cls": "6-Б", "names": ["Бондар Макс"]}).json()["created"][0]
    st = t.get("/api/state").json()
    assert st["classes"] == ["5-А", "6-Б"] and len(st["students"]) == 3
    ids = {s["login"]: s["id"] for s in st["students"]}

    a, b, c6 = client(m), client(m), client(m)
    assert login(a, "student", ivan["login"], "nope").status_code == 401
    assert login(a, "student", ivan["login"].upper(), ivan["pin"]).status_code == 200
    assert login(b, "student", olya["login"], olya["pin"]).status_code == 200
    assert login(c6, "student", other["login"], other["pin"]).status_code == 200
    assert login(client(m), "teacher", ivan["login"], ivan["pin"]).status_code == 401  # roles do not mix

    # --- students cannot use teacher endpoints ---
    for method, url, body in [
        ("post", "/api/students", {"cls": "5-А", "names": ["А Б"]}),
        ("post", f"/api/students/{ids[olya['login']]}/pin", None),
        ("delete", f"/api/students/{ids[olya['login']]}", None),
        ("post", "/api/lessons/generate", {"topic": "x", "cls": "5-А", "date": "2026-01-01"}),
        ("patch", "/api/lessons/1", {"cls": "5-А", "date": None}),
        ("delete", "/api/lessons/1", None),
        ("put", "/api/grades", {"student_id": ids[ivan["login"]], "lesson_id": 1, "value": 12}),
        ("put", "/api/me", {"last": "Хак", "first": "Хак"}),
        ("post", "/api/teachers", T | {"login": "evil2"}),
    ]:
        assert a.request(method, url, json=body).status_code == 403, url
        assert anon.request(method, url, json=body).status_code in (401, 403), url

    # --- lessons: only own class, only from the lesson day ---
    today = m.today()
    def gen(topic, cls, d):
        return t.post("/api/lessons/generate", json={"topic": topic, "cls": cls, "date": str(d),
                                                     "video_url": "javascript:alert(1)"}).json()["id"]
    l_today, l_future = gen("Цикли", "5-А", today), gen("Майбутнє", "5-А", today + timedelta(days=1))
    l_other = gen("Чужий", "6-Б", today)
    sa = a.get("/api/state").json()
    assert [l["id"] for l in sa["lessons"]] == [l_today]
    assert sa["lessons"][0]["video_url"] == ""  # only https links are kept
    assert "students" not in sa and "classes" not in sa
    assert sa["me"]["cls"] == "5-А" and "h" not in sa["me"] and "pin_hash" not in str(sa)

    # --- answers: only to visible lessons; file goes to the store ---
    def answer(c, lid, **kw):
        return c.post("/api/answers", data={"lesson_id": lid, "kind": "text", "text": "моя відповідь"}, **kw)
    assert answer(a, l_today, files={"file": ("фото.png", io.BytesIO(b"png"), "image/png")}).status_code == 200
    assert answer(a, l_future).status_code == 404
    assert answer(a, l_other).status_code == 404
    assert answer(t, l_today).status_code == 403
    assert answer(a, l_today, files={"file": ("x.exe", io.BytesIO(b"mz"), "application/x-msdownload")}).status_code == 415
    assert a.post("/api/answers", data={"lesson_id": l_today, "kind": "bad", "text": "x"}).status_code == 422
    assert a.post("/api/answers", data={"lesson_id": l_today, "kind": "text", "text": " "}).status_code == 422
    assert answer(b, l_today).status_code == 200
    key = next(iter(m.s3.objects))
    assert key.startswith(f"answers/{ids[ivan['login']]}/") and key.endswith(".png")

    mine = a.get("/api/state").json()["answers"]
    assert len(mine) == 1 and mine[0]["file_name"] == "фото.png" and "file_key" not in mine[0]
    aid = mine[0]["id"]
    assert a.get(f"/api/files/{aid}").headers["location"].endswith(key)
    assert t.get(f"/api/files/{aid}").status_code == 302
    assert b.get(f"/api/files/{aid}").status_code == 404   # someone else's file
    assert anon.get(f"/api/files/{aid}").status_code == 401

    # --- comments and grades: a student sees only their own ---
    ivan_id, olya_id = ids[ivan["login"]], ids[olya["login"]]
    assert a.post("/api/comments", json={"lesson_id": l_today, "text": "питання", "student_id": olya_id}).status_code == 200
    assert a.post("/api/comments", json={"lesson_id": l_other, "text": "x"}).status_code == 404
    assert t.post("/api/comments", json={"lesson_id": l_today, "text": "молодець", "student_id": ivan_id}).status_code == 200
    assert t.post("/api/comments", json={"lesson_id": l_today, "text": "x"}).status_code == 422
    assert t.post("/api/comments", json={"lesson_id": l_today, "text": "x", "student_id": 99999}).status_code == 404
    assert t.put("/api/grades", json={"student_id": ivan_id, "lesson_id": l_today, "value": 13}).status_code == 422
    assert t.put("/api/grades", json={"student_id": ivan_id, "lesson_id": l_today, "value": 9}).status_code == 200
    assert t.put("/api/grades", json={"student_id": ivan_id, "lesson_id": l_today, "value": 11}).status_code == 200
    assert t.put("/api/grades", json={"student_id": olya_id, "lesson_id": l_today, "value": 4}).status_code == 200
    sa, sb = a.get("/api/state").json(), b.get("/api/state").json()
    assert sa["grades"] == [{"student_id": ivan_id, "lesson_id": l_today, "value": 11}]
    assert sorted(x["author"] for x in sa["comments"]) == ["student", "teacher"]  # student_id in body was ignored
    assert all(x["student_id"] == ivan_id for x in sa["comments"])
    assert sb["grades"] == [{"student_id": olya_id, "lesson_id": l_today, "value": 4}]
    assert sb["comments"] == [] and len(sb["answers"]) == 1
    stt = t.get("/api/state").json()
    assert len(stt["answers"]) == 2 and len(stt["grades"]) == 2 and len(stt["lessons"]) == 3

    # --- schedule: moving the lesson to tomorrow hides it ---
    assert t.patch(f"/api/lessons/{l_today}", json={"cls": "5-А", "date": str(today + timedelta(days=1))}).status_code == 200
    assert a.get("/api/state").json()["lessons"] == []
    assert t.patch(f"/api/lessons/{l_today}", json={"cls": "", "date": None}).status_code == 200  # draft
    assert t.patch(f"/api/lessons/{l_today}", json={"cls": "5-А", "date": str(today)}).status_code == 200

    # --- new PIN logs the old session out; old PIN stops working ---
    new = t.post(f"/api/students/{olya_id}/pin").json()
    assert b.get("/api/state").status_code == 401
    assert login(b, "student", olya["login"], olya["pin"]).status_code == 401
    assert login(b, "student", olya["login"], new["pin"]).status_code == 200

    # --- lockout after 5 wrong attempts, even with the right PIN ---
    x = client(m)
    for _ in range(5):
        assert login(x, "student", other["login"], "0000x").status_code == 401
    assert login(x, "student", other["login"], other["pin"]).status_code == 429

    # --- deleting a lesson keeps answers; deleting a student removes everything, files too ---
    assert t.delete(f"/api/lessons/{l_today}").status_code == 200
    sa = a.get("/api/state").json()
    assert len(sa["answers"]) == 1 and sa["answers"][0]["lesson_id"] is None and sa["grades"] == []
    assert t.delete(f"/api/students/{ivan_id}").status_code == 200
    assert a.get("/api/state").status_code == 401 and m.s3.objects == {}
    assert len(t.get("/api/state").json()["answers"]) == 1

    # --- teacher password change keeps this session, drops others ---
    t2 = client(m)
    assert login(t2, "teacher", "teacher1", "password1").status_code == 200
    assert t.put("/api/me", json={"last": "Коваль", "first": "Олена", "password": "short"}).status_code == 422
    assert t.put("/api/me", json={"last": "Коваль", "first": "Олена", "password": "newpassword"}).status_code == 200
    assert t.get("/api/state").json()["me"]["first"] == "Олена"
    assert t2.get("/api/state").status_code == 401

    # --- oversized upload is refused before it is read ---
    assert a.post("/api/answers", content=b"x", headers={"content-length": str(30 * 1024 * 1024)}).status_code == 413
