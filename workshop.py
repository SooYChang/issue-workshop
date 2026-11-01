"""Issue workshop for one journal issue.

Members upload papers, reviewers recommend, and the chief editor decides.
Producing an issue writes page-numbered PDFs and a confidential history.
The public journal website is a different program and is not used here.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import sqlite3
import threading
import traceback
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = int(os.environ.get("WORKSHOP_PORT", "8787"))
LOCK = threading.Lock()
PDF_LIMIT = 20 * 1024 * 1024
ROLES = {"chief": "Chief editor", "member": "Member", "reviewer": "Reviewer"}
STATUSES = {
    "submitted": "Submitted",
    "in_review": "With reviewers",
    "revision": "Revision requested",
    "accepted": "Accepted",
    "rejected": "Rejected",
}
RECOMMENDATIONS = {"accept": "Accept", "revise": "Revise", "reject": "Reject"}


class AppError(Exception):
    pass


def data_root() -> Path:
    raw = os.environ.get("WORKSHOP_DATA")
    path = Path(raw) if raw else ROOT / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def pretty_date(iso: str | None) -> str:
    if not iso:
        return ""
    moment = datetime.fromisoformat(iso)
    if moment.tzinfo:
        moment = moment.astimezone()
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{moment.day:02d} {months[moment.month - 1]} {moment.year}, {moment:%H:%M}"


def esc(value) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def new_id() -> str:
    return secrets.token_hex(8)


def same(left: str, right: str) -> bool:
    if not left or not right or len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000)
    return f"{salt}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000)
    except Exception:
        return False
    return same(digest, check.hex())


def required(value: str | None, message: str, limit: int = 4000) -> str:
    text = (value or "").strip()
    if not text:
        raise AppError(message)
    if len(text) > limit:
        raise AppError("That text is too long.")
    return text


def optional(value: str | None, limit: int = 8000) -> str:
    text = (value or "").strip()
    if len(text) > limit:
        raise AppError("That text is too long.")
    return text


def clean_email(value: str | None) -> str:
    email = (value or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise AppError("Enter a real email address.")
    return email


def clean_password(value: str | None) -> str:
    password = value or ""
    if len(password) < 8:
        raise AppError("Use a password of at least 8 characters.")
    if len(password) > 200:
        raise AppError("That password is too long.")
    return password


def field(fields: dict, name: str, default: str = "") -> str:
    values = fields.get(name) or []
    return values[-1] if values else default


def field_all(fields: dict, name: str) -> list[str]:
    return [item for item in (fields.get(name) or []) if item]


def param(header: str, key: str) -> str | None:
    star = re.search(rf"{key}\*=UTF-8''([^;]+)", header, re.I)
    if star:
        return unquote(star.group(1))
    quoted = re.search(rf'{key}="([^"]*)"', header, re.I)
    if quoted:
        return quoted.group(1)
    plain = re.search(rf"{key}=([^;]+)", header, re.I)
    if plain:
        return plain.group(1).strip().strip('"')
    return None


def parse_body(content_type: str, body: bytes):
    fields: dict[str, list[str]] = {}
    files: dict[str, tuple[str, bytes]] = {}
    if "multipart/form-data" not in content_type.lower():
        parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        return parsed, files
    match = re.search(r"boundary=(?P<b>[^;]+)", content_type, re.I)
    if not match:
        raise AppError("The form could not be read.")
    boundary = match.group("b").strip().strip('"').encode("utf-8", errors="replace")
    for part in body.split(b"--" + boundary):
        if part in (b"", b"--", b"--\r\n") or part.startswith(b"--"):
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        header_blob, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        headers = {}
        for line in header_blob.decode("utf-8", errors="replace").split("\r\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()
        disposition = headers.get("content-disposition", "")
        name = param(disposition, "name")
        filename = param(disposition, "filename")
        if not name:
            continue
        if filename:
            if data:
                files[name] = (Path(filename).name, data)
        else:
            fields.setdefault(name, []).append(data.decode("utf-8", errors="replace"))
    return fields, files


def db():
    class Conn:
        def __enter__(self):
            LOCK.acquire()
            self.conn = sqlite3.connect(data_root() / "workshop.db")
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type:
                    self.conn.rollback()
                else:
                    self.conn.commit()
            finally:
                self.conn.close()
                LOCK.release()

    return Conn()


SCHEMA = """
CREATE TABLE IF NOT EXISTS editor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issue (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    journal_name TEXT NOT NULL,
    volume INTEGER,
    issue_number INTEGER,
    opened_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    affiliation TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('chief', 'member', 'reviewer')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signins (
    token TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    csrf TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS works (
    id TEXT PRIMARY KEY,
    member_id TEXT NOT NULL REFERENCES accounts(id),
    title TEXT NOT NULL,
    article_type TEXT NOT NULL DEFAULT '',
    author_name TEXT NOT NULL,
    author_email TEXT NOT NULL,
    author_affiliation TEXT NOT NULL,
    coauthors TEXT NOT NULL DEFAULT '',
    abstract_text TEXT NOT NULL DEFAULT '',
    keywords TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('submitted', 'in_review', 'revision', 'accepted', 'rejected')),
    revision_count INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL REFERENCES works(id),
    kind TEXT NOT NULL CHECK (kind IN ('anonymous', 'response', 'final', 'report')),
    round_no INTEGER NOT NULL DEFAULT 0,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    uploaded_by TEXT NOT NULL REFERENCES accounts(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assignments (
    id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL REFERENCES works(id),
    reviewer_id TEXT NOT NULL REFERENCES accounts(id),
    round_no INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    response TEXT NOT NULL DEFAULT 'pending' CHECK (response IN ('pending', 'agreed', 'declined')),
    responded_at TEXT,
    replaces_id TEXT,
    UNIQUE (work_id, reviewer_id, round_no)
);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    assignment_id TEXT NOT NULL UNIQUE REFERENCES assignments(id),
    recommendation TEXT NOT NULL CHECK (recommendation IN ('accept', 'revise', 'reject')),
    comments TEXT NOT NULL DEFAULT '',
    editor_note TEXT NOT NULL DEFAULT '',
    file_id TEXT REFERENCES files(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL REFERENCES works(id),
    round_no INTEGER NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('accept', 'revise', 'reject')),
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    desk INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS productions (
    id TEXT PRIMARY KEY,
    folder_name TEXT NOT NULL,
    page_count INTEGER NOT NULL,
    paper_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        ensure_columns(
            conn,
            "assignments",
            {
                "response": "TEXT NOT NULL DEFAULT 'pending'",
                "responded_at": "TEXT",
                "replaces_id": "TEXT",
            },
        )
        ensure_columns(conn, "decisions", {"desk": "INTEGER NOT NULL DEFAULT 0"})
        ensure_columns(conn, "reports", {"editor_note": "TEXT NOT NULL DEFAULT ''"})
        ensure_optional_heading(conn)
        ensure_columns(conn, "works", {"paper_no": "INTEGER"})
        assign_paper_numbers(conn)
        ensure_chief(conn)


def ensure_columns(conn, table: str, columns: dict[str, str]) -> None:
    found = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, declaration in columns.items():
        if name not in found:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def ensure_optional_heading(conn) -> None:
    try:
        info = list(conn.execute("PRAGMA table_info(issue)"))
    except sqlite3.OperationalError:
        return
    locked = {row["name"]: row["notnull"] for row in info}
    if not locked.get("volume") and not locked.get("issue_number"):
        return
    conn.execute(
        """CREATE TABLE issue_optional (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            journal_name TEXT NOT NULL,
            volume INTEGER,
            issue_number INTEGER,
            opened_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """INSERT INTO issue_optional (id, journal_name, volume, issue_number, opened_at)
           SELECT id, journal_name, volume, issue_number, opened_at FROM issue"""
    )
    conn.execute("DROP TABLE issue")
    conn.execute("ALTER TABLE issue_optional RENAME TO issue")


def ensure_chief(conn) -> None:
    try:
        editor = conn.execute("SELECT name, email, password_hash FROM editor WHERE id = 1").fetchone()
    except sqlite3.OperationalError:
        return
    if editor is None:
        return
    found = conn.execute(
        "SELECT id FROM accounts WHERE email = ? COLLATE NOCASE",
        (editor["email"],),
    ).fetchone()
    if found:
        return
    conn.execute(
        """INSERT INTO accounts (id, name, email, affiliation, password_hash, role, created_at)
           VALUES (?, ?, ?, '', ?, 'chief', ?)""",
        (new_id(), editor["name"], editor["email"], editor["password_hash"], now()),
    )


def current_issue(conn):
    try:
        return conn.execute(
            "SELECT journal_name, volume, issue_number, opened_at FROM issue WHERE id = 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return None


def account_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"]


def header_line(issue) -> str:
    parts = [issue["journal_name"]]
    if issue["volume"]:
        parts.append(f"Volume {issue['volume']}")
    if issue["issue_number"]:
        parts.append(f"Issue {issue['issue_number']}")
    return " · ".join(parts)


def paper_code(issue, work) -> str:
    seq = f"{int(work['paper_no'] or 0):03d}"
    if issue is None:
        return seq
    parts = [issue["journal_name"]]
    if issue["volume"]:
        parts.append(str(issue["volume"]))
    if issue["issue_number"]:
        parts.append(str(issue["issue_number"]))
    parts.append(seq)
    return "-".join(parts)


def next_paper_no(conn) -> int:
    row = conn.execute("SELECT COALESCE(MAX(paper_no), 0) AS n FROM works").fetchone()
    return int(row["n"]) + 1


def assign_paper_numbers(conn) -> None:
    missing = conn.execute(
        "SELECT id FROM works WHERE paper_no IS NULL ORDER BY created_at, id"
    ).fetchall()
    number = next_paper_no(conn)
    for row in missing:
        conn.execute("UPDATE works SET paper_no = ? WHERE id = ?", (number, row["id"]))
        number += 1


def optional_number(fields, name: str, label: str):
    raw = field(fields, name).strip()
    if not raw:
        return None
    try:
        number = int(raw)
    except ValueError:
        raise AppError(f"{label} needs a whole number.")
    if number < 1 or number > 10000:
        raise AppError(f"{label} needs a whole number.")
    return number


def read_issue_heading(fields):
    journal = required(field(fields, "journal_name"), "Enter the journal or proceeding name.", 200)
    volume = optional_number(fields, "volume", "Volume")
    issue_number = optional_number(fields, "issue_number", "Issue")
    return journal, volume, issue_number


def round_label(number: int) -> str:
    if number == 0:
        return "First submission"
    return f"Revision {number}"


def decision_name(row) -> str:
    if row["decision"] == "reject" and row["desk"]:
        return "Desk reject"
    return RECOMMENDATIONS[row["decision"]]


def status_pill(status: str) -> str:
    return f"<span class='pill {esc(status)}'>{esc(STATUSES.get(status, status))}</span>"


def keep(user, path: str) -> str:
    if not user or not user["token"]:
        return path
    base, _, fragment = path.partition("#")
    join = "&" if "?" in base else "?"
    secured = base + join + "s=" + quote(user["token"], safe="")
    if fragment:
        return secured + "#" + fragment
    return secured


def csrf_input(user) -> str:
    return (
        f"<input type='hidden' name='csrf' value='{esc(user['csrf'])}'>"
        f"<input type='hidden' name='session' value='{esc(user['token'])}'>"
    )


def layout(title: str, inner: str, user=None, issue=None, mark: str = "") -> str:
    kicker = "Issue workshop"
    if issue:
        kicker = header_line(issue)
    who = ""
    if user:
        who = (
            "<div class='who'><strong>"
            + esc(user["name"])
            + "</strong><div class='muted'>"
            + esc(ROLES.get(user["role"], user["role"]))
            + "</div><form method='post' action='/logout'>"
            + csrf_input(user)
            + "<button class='secondary' type='submit'>Sign out</button></form></div>"
        )
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{esc(title)}</title><link rel='stylesheet' href='/static/workshop.css'></head>"
        "<body><main><div class='wrap'><div class='top'><div><p class='kicker'>"
        + esc(kicker)
        + f"</p><h1>{esc(title)}</h1>"
        + (f"<p class='code'>{esc(mark)}</p>" if mark else "")
        + "</div>"
        + who
        + "</div>"
        + inner
        + "</div></main><footer>This workshop stays on this computer. It is separate from the public journal website.</footer>"
        + (
            "<script>if(location.search.indexOf('s=')!==-1){history.replaceState(null,'',location.pathname+location.hash)}</script>"
            if user
            else ""
        )
        + "</body></html>"
    )


def file_row(conn, work_id: str, kind: str, round_no: int | None = None):
    if round_no is None:
        return conn.execute(
            """SELECT * FROM files WHERE work_id = ? AND kind = ?
               ORDER BY created_at DESC LIMIT 1""",
            (work_id, kind),
        ).fetchone()
    return conn.execute(
        """SELECT * FROM files WHERE work_id = ? AND kind = ? AND round_no = ?
           ORDER BY created_at DESC LIMIT 1""",
        (work_id, kind, round_no),
    ).fetchone()


def stored_path(stored_name: str) -> Path:
    root = (data_root() / "files").resolve()
    path = (root / stored_name).resolve()
    if path != root and root not in path.parents:
        raise AppError("That file was not found.")
    return path


def save_file(conn, user, work_id: str, kind: str, round_no: int, original: str, data: bytes) -> str:
    file_id = new_id()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", original).strip(".-")[:80] or "file"
    if "." not in safe:
        safe += ".pdf" if kind != "response" else ".txt"
    stored = f"{work_id}/{file_id}-{safe}"
    path = stored_path(stored)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    conn.execute(
        """INSERT INTO files
           (id, work_id, kind, round_no, original_name, stored_name, uploaded_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (file_id, work_id, kind, round_no, original, stored, user["id"], now()),
    )
    return file_id


def require_pdf(upload, label: str) -> tuple[str, bytes]:
    if not upload or not upload[1]:
        raise AppError(f"Choose the {label}.")
    name, data = upload
    if len(data) > PDF_LIMIT:
        raise AppError("That PDF is larger than 20 MB.")
    if not data[:32].lstrip().startswith(b"%PDF"):
        raise AppError(f"The {label} needs to be a PDF.")
    return name, data


def require_response(upload, text: str) -> tuple[str, bytes]:
    if upload and upload[1]:
        name, data = upload
        if len(data) > PDF_LIMIT:
            raise AppError("That response file is larger than 20 MB.")
        lower = name.lower()
        if lower.endswith(".pdf") or data[:32].lstrip().startswith(b"%PDF"):
            if not data[:32].lstrip().startswith(b"%PDF"):
                raise AppError("That response PDF could not be read.")
            return name, data
        if lower.endswith(".txt"):
            if b"\x00" in data[:2000]:
                raise AppError("The response should be a PDF or a plain text file.")
            return name, data
        raise AppError("Upload the response as a PDF or a .txt file, or type it in the box.")
    typed = (text or "").strip()
    if typed:
        if len(typed) > 8000:
            raise AppError("That response is too long. Put a long response in a PDF.")
        return "response.txt", typed.encode("utf-8")
    raise AppError("Add a response to the reviewers as a PDF, a text file, or a short note.")


def user_by_token(conn, token: str):
    if not token:
        return None
    return conn.execute(
        """SELECT s.token, s.csrf, a.id, a.name, a.email, a.affiliation, a.role
           FROM signins s JOIN accounts a ON a.id = s.account_id
           WHERE s.token = ?""",
        (token,),
    ).fetchone()


def load_user(conn, handler):
    token = ""
    for part in handler.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("workshop="):
            token = part.split("=", 1)[1]
    return user_by_token(conn, token)


def require_user(user):
    if user is None:
        raise AppError("Sign in first.")
    return user


def require_csrf(user, fields) -> None:
    require_user(user)
    if not same(field(fields, "csrf"), user["csrf"]):
        raise AppError("This form expired. Go back and try again.")


def load_work(conn, user, work_id: str):
    work = conn.execute("SELECT * FROM works WHERE id = ?", (work_id,)).fetchone()
    if work is None:
        raise AppError("That paper was not found.")
    if user["role"] == "chief":
        return work
    if user["role"] == "member" and work["member_id"] == user["id"]:
        return work
    if user["role"] == "reviewer":
        assigned = conn.execute(
            "SELECT 1 FROM assignments WHERE work_id = ? AND reviewer_id = ?",
            (work_id, user["id"]),
        ).fetchone()
        if assigned:
            return work
    raise AppError("That paper is not open to this sign-in.")


def can_download(conn, user, work, file_rec) -> bool:
    if user["role"] == "chief":
        return True
    if user["role"] == "member" and work["member_id"] == user["id"]:
        return True
    if user["role"] == "reviewer" and file_rec["kind"] in ("anonymous", "response"):
        assigned = conn.execute(
            """SELECT 1 FROM assignments
               WHERE work_id = ? AND reviewer_id = ? AND round_no = ? AND response IN ('pending', 'agreed')""",
            (work["id"], user["id"], file_rec["round_no"]),
        ).fetchone()
        return assigned is not None
    return False


def download_name(user, file_rec) -> str:
    if user["role"] == "reviewer":
        if file_rec["kind"] == "response":
            suffix = ".txt" if file_rec["original_name"].lower().endswith(".txt") else ".pdf"
            return f"response-round-{file_rec['round_no']}{suffix}"
        return f"manuscript-round-{file_rec['round_no']}.pdf"
    return file_rec["original_name"]


def paper_link(work, user, issue) -> str:
    return (
        f"<a class='paper' href='{keep(user, '/works/' + work['id'])}'><span>"
        f"<span class='code'>{esc(paper_code(issue, work))}</span>"
        f"<strong>{esc(work['title'])}</strong>"
        f"<span class='muted'>{esc(pretty_date(work['created_at']))}</span></span>"
        f"{status_pill(work['status'])}</a>"
    )


def next_step(conn) -> str:
    members = conn.execute("SELECT COUNT(*) AS n FROM accounts WHERE role = 'member'").fetchone()["n"]
    reviewers = conn.execute("SELECT COUNT(*) AS n FROM accounts WHERE role = 'reviewer'").fetchone()["n"]
    if members == 0:
        return "Create a member account. That person will upload the paper."
    if reviewers < 2:
        return "Create at least two reviewer accounts."
    works = conn.execute("SELECT status FROM works").fetchall()
    if not works:
        return "Sign out, sign in as the member, and upload a paper. The PDF must not show the authors."
    if any(row["status"] == "submitted" for row in works):
        return "Open the submitted paper. Choose 2 or 3 reviewers, or desk-reject it."
    if any(row["status"] == "in_review" for row in works):
        return (
            "You can accept, reject, or ask for a revision before the reviews are finished. "
            "If a reviewer declines, you can still choose a replacement."
        )
    if any(row["status"] == "revision" for row in works):
        return "The member needs to upload a revised PDF and a separate response to the reviewers."
    produced = conn.execute("SELECT COUNT(*) AS n FROM productions").fetchone()["n"]
    accepted = conn.execute("SELECT id FROM works WHERE status = 'accepted'").fetchall()
    if not accepted:
        return "There is no accepted paper to bind yet."
    for row in accepted:
        if file_row(conn, row["id"], "final") is None:
            return "An accepted paper still needs its final PDF, with the author names and without page numbers."
    busy = [row for row in works if row["status"] in ("submitted", "in_review", "revision")]
    if busy:
        return "Finish every paper that is still in review before producing the issue."
    if produced:
        return "The issue has been produced. The history record and the page-numbered PDFs are listed below."
    return "Every paper is decided and the final PDFs are in. You can produce the issue."


def home_page(conn, user, made: str, saved: str = "", heading: str = "", fresh: str = "") -> str:
    issue = current_issue(conn)
    if user["role"] == "chief":
        return chief_home(conn, user, issue, made, saved, heading, fresh)
    if user["role"] == "member":
        works = conn.execute(
            "SELECT * FROM works WHERE member_id = ? ORDER BY paper_no",
            (user["id"],),
        ).fetchall()
        items = "".join(paper_link(work, user, issue) for work in works) or "<p class='muted'>No papers yet.</p>"
        inner = (
            "<div class='stack'><p class='lede'>Upload the paper without author names. "
            "Type the names in the form. After acceptance, upload the final PDF with the names on the pages.</p>"
            f"<p><a class='button' href='{keep(user, '/works/new')}'>Upload a paper</a></p><div class='list'>{items}</div></div>"
        )
        return layout("Your papers", inner, user, issue)
    works = conn.execute(
        """SELECT DISTINCT w.* FROM works w
           JOIN assignments a ON a.work_id = w.id
           WHERE a.reviewer_id = ?
           ORDER BY w.paper_no""",
        (user["id"],),
    ).fetchall()
    items = "".join(reviewer_paper_link(conn, user, work, issue) for work in works) or "<p class='muted'>No papers are assigned to you yet.</p>"
    inner = (
        "<div class='stack'><p class='lede'>Open a request and read the anonymous PDF, then agree or decline. "
        "The authors stay hidden, and your name stays hidden from the authors. "
        "Your decision is shown on each paper as Decision: Accept, Decision: Revise, or Decision: Reject.</p>"
        f"<div class='list'>{items}</div></div>"
    )
    return layout("Papers to review", inner, user, issue)


def current_reviews(conn, work):
    return conn.execute(
        """SELECT a.id, a.reviewer_id, a.response, a.replaces_id, p.name, r.recommendation
           FROM assignments a
           JOIN accounts p ON p.id = a.reviewer_id
           LEFT JOIN reports r ON r.assignment_id = a.id
           WHERE a.work_id = ? AND a.round_no = ?
           ORDER BY p.name""",
        (work["id"], work["revision_count"]),
    ).fetchall()


def reviewer_decision_line(conn, user, work) -> str:
    reviews = current_reviews(conn, work)
    mine = next((row for row in reviews if row["reviewer_id"] == user["id"]), None)
    if mine is None:
        mine = conn.execute(
            """SELECT a.response, r.recommendation
               FROM assignments a
               LEFT JOIN reports r ON r.assignment_id = a.id
               WHERE a.work_id = ? AND a.reviewer_id = ?
               ORDER BY a.round_no DESC LIMIT 1""",
            (work["id"], user["id"]),
        ).fetchone()
        reviews = []
    if mine is not None and mine["recommendation"]:
        return "<span class='chip report'>Decision: " + esc(RECOMMENDATIONS[mine["recommendation"]]) + "</span>"
    if mine is None:
        return ""
    if mine["response"] == "declined":
        return "<span class='chip declined'>You declined</span>"
    if mine["response"] == "pending":
        return "<span class='chip wait'>Waiting for your reply</span>"
    return "<span class='chip agreed'>Your report is not sent yet</span>"


def reviewer_paper_link(conn, user, work, issue) -> str:
    detail = reviewer_decision_line(conn, user, work)
    line = f"<span class='reviewline'>{detail}</span>" if detail else ""
    return (
        f"<a class='paper dashboard' href='{keep(user, '/works/' + work['id'])}'>"
        f"<span><span class='code'>{esc(paper_code(issue, work))}</span>"
        f"<strong>{esc(work['title'])}</strong>"
        f"{line}</span>"
        f"{status_pill(work['status'])}</a>"
    )


def review_chip(row, replaced: bool) -> str:
    if row["response"] == "declined" and replaced:
        kind, label = "declined", "declined, replaced"
    elif row["response"] == "declined":
        kind, label = "declined", "declined"
    elif row["response"] == "pending":
        kind, label = "wait", "waiting"
    elif row["recommendation"]:
        kind, label = "report", RECOMMENDATIONS[row["recommendation"]]
    else:
        kind, label = "agreed", "agreed"
    return f"<span class='chip {kind}'>{esc(row['name'])} · {esc(label)}</span>"


def review_line(conn, work) -> str:
    if work["status"] not in ("submitted", "in_review", "revision"):
        return ""
    reviews = current_reviews(conn, work)
    if work["status"] == "submitted":
        return "<span class='chip wait'>Choose reviewers</span>"
    if work["status"] == "revision":
        return "<span class='chip wait'>Waiting for the revised PDF</span>"
    if not reviews:
        return "<span class='chip wait'>No reviewers yet</span>"
    replaced = {row["replaces_id"] for row in reviews if row["replaces_id"]}
    detail = "".join(review_chip(row, row["id"] in replaced) for row in reviews)
    open_reviews = [row for row in reviews if row["response"] != "declined"]
    pending = [row for row in open_reviews if row["response"] == "pending"]
    reports = [row for row in open_reviews if row["recommendation"]]
    if declined_without_replacement(reviews):
        detail += "<span class='chip declined'>Choose a replacement</span>"
    elif (
        open_reviews
        and not pending
        and len(open_reviews) in (2, 3)
        and len(reports) == len(open_reviews)
    ):
        detail += "<span class='chip report'>Ready for your decision</span>"
    return detail


def review_dashboard(conn, user, works, issue) -> str:
    counts = {key: 0 for key in STATUSES}
    for work in works:
        counts[work["status"]] = counts.get(work["status"], 0) + 1
    meters = (
        ("Submitted", counts["submitted"]),
        ("With reviewers", counts["in_review"]),
        ("Revision", counts["revision"]),
        ("Accepted", counts["accepted"]),
        ("Rejected", counts["rejected"]),
    )
    meter_html = "".join(
        f"<div class='meter'><strong>{count}</strong><span>{esc(label)}</span></div>"
        for label, count in meters
    )
    active = [work for work in works if work["status"] in ("submitted", "in_review", "revision")]
    if not active:
        rows = "<p class='muted'>No papers are with reviewers.</p>"
    else:
        blocks = []
        for work in active:
            detail = review_line(conn, work)
            line = f"<span class='reviewline'>{detail}</span>" if detail else ""
            blocks.append(
                f"<a class='paper dashboard' href='{keep(user, '/works/' + work['id'])}'>"
                f"<span><span class='code'>{esc(paper_code(issue, work))}</span>"
                f"<strong>{esc(work['title'])}</strong>"
                f"{line}</span>"
                f"{status_pill(work['status'])}</a>"
            )
        rows = "<div class='list'>" + "".join(blocks) + "</div>"
    return (
        "<section class='card'><h2>Dashboard</h2>"
        "<p class='muted'>Papers still with reviewers. A report shows Accept, Revise, or Reject.</p>"
        f"<div class='meters'>{meter_html}</div>"
        + rows
        + "</section>"
    )


def papers_section(conn, user, works, issue) -> str:
    if not works:
        rows = "<p class='muted'>No papers yet.</p>"
    else:
        blocks = []
        for work in works:
            blocks.append(
                f"<a class='paper' href='{keep(user, '/works/' + work['id'])}'>"
                f"<span><span class='code'>{esc(paper_code(issue, work))}</span>"
                f"<strong>{esc(work['title'])}</strong>"
                f"<span class='muted'>{esc(pretty_date(work['created_at']))}</span></span>"
                f"{status_pill(work['status'])}</a>"
            )
        rows = "<div class='list'>" + "".join(blocks) + "</div>"
    return (
        "<section class='card'><h2>Papers</h2>"
        "<p class='muted'>In number order. Open one to assign reviewers, "
        "replace someone who declined, or record a decision.</p>"
        + rows
        + "</section>"
    )


def chief_home(conn, user, issue, made: str, saved: str = "", heading: str = "", fresh: str = "") -> str:
    works = conn.execute("SELECT * FROM works ORDER BY paper_no").fetchall()
    saved_note = ""
    if saved:
        saved_note = f"<p class='note'>{esc(saved)} is saved. Open People to see the account.</p>"
    made_note = ""
    if made:
        production = conn.execute("SELECT id FROM productions WHERE id = ?", (made,)).fetchone()
        if production:
            made_note = (
                "<p class='note'>The issue is ready. Open the history record, then download the PDFs. "
                "Keep the history record here. Only the page-numbered PDFs belong on the public journal site.</p>"
            )
    productions = production_cards(conn, user)
    heading_note = ""
    if heading:
        heading_note = "<p class='note'>The heading is saved.</p>"
    fresh_note = ""
    if fresh:
        fresh_note = (
            "<p class='note'>The new issue is open. Reviewer sign-ins are unchanged. "
            "Create member accounts when the next papers are submitted.</p>"
        )
    inner = (
        "<div class='stack'>"
        + saved_note
        + made_note
        + heading_note
        + fresh_note
        + "<p class='muted'>The line at the top names this journal issue. "
        + f"<a href='{keep(user, '/issue')}'>Edit the heading</a></p>"
        + f"<p class='note'>{esc(next_step(conn))}</p>"
        + review_dashboard(conn, user, works, issue)
        + papers_section(conn, user, works, issue)
        + "<section class='card'><h2>People</h2>"
        + "<p class='muted'>Members upload papers. Reviewers read the anonymous PDF and send a report.</p>"
        + f"<p><a class='button' href='{keep(user, '/people#members')}'>Open People</a></p></section>"
        + "<section class='card'><h2>Produce the issue</h2>"
        + "<p class='muted'>This writes two things: the page-numbered PDFs, and a confidential history for the society. "
        + "The history is not part of the public issue.</p>"
        + f"<p><a class='button' href='{keep(user, '/produce')}'>Open the issue step</a></p>"
        + productions
        + "</section>"
        + "<section class='card'><h2>Start a new issue</h2>"
        + "<p class='muted'>When this issue is finished, clear the papers, comments, decisions, "
        + "produced files, and member accounts. Reviewer sign-ins stay.</p>"
        + f"<p><a class='button secondary' href='{keep(user, '/issue/new')}'>Start a new issue</a></p>"
        + "</section></div>"
    )
    return layout("This issue", inner, user, issue)


def issue_page(conn, user) -> str:
    issue = current_issue(conn)
    produced = conn.execute("SELECT COUNT(*) AS n FROM productions").fetchone()["n"]
    kept = ""
    if produced:
        kept = "<p class='muted'>PDFs already produced keep the heading they were made with.</p>"
    inner = (
        "<p><a href='" + keep(user, "/") + "'>Back</a></p>"
        "<div class='stack'><p class='lede'>This line appears at the top of every page. "
        "Leave volume and issue blank for a conference proceeding.</p>"
        + kept
        + "<form class='form-grid card' method='post' action='/issue'>"
        + csrf_input(user)
        + f"<label>Journal or proceeding name<input name='journal_name' value='{esc(issue['journal_name'])}' required></label>"
        + f"<label>Volume<span class='hint'>Optional.</span><input name='volume' value='{esc(issue['volume'])}'></label>"
        + f"<label>Issue<span class='hint'>Optional.</span><input name='issue_number' value='{esc(issue['issue_number'])}'></label>"
        + "<div class='actions'><button type='submit'>Save the heading</button></div></form></div>"
    )
    return layout("Edit the heading", inner, user, issue)


def new_issue_page(conn, user) -> str:
    issue = current_issue(conn)
    papers = conn.execute("SELECT COUNT(*) AS n FROM works").fetchone()["n"]
    members = conn.execute("SELECT COUNT(*) AS n FROM accounts WHERE role = 'member'").fetchone()["n"]
    reviewers = conn.execute("SELECT COUNT(*) AS n FROM accounts WHERE role = 'reviewer'").fetchone()["n"]
    produced = conn.execute("SELECT COUNT(*) AS n FROM productions").fetchone()["n"]
    inner = (
        "<p><a href='" + keep(user, "/") + "'>Back</a></p>"
        "<div class='stack'><p class='lede'>This opens the next issue and clears the one that just finished.</p>"
        "<div class='warnbox'><p>Save your own copy of the history record and the page-numbered PDFs first. "
        "Those files are removed from this workshop.</p>"
        f"<p>Papers to remove: {papers}. Member accounts to remove: {members}. "
        f"Produced copies to remove: {produced}. "
        f"Reviewer sign-ins that stay: {reviewers}. Those passwords stay. "
        "Their comments and decisions are removed. "
        "The first paper of the new issue is number 001.</p></div>"
        "<form class='form-grid card' method='post' action='/issue/new'>"
        + csrf_input(user)
        + f"<label>Journal or proceeding name<input name='journal_name' value='{esc(issue['journal_name'])}' required></label>"
        + f"<label>Volume<span class='hint'>Optional.</span><input name='volume' value='{esc(issue['volume'])}'></label>"
        + f"<label>Issue<span class='hint'>Optional.</span><input name='issue_number' value='{esc(issue['issue_number'])}'></label>"
        + "<div class='actions'><button class='warn' type='submit'>Start the new issue</button></div></form></div>"
    )
    return layout("Start a new issue", inner, user, issue)


def clear_issue_files() -> None:
    for name in ("files", "productions"):
        folder = data_root() / name
        if not folder.exists():
            continue
        for child in folder.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()


def start_new_issue(conn, fields) -> None:
    journal, volume, issue_number = read_issue_heading(fields)
    conn.execute("DELETE FROM reports")
    conn.execute("DELETE FROM decisions")
    conn.execute("DELETE FROM assignments")
    conn.execute("DELETE FROM files")
    conn.execute("DELETE FROM works")
    conn.execute("DELETE FROM productions")
    conn.execute(
        "DELETE FROM signins WHERE account_id IN (SELECT id FROM accounts WHERE role = 'member')"
    )
    conn.execute("DELETE FROM accounts WHERE role = 'member'")
    conn.execute(
        "UPDATE issue SET journal_name = ?, volume = ?, issue_number = ?, opened_at = ? WHERE id = 1",
        (journal, volume, issue_number, now()),
    )
    clear_issue_files()


def person_rows(conn, user, role: str) -> str:
    people = conn.execute(
        "SELECT * FROM accounts WHERE role = ? ORDER BY name",
        (role,),
    ).fetchall()
    rows = []
    for person in people:
        extra = ""
        if role == "member":
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM works WHERE member_id = ?",
                (person["id"],),
            ).fetchone()["n"]
            extra = "Has papers" if count else ""
        else:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM assignments WHERE reviewer_id = ?",
                (person["id"],),
            ).fetchone()["n"]
            extra = "Has reviews" if count else ""
        remove = ""
        if not extra:
            remove = (
                f"<form method='post' action='/accounts/{esc(person['id'])}/remove'>"
                + csrf_input(user)
                + "<button class='secondary' type='submit'>Remove</button></form>"
            )
        rows.append(
            "<div class='paper'><span><strong>"
            + esc(person["name"])
            + "</strong><br><span class='muted'>"
            + esc(person["email"])
            + (" · " + esc(person["affiliation"]) if person["affiliation"] else "")
            + "</span></span><span>"
            + (f"<span class='muted'>{esc(extra)}</span> " if extra else "")
            + remove
            + "</span></div>"
        )
    if not rows:
        empty = "No members yet." if role == "member" else "No reviewers yet."
        return f"<p class='muted'>{empty}</p>"
    return f"<div class='list'>{''.join(rows)}</div>"


def account_form(user, role: str) -> str:
    if role == "member":
        button = "Create member"
        hint = "Create this account when the person is ready to submit a paper."
    else:
        button = "Create reviewer"
        hint = "This person reads the anonymous PDF and sends a report. This sign-in stays for the next issue."
    return (
        "<form class='form-grid' method='post' action='/accounts'>"
        + csrf_input(user)
        + f"<input type='hidden' name='role' value='{role}'>"
        + f"<p class='muted'>{hint}</p>"
        + "<label>Name<input name='name' required></label>"
        + "<label>Email<input name='email' type='email' required></label>"
        + "<label>Affiliation<input name='affiliation'></label>"
        + "<label>Password<span class='hint'>At least 8 characters. You can read it here so you can tell this person.</span>"
        + "<input name='password' required></label>"
        + f"<div class='actions'><button type='submit'>{button}</button></div></form>"
    )


def people_page(conn, user, saved: str = "", saved_role: str = "") -> str:
    issue = current_issue(conn)
    note = ""
    if saved:
        place = "Members" if saved_role == "member" else "Reviewers"
        note = f"<p class='note'>{esc(saved)} is listed under {place}.</p>"
    inner = (
        "<p><a href='" + keep(user, "/") + "'>Back to the issue</a></p>"
        + note
        + "<p class='jump'><a href='#members'>Members</a><a href='#reviewers'>Reviewers</a></p>"
        + "<div class='stack'>"
        + "<section class='card' id='members'><h2>Members</h2>"
        + "<p class='muted'>Create a member when that person is ready to submit a paper. "
        + "Member accounts are removed when the next issue starts.</p>"
        + person_rows(conn, user, "member")
        + f"<p><a class='button' href='{keep(user, '/people/member')}'>Create member</a></p>"
        + "</section>"
        + "<section class='card' id='reviewers'><h2>Reviewers</h2>"
        + "<p class='muted'>Reviewer sign-ins stay when a new issue starts. "
        + "Their comments and decisions do not.</p>"
        + person_rows(conn, user, "reviewer")
        + f"<p><a class='button' href='{keep(user, '/people/reviewer')}'>Create reviewer</a></p>"
        + "</section></div>"
    )
    anchor = "reviewers" if saved_role == "reviewer" else "members"
    page = layout("People", inner, user, issue)
    if saved_role:
        page = page.replace("</body>", f"<script>location.hash='{anchor}'</script></body>")
    return page


def new_person_page(conn, user, role: str) -> str:
    title = "Create member" if role == "member" else "Create reviewer"
    inner = (
        "<p><a href='" + keep(user, "/people") + "'>Back to People</a></p>"
        + "<div class='card'>"
        + account_form(user, role)
        + "</div>"
    )
    return layout(title, inner, user, current_issue(conn))


def production_cards(conn, user) -> str:
    rows = conn.execute("SELECT * FROM productions ORDER BY created_at DESC").fetchall()
    if not rows:
        return ""
    cards = []
    for row in rows:
        folder = data_root() / "productions" / row["folder_name"]
        links = [
            f"<a href='{keep(user, '/productions/' + row['id'] + '/record.html')}'>History record</a>",
            f"<a href='{keep(user, '/productions/' + row['id'] + '/issue.pdf')}'>Bound issue PDF</a>",
        ]
        stamped = folder / "stamped"
        if stamped.is_dir():
            for path in sorted(stamped.glob("*.pdf")):
                links.append(
                    f"<a href='{keep(user, '/productions/' + row['id'] + '/stamped/' + path.name)}'>{esc(path.name)}</a>"
                )
        cards.append(
            "<div class='review'><strong>"
            + esc(pretty_date(row["created_at"]))
            + f"</strong><span class='muted'> · {row['paper_count']} accepted papers · {row['page_count']} pages</span>"
            + "<div class='meta'>"
            + " · ".join(links)
            + "</div></div>"
        )
    return "".join(cards)


def new_work_page(conn, user) -> str:
    issue = current_issue(conn)
    inner = (
        "<p><a href='" + keep(user, "/") + "'>Back to your papers</a></p>"
        "<form class='form-grid card' method='post' action='/works' enctype='multipart/form-data'>"
        + csrf_input(user)
        + "<label>Title<input name='title' required></label>"
        + "<label>Article type<select name='article_type'>"
        + "<option>Research article</option><option>Review article</option>"
        + "<option>Case study</option><option>Short communication</option></select></label>"
        + "<label>Author names on the form<span class='hint'>Reviewers do not see this. The PDF itself must not show the authors.</span>"
        + "<input name='author_name' required></label>"
        + "<label>Author email<input name='author_email' type='email' required></label>"
        + "<label>Affiliation<input name='author_affiliation' required></label>"
        + "<label>Coauthors<span class='hint'>One name on each line. Reviewers do not see this.</span>"
        + "<textarea name='coauthors'></textarea></label>"
        + "<label>Abstract<textarea name='abstract_text' required></textarea></label>"
        + "<label>Keywords<input name='keywords'></label>"
        + "<label>Anonymous PDF<span class='hint'>No author names, and no page numbers.</span>"
        + "<input name='manuscript' type='file' accept='application/pdf,.pdf' required></label>"
        + "<div class='actions'><button type='submit'>Upload paper</button></div></form>"
    )
    return layout("Upload a paper", inner, user, issue)


def work_page(conn, user, work) -> str:
    issue = current_issue(conn)
    if user["role"] == "chief":
        inner = chief_work(conn, user, work)
    elif user["role"] == "member":
        inner = member_work(conn, user, work)
    else:
        inner = reviewer_work(conn, user, work)
    title = work["title"]
    return layout(
        title,
        "<p><a href='" + keep(user, "/") + "'>Back</a></p>" + inner,
        user,
        issue,
        mark=paper_code(issue, work),
    )


def file_links(conn, user, work, kinds: set[str] | None = None) -> str:
    rows = conn.execute(
        "SELECT * FROM files WHERE work_id = ? ORDER BY round_no, created_at",
        (work["id"],),
    ).fetchall()
    items = []
    for row in rows:
        if kinds is not None and row["kind"] not in kinds:
            continue
        if not can_download(conn, user, work, row):
            continue
        label = {
            "anonymous": "Anonymous PDF",
            "response": "Response to reviewers",
            "final": "Final PDF",
            "report": "Review report",
        }[row["kind"]]
        if row["kind"] != "final":
            label += " · " + round_label(row["round_no"])
        items.append(
            f"<a href='{keep(user, '/files/' + row['id'])}'>{esc(label)}</a>"
        )
    if not items:
        return "<p class='muted'>No files yet.</p>"
    return "<div class='meta'>" + " · ".join(items) + "</div>"


def member_work(conn, user, work) -> str:
    guidance = {
        "submitted": "The chief editor has the paper. Reviewers do not see your name.",
        "in_review": "The chief editor has asked reviewers to read the anonymous PDF. They do not see your name, and you will not see theirs.",
        "revision": "Upload a revised PDF with no author names, and a separate response to the reviewers.",
        "accepted": "Upload the final PDF with the author names on the pages. Leave out page numbers and a running header.",
        "rejected": "This paper is closed. It stays in the workshop record. If you were asked to try again, upload it as a new paper.",
    }
    parts = [
        "<div class='stack'>",
        f"<p>{status_pill(work['status'])} <span class='muted'>{esc(guidance.get(work['status'], ''))}</span></p>",
    ]
    decisions = conn.execute(
        "SELECT * FROM decisions WHERE work_id = ? ORDER BY created_at",
        (work["id"],),
    ).fetchall()
    if decisions:
        latest = decisions[-1]
        note = latest["note"] or "No added note."
        parts.append(
            "<section class='card'><h2>Editor decision</h2><p><strong>"
            + esc(decision_name(latest))
            + "</strong> · "
            + esc(round_label(latest["round_no"]))
            + "</p><p class='prose'>"
            + esc(note)
            + "</p></section>"
        )
    reports = conn.execute(
        """SELECT r.*, a.round_no, f.id AS report_file, f.original_name
           FROM reports r
           JOIN assignments a ON a.id = r.assignment_id
           LEFT JOIN files f ON f.id = r.file_id
           WHERE a.work_id = ?
           ORDER BY a.round_no, r.created_at""",
        (work["id"],),
    ).fetchall()
    if reports:
        blocks = ["<section class='card'><h2>Reviewer reports</h2><p class='muted'>Reviewer names are hidden.</p>"]
        current = None
        index = 0
        for report in reports:
            if report["round_no"] != current:
                current = report["round_no"]
                index = 1
                blocks.append(f"<h3>{esc(round_label(current))}</h3>")
            else:
                index += 1
            link = ""
            if report["report_file"]:
                link = f" <a href='{keep(user, '/files/' + report['report_file'])}'>Report file</a>"
            blocks.append(
                "<div class='review'><strong>Report "
                + str(index)
                + " · "
                + esc(RECOMMENDATIONS[report["recommendation"]])
                + "</strong>"
                + link
                + "<p class='prose'>"
                + esc(report["comments"] or ("The comments are in the report file." if report["report_file"] else "No written comments."))
                + "</p></div>"
            )
        blocks.append("</section>")
        parts.append("".join(blocks))
    parts.append("<section class='card'><h2>Files</h2>" + file_links(conn, user, work) + "</section>")
    if work["status"] == "revision":
        parts.append(
            "<section class='card'><h2>Upload the revision</h2>"
            "<p class='muted'>The revised PDF must not show the authors. The response is a separate file and is not printed in the issue.</p>"
            "<form class='form-grid' method='post' action='/works/"
            + esc(work["id"])
            + "/revision' enctype='multipart/form-data'>"
            + csrf_input(user)
            + "<label>Revised anonymous PDF<input name='manuscript' type='file' accept='application/pdf,.pdf' required></label>"
            + "<label>Response file<span class='hint'>PDF or .txt. Or type a short response below.</span>"
            + "<input name='response_file' type='file' accept='application/pdf,.pdf,text/plain,.txt'></label>"
            + "<label>Short response<textarea name='response_text'></textarea></label>"
            + "<div class='actions'><button type='submit'>Upload revision</button></div></form></section>"
        )
    if work["status"] == "accepted":
        parts.append(
            "<section class='card'><h2>Upload the final PDF</h2>"
            "<p class='muted'>This file may show the author names. Do not add page numbers or a running header. The workshop adds those when the issue is produced.</p>"
            "<form class='form-grid' method='post' action='/works/"
            + esc(work["id"])
            + "/final' enctype='multipart/form-data'>"
            + csrf_input(user)
            + "<label>Final PDF<input name='manuscript' type='file' accept='application/pdf,.pdf' required></label>"
            + "<div class='actions'><button type='submit'>Upload final PDF</button></div></form></section>"
        )
    parts.append("</div>")
    return "".join(parts)


def declined_without_replacement(rows) -> list:
    replaced = {row["replaces_id"] for row in rows if row["replaces_id"]}
    return [row for row in rows if row["response"] == "declined" and row["id"] not in replaced]


def reviewer_work(conn, user, work) -> str:
    assignments = conn.execute(
        """SELECT a.*, r.id AS report_id, r.recommendation, r.comments, r.editor_note, r.created_at AS reported_at
           FROM assignments a
           LEFT JOIN reports r ON r.assignment_id = a.id
           WHERE a.work_id = ? AND a.reviewer_id = ?
           ORDER BY a.round_no""",
        (work["id"], user["id"]),
    ).fetchall()
    agreed = [row for row in assignments if row["response"] == "agreed"]
    pending_now = [
        row for row in assignments
        if row["response"] == "pending"
        and work["status"] == "in_review"
        and row["round_no"] == work["revision_count"]
    ]
    can_read = [
        row for row in assignments
        if row["response"] == "agreed" or (row["response"] == "pending" and work["status"] == "in_review")
    ]
    parts = ["<div class='stack'>"]
    if pending_now:
        parts.append(
            "<p class='lede'>Read the anonymous PDF, then agree or decline. "
            "The authors are hidden. If you decline, the chief editor will ask someone else.</p>"
        )
    elif agreed:
        parts.append(
            "<p class='lede'>The authors are hidden. Download the paper and upload your report. "
            "Your recommendation does not decide the paper, and your name is hidden from the authors.</p>"
        )
    else:
        parts.append("<p class='lede'>You declined this review. The chief editor will ask someone else.</p>")
    if can_read:
        if work["article_type"]:
            parts.append(f"<p class='muted'>{esc(work['article_type'])}</p>")
        if work["abstract_text"]:
            parts.append("<section class='card'><h2>Abstract</h2><p class='prose'>" + esc(work["abstract_text"]) + "</p></section>")
        if work["keywords"]:
            parts.append("<p><strong>Keywords.</strong> " + esc(work["keywords"]) + "</p>")
        parts.append("<section class='card'><h2>Files for you</h2>" + file_links(conn, user, work, {"anonymous", "response"}) + "</section>")
    for assignment in assignments:
        parts.append("<section class='card'><h2>" + esc(round_label(assignment["round_no"])) + "</h2>")
        if assignment["response"] == "pending" and work["status"] == "in_review" and assignment["round_no"] == work["revision_count"]:
            parts.append(
                "<p>Will you review this paper?</p><div class='actions'>"
                "<form method='post' action='/works/"
                + esc(work["id"])
                + "/agree'>"
                + csrf_input(user)
                + "<button type='submit'>Agree to review</button></form>"
                "<form method='post' action='/works/"
                + esc(work["id"])
                + "/decline'>"
                + csrf_input(user)
                + "<button class='secondary' type='submit'>Decline to review</button></form></div>"
            )
        elif assignment["response"] == "declined":
            parts.append("<p class='note'>You declined. The chief editor will ask someone else.</p>")
        elif assignment["report_id"]:
            parts.append(
                "<p class='note'>You sent this report: <strong>"
                + esc(RECOMMENDATIONS[assignment["recommendation"]])
                + "</strong></p>"
            )
            if assignment["comments"]:
                parts.append("<p class='muted'>Comments for the author</p><p class='prose'>" + esc(assignment["comments"]) + "</p>")
            if assignment["editor_note"]:
                parts.append(
                    "<p class='muted'>Note to the chief editor. The author does not see this.</p><p class='prose'>"
                    + esc(assignment["editor_note"])
                    + "</p>"
                )
        elif assignment["response"] == "agreed" and work["status"] == "in_review" and assignment["round_no"] == work["revision_count"]:
            parts.append(
                "<form class='form-grid' method='post' action='/works/"
                + esc(work["id"])
                + "/report' enctype='multipart/form-data'>"
                + csrf_input(user)
                + "<label>Recommendation<select name='recommendation' required>"
                + "<option value=''>Choose</option><option value='accept'>Accept</option>"
                + "<option value='revise'>Revise</option><option value='reject'>Reject</option></select></label>"
                + "<label>Comments for the author<span class='hint'>The author sees this. Do not write your name.</span>"
                + "<textarea name='comments'></textarea></label>"
                + "<label>Note to the chief editor<span class='hint'>Only the chief editor sees this. The author does not.</span>"
                + "<textarea name='editor_note'></textarea></label>"
                + "<label>Report PDF<span class='hint'>Optional. The author can open this file. Do not put your name in it, or a private note to the chief editor.</span>"
                + "<input name='report' type='file' accept='application/pdf,.pdf'></label>"
                + "<div class='actions'><button type='submit'>Send report</button></div></form>"
            )
        else:
            parts.append("<p class='muted'>This round is closed.</p>")
        parts.append("</section>")
    parts.append("</div>")
    return "".join(parts)


def chief_work(conn, user, work) -> str:
    member = conn.execute("SELECT name, email FROM accounts WHERE id = ?", (work["member_id"],)).fetchone()
    assignments = conn.execute(
        """SELECT a.*, p.name AS reviewer_name, p.email AS reviewer_email,
                  r.recommendation, r.comments, r.editor_note, r.created_at AS reported_at, r.file_id
           FROM assignments a
           JOIN accounts p ON p.id = a.reviewer_id
           LEFT JOIN reports r ON r.assignment_id = a.id
           WHERE a.work_id = ?
           ORDER BY a.round_no, p.name""",
        (work["id"],),
    ).fetchall()
    parts = ["<div class='stack'>", f"<p>{status_pill(work['status'])}</p>"]
    authors = esc(work["author_name"])
    if work["coauthors"]:
        authors += "<br>" + esc(work["coauthors"]).replace("\n", "<br>")
    parts.append(
        "<section class='card'><h2>Authors</h2><p>"
        + authors
        + "</p><p class='muted'>"
        + esc(work["author_email"])
        + " · "
        + esc(work["author_affiliation"])
        + "</p><p class='muted'>Uploaded by "
        + esc(member["name"] if member else "")
        + " · "
        + esc(pretty_date(work["created_at"]))
        + "</p>"
        + (f"<p class='prose'>{esc(work['abstract_text'])}</p>" if work["abstract_text"] else "")
        + "</section>"
    )
    parts.append("<section class='card'><h2>Files</h2>" + file_links(conn, user, work) + "</section>")
    if assignments:
        blocks = ["<section class='card'><h2>Reviewers</h2><p class='muted'>Only you can see these names.</p>"]
        current = None
        for row in assignments:
            if row["round_no"] != current:
                current = row["round_no"]
                blocks.append("<h3>" + esc(round_label(current)) + "</h3>")
            if row["response"] == "declined":
                detail = f"<p>{esc(row['reviewer_name'])} · <span class='muted'>Declined to review</span></p>"
            elif row["response"] == "pending":
                detail = f"<p>{esc(row['reviewer_name'])} · <span class='muted'>Waiting for a reply</span></p>"
            elif row["recommendation"]:
                detail = (
                    "<div class='review'><strong>"
                    + esc(row["reviewer_name"])
                    + "</strong> · "
                    + esc(RECOMMENDATIONS[row["recommendation"]])
                    + (f" · <a href='{keep(user, '/files/' + row['file_id'])}'>Report file</a>" if row["file_id"] else "")
                    + "<p class='prose'>"
                    + esc(row["comments"] or ("The comments are in the report file." if row["file_id"] else "No written comments."))
                    + "</p>"
                    + (
                        "<p class='muted'>Note to you. The author does not see this.</p><p class='prose'>"
                        + esc(row["editor_note"])
                        + "</p>"
                        if row["editor_note"]
                        else ""
                    )
                    + "</div>"
                )
            else:
                detail = f"<p>{esc(row['reviewer_name'])} · <span class='muted'>Agreed · report not in yet</span></p>"
            blocks.append(detail)
        blocks.append("</section>")
        parts.append("".join(blocks))
    this_round = [row for row in assignments if row["round_no"] == work["revision_count"]]
    active = [row for row in this_round if row["response"] != "declined"]
    reports_in = [row for row in active if row["recommendation"]]
    pending = [row for row in active if row["response"] == "pending"]
    declines = declined_without_replacement(this_round)
    anyone_replied = any(row["response"] != "pending" for row in this_round)
    if work["status"] == "submitted":
        reviewers = conn.execute(
            "SELECT id, name, email, affiliation FROM accounts WHERE role = 'reviewer' ORDER BY name"
        ).fetchall()
        if len(reviewers) < 2:
            parts.append("<p class='warnbox'>Create at least two reviewer accounts before assigning this paper.</p>")
        elif file_row(conn, work["id"], "anonymous", work["revision_count"]) is None:
            parts.append("<p class='warnbox'>The anonymous PDF for this round is not here yet.</p>")
        else:
            choices = []
            for reviewer in reviewers:
                label = reviewer["name"]
                if reviewer["affiliation"]:
                    label += " · " + reviewer["affiliation"]
                choices.append(
                    "<label class='check'><input type='checkbox' name='reviewer_id' value='"
                    + esc(reviewer["id"])
                    + "'> "
                    + esc(label)
                    + "</label>"
                )
            parts.append(
                "<section class='card'><h2>Assign reviewers</h2>"
                "<p class='muted'>Choose 2 or 3. Each reviewer can read the anonymous PDF, then agree or decline. "
                "If someone declines, you choose a replacement.</p>"
                "<form class='form-grid' method='post' action='/works/"
                + esc(work["id"])
                + "/assign'>"
                + csrf_input(user)
                + "<div class='choices'>"
                + "".join(choices)
                + "</div><div class='actions'><button type='submit'>Assign</button></div></form></section>"
            )
        parts.append(
            "<section class='card'><h2>Desk reject</h2>"
            "<p class='muted'>Reject this paper before it goes to reviewers. The author sees your note.</p>"
            "<form class='form-grid' method='post' action='/works/"
            + esc(work["id"])
            + "/desk'>"
            + csrf_input(user)
            + "<label>Note for the author<textarea name='note'></textarea></label>"
            + "<div class='actions'><button class='warn' type='submit'>Desk reject</button></div></form></section>"
        )
    if work["status"] == "in_review" and declines:
        open_ids = [row["reviewer_id"] for row in this_round]
        marks = ",".join("?" for _ in open_ids)
        available = conn.execute(
            f"""SELECT id, name, email FROM accounts
                WHERE role = 'reviewer' AND id NOT IN ({marks})
                ORDER BY name""",
            open_ids,
        ).fetchall()
        forms = []
        for row in declines:
            if not available:
                forms.append(
                    "<p class='warnbox'>Create another reviewer in People, then choose a replacement for "
                    + esc(row["reviewer_name"])
                    + ".</p>"
                )
                continue
            options = "".join(
                "<option value='"
                + esc(person["id"])
                + "'>"
                + esc(person["name"])
                + " · "
                + esc(person["email"])
                + "</option>"
                for person in available
            )
            forms.append(
                "<form class='form-grid' method='post' action='/works/"
                + esc(work["id"])
                + "/replace'>"
                + csrf_input(user)
                + "<input type='hidden' name='declined_id' value='"
                + esc(row["id"])
                + "'>"
                + "<label>Replacement for "
                + esc(row["reviewer_name"])
                + "<select name='reviewer_id' required><option value=''>Choose</option>"
                + options
                + "</select></label><div class='actions'><button type='submit'>Assign replacement</button></div></form>"
            )
        parts.append(
            "<section class='card'><h2>Choose a replacement</h2>"
            "<p class='muted'>A reviewer declined. The paper stays with the reviewers who agreed, "
            "and the new reviewer can agree or decline too.</p>"
            + "".join(forms)
            + "</section>"
        )
    if work["status"] == "in_review":
        options = ["<option value='accept'>Accept</option>", "<option value='reject'>Reject</option>"]
        warning = ""
        if work["revision_count"] < 3:
            options.insert(1, "<option value='revise'>Revise</option>")
        else:
            warning = (
                "<p class='warnbox'>This is the third revision. Choose Accept or Reject. "
                "If it still needs work, reject it and ask the author to submit it as a new paper. "
                "The old files stay on this closed paper.</p>"
            )
        reviews_finished = (
            active
            and not pending
            and not declines
            and len(active) in (2, 3)
            and len(reports_in) == len(active)
        )
        early = ""
        if not reviews_finished:
            early = (
                "<p class='muted'>You can decide before every review is in. "
                "Reports that are already here stay in the record.</p>"
            )
        parts.append(
            "<section class='card'><h2>Your decision</h2>"
            + warning
            + early
            + "<form class='form-grid' method='post' action='/works/"
            + esc(work["id"])
            + "/decision'>"
            + csrf_input(user)
            + "<label>Decision<select name='decision' required><option value=''>Choose</option>"
            + "".join(options)
            + "</select></label><label>Note for the author<textarea name='note'></textarea></label>"
            + "<div class='actions'><button type='submit'>Record decision</button></div></form></section>"
        )
    if work["status"] == "in_review" and this_round and not reports_in and not anyone_replied:
        parts.append(
            "<form method='post' action='/works/"
            + esc(work["id"])
            + "/clear'>"
            + csrf_input(user)
            + "<button class='secondary' type='submit'>Choose different reviewers</button></form>"
        )
    elif work["status"] == "in_review" and active:
        parts.append(
            f"<p class='muted'>{len(reports_in)} of {len(active)} reports are in.</p>"
        )
    decisions = conn.execute(
        "SELECT * FROM decisions WHERE work_id = ? ORDER BY created_at",
        (work["id"],),
    ).fetchall()
    if decisions:
        lines = []
        for decision in decisions:
            lines.append(
                "<div class='review'><strong>"
                + esc(decision_name(decision))
                + "</strong> · "
                + esc(round_label(decision["round_no"]))
                + " · "
                + esc(pretty_date(decision["created_at"]))
                + "<p class='prose'>"
                + esc(decision["note"])
                + "</p></div>"
            )
        parts.append("<section class='card'><h2>Decisions</h2>" + "".join(lines) + "</section>")
    parts.append("</div>")
    return "".join(parts)


def produce_page(conn, user) -> str:
    issue = current_issue(conn)
    problems = produce_problems(conn)
    accepted = conn.execute(
        """SELECT * FROM works WHERE status = 'accepted'
           ORDER BY paper_no, title"""
    ).fetchall()
    rows = []
    for work in accepted:
        final = file_row(conn, work["id"], "final")
        pages = ""
        if final:
            try:
                pages = f"{count_pages(stored_path(final['stored_name']))} pages"
            except AppError as err:
                pages = str(err)
        rows.append(
            "<li><strong>"
            + esc(paper_code(issue, work))
            + "</strong> · "
            + esc(work["title"])
            + (f" <span class='muted'>{esc(pages)}</span>" if pages else "")
            + "</li>"
        )
    problem_html = ""
    if problems:
        problem_html = "<div class='warnbox'><ul class='checklist'>" + "".join(
            f"<li>{esc(item)}</li>" for item in problems
        ) + "</ul></div>"
    form = ""
    if not problems and accepted:
        form = (
            "<form class='form-grid' method='post' action='/produce'>"
            + csrf_input(user)
            + "<p class='muted'>Articles are bound in number order. The header on every page will read: "
            + esc(header_line(issue))
            + ", followed by the page number.</p>"
            + "<ol class='checklist'>"
            + "".join(rows)
            + "</ol>"
            + "<label>Starting page of the first article"
            + "<span class='hint'>The next article continues on the following page.</span>"
            + "<input name='start_page' value='1' required></label>"
            + "<div class='actions'><button type='submit'>Produce the issue</button></div></form>"
        )
    elif not accepted and not problems:
        problem_html = "<p class='warnbox'>Accept at least one paper before producing the issue.</p>"
    inner = (
        "<p><a href='" + keep(user, "/") + "'>Back</a></p><div class='stack'><section class='card'><h2>Bind this issue</h2>"
        "<p>Accepted papers are stamped with the journal header and continuous page numbers. "
        "Rejected papers stay in the confidential history and are left out of the issue.</p>"
        + problem_html
        + form
        + "</section></div>"
    )
    return layout("Produce the issue", inner, user, issue)


def produce_problems(conn) -> list[str]:
    problems = []
    busy = conn.execute(
        """SELECT title, status FROM works
           WHERE status IN ('submitted', 'in_review', 'revision') ORDER BY created_at"""
    ).fetchall()
    for row in busy:
        problems.append(f"{row['title']} is still {STATUSES[row['status']].lower()}.")
    accepted = conn.execute("SELECT id, title FROM works WHERE status = 'accepted'").fetchall()
    if not busy and not accepted:
        problems.append("Accept at least one paper before producing the issue.")
    for row in accepted:
        if file_row(conn, row["id"], "final") is None:
            problems.append(f"{row['title']} needs its final PDF.")
    return problems


def count_pages(path: Path) -> int:
    try:
        from pypdf import PdfReader
    except ImportError as err:
        raise AppError("The page-number tool is not installed. Close this window and start again with start.bat.") from err
    reader = PdfReader(str(path))
    if reader.is_encrypted and reader.decrypt("") == 0:
        raise AppError("A final PDF is password-protected. Ask the author for an open PDF.")
    if not reader.pages:
        raise AppError("A final PDF has no pages.")
    return len(reader.pages)


def overlay_bytes(width: float, height: float, header: str, number: str) -> bytes:
    def pdf_escape(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def text_width(text: str, size: float) -> float:
        total = 0.0
        for char in text:
            if char == " ":
                total += 0.28
            elif char.isupper() or char.isdigit():
                total += 0.62
            else:
                total += 0.5
        return total * size

    header_size = 9
    number_size = 11
    header_y = height - 36
    number_width = text_width(number, number_size)
    number_x = max(28, width - 36 - number_width)
    header_room = max(40, number_x - 16)
    header_width = text_width(header, header_size)
    header_x = max(28, min((width - header_width) / 2, header_room - header_width))
    stream = (
        f"BT /F1 {header_size} Tf 0.15 0.2 0.16 rg {header_x:.2f} {header_y:.2f} Td ({pdf_escape(header)}) Tj ET\n"
        f"BT /F1 {number_size} Tf 0 0 0 rg {number_x:.2f} {header_y:.2f} Td ({pdf_escape(number)}) Tj ET\n"
    ).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width:.2f} {height:.2f}] "
            "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ).encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{index} 0 obj\n".encode("ascii"))
        out.extend(obj)
        out.extend(b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("ascii")
    )
    return bytes(out)


def stamp_pdf(source: Path, dest: Path, header: str, start_page: int) -> int:
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError as err:
        raise AppError("The page-number tool is not installed. Close this window and start again with start.bat.") from err
    reader = PdfReader(str(source))
    if reader.is_encrypted and reader.decrypt("") == 0:
        raise AppError("A final PDF is password-protected. Ask the author for an open PDF.")
    writer = PdfWriter()
    for index, page in enumerate(reader.pages):
        box = page.mediabox
        overlay = PdfReader(
            BytesIO(overlay_bytes(float(box.width), float(box.height), header, str(start_page + index)))
        ).pages[0]
        page.merge_page(overlay)
        writer.add_page(page)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as handle:
        writer.write(handle)
    return len(reader.pages)


def produce_issue(conn, user, fields) -> str:
    if user["role"] != "chief":
        raise AppError("Only the chief editor can produce the issue.")
    issue = current_issue(conn)
    if issue is None:
        raise AppError("The issue is not set up yet.")
    problems = produce_problems(conn)
    if problems:
        raise AppError(problems[0])
    raw = field(fields, "start_page").strip()
    try:
        start_page = int(raw)
    except ValueError:
        raise AppError("The starting page needs a whole number.")
    if start_page < 1 or start_page > 10000:
        raise AppError("The starting page needs a whole number.")
    accepted = conn.execute(
        """SELECT * FROM works WHERE status = 'accepted'
           ORDER BY paper_no, title"""
    ).fetchall()
    if not accepted:
        raise AppError("Accept at least one paper before producing the issue.")
    folder_name = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = data_root() / "productions" / folder_name
    header = header_line(issue)
    ranges = []
    page_no = start_page
    for index, work in enumerate(accepted, start=1):
        final = file_row(conn, work["id"], "final")
        if final is None:
            raise AppError(f"{work['title']} needs its final PDF.")
        stamped_name = f"{index:02d}.pdf"
        count = stamp_pdf(stored_path(final["stored_name"]), folder / "stamped" / stamped_name, header, page_no)
        ranges.append((work, page_no, page_no + count - 1, stamped_name))
        page_no += count
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError as err:
        raise AppError("The page-number tool is not installed. Close this window and start again with start.bat.") from err
    issue_writer = PdfWriter()
    for _work, _start, _end, stamped_name in ranges:
        for page in PdfReader(str(folder / "stamped" / stamped_name)).pages:
            issue_writer.add_page(page)
    with (folder / "issue.pdf").open("wb") as handle:
        issue_writer.write(handle)
    copy_history(conn, folder)
    (folder / "record.html").write_text(
        history_html(conn, issue, user, ranges, page_no - 1),
        encoding="utf-8",
    )
    production_id = new_id()
    conn.execute(
        """INSERT INTO productions (id, folder_name, page_count, paper_count, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (production_id, folder_name, page_no - 1, len(accepted), now()),
    )
    return production_id


def copy_history(conn, folder: Path) -> None:
    works = conn.execute("SELECT * FROM works ORDER BY created_at").fetchall()
    for work in works:
        target = folder / "history" / work["id"]
        target.mkdir(parents=True, exist_ok=True)
        files = conn.execute("SELECT * FROM files WHERE work_id = ?", (work["id"],)).fetchall()
        for row in files:
            source = stored_path(row["stored_name"])
            if not source.is_file():
                continue
            suffix = Path(row["original_name"]).suffix.lower() or ".bin"
            if suffix not in (".pdf", ".txt"):
                suffix = ".bin"
            name = f"{row['kind']}-round-{row['round_no']}-{row['id']}{suffix}"
            shutil.copyfile(source, target / name)


def history_html(conn, issue, user, ranges, page_count: int) -> str:
    works = conn.execute("SELECT * FROM works ORDER BY created_at").fetchall()
    accepted_ids = {work["id"] for work, *_rest in ranges}
    submitted = len(works)
    accepted = sum(1 for work in works if work["status"] == "accepted")
    rejected = sum(1 for work in works if work["status"] == "rejected")
    range_by_id = {work["id"]: (start, end, name) for work, start, end, name in ranges}
    editor = None
    try:
        editor = conn.execute("SELECT name, email FROM editor WHERE id = 1").fetchone()
    except sqlite3.OperationalError:
        editor = None
    editor_line = esc(user["name"])
    if editor:
        editor_line = esc(editor["name"]) + " · " + esc(editor["email"])
    paper_blocks = []
    for work in works:
        files = conn.execute(
            "SELECT * FROM files WHERE work_id = ? ORDER BY round_no, created_at",
            (work["id"],),
        ).fetchall()
        file_items = []
        for row in files:
            suffix = Path(row["original_name"]).suffix.lower() or ".bin"
            if suffix not in (".pdf", ".txt"):
                suffix = ".bin"
            href = f"history/{work['id']}/{row['kind']}-round-{row['round_no']}-{row['id']}{suffix}"
            if row["kind"] == "final":
                file_label = "Final PDF"
            else:
                file_label = row["kind"] + " · " + round_label(row["round_no"])
            item = (
                f"<li><a href='{esc(href)}'>{esc(file_label)}</a> · {esc(pretty_date(row['created_at']))}</li>"
            )
            if row["kind"] == "response" and str(row["original_name"]).lower().endswith(".txt"):
                source = stored_path(row["stored_name"])
                if source.is_file():
                    item += "<pre>" + esc(source.read_text("utf-8", "replace")[:8000]) + "</pre>"
            file_items.append(item)
        assignments = conn.execute(
            """SELECT a.round_no, a.response, a.responded_at, a.created_at AS assigned_at,
                      p.name AS reviewer_name,
                      r.recommendation, r.comments, r.editor_note, r.created_at AS reported_at, r.file_id
               FROM assignments a
               JOIN accounts p ON p.id = a.reviewer_id
               LEFT JOIN reports r ON r.assignment_id = a.id
               WHERE a.work_id = ?
               ORDER BY a.round_no, p.name""",
            (work["id"],),
        ).fetchall()
        decisions = conn.execute(
            "SELECT * FROM decisions WHERE work_id = ? ORDER BY round_no, created_at",
            (work["id"],),
        ).fetchall()
        decision_by_round = {row["round_no"]: row for row in decisions}
        rounds: dict[int, list] = {}
        for row in assignments:
            rounds.setdefault(row["round_no"], []).append(row)
        round_html = []
        for round_no in sorted(set(list(rounds) + list(decision_by_round))):
            lines = [f"<h3>{esc(round_label(round_no))}</h3><ul>"]
            for row in rounds.get(round_no, []):
                if row["response"] == "declined":
                    lines.append(
                        "<li>"
                        + esc(row["reviewer_name"])
                        + " declined to review on "
                        + esc(pretty_date(row["responded_at"]))
                        + ".</li>"
                    )
                elif row["recommendation"]:
                    lines.append(
                        "<li>"
                        + esc(row["reviewer_name"])
                        + " recommended "
                        + esc(RECOMMENDATIONS[row["recommendation"]])
                        + " on "
                        + esc(pretty_date(row["reported_at"]))
                        + (
                            "<br>To the author: " + esc(row["comments"])
                            if row["comments"]
                            else ""
                        )
                        + (
                            "<br>To the chief editor, not shown to the author: " + esc(row["editor_note"])
                            if row["editor_note"]
                            else ""
                        )
                        + "</li>"
                    )
                elif row["response"] == "agreed":
                    lines.append("<li>" + esc(row["reviewer_name"]) + " agreed and did not send a report.</li>")
                else:
                    lines.append("<li>" + esc(row["reviewer_name"]) + " has not replied.</li>")
            lines.append("</ul>")
            decision = decision_by_round.get(round_no)
            if decision:
                lines.append(
                    "<p><strong>Editor decision:</strong> "
                    + esc(decision_name(decision))
                    + " on "
                    + esc(pretty_date(decision["created_at"]))
                    + "</p><p>"
                    + esc(decision["note"])
                    + "</p>"
                )
            round_html.append("".join(lines))
        pages = ""
        if work["id"] in range_by_id:
            start, end, name = range_by_id[work["id"]]
            span = f"page {start}" if start == end else f"pages {start}–{end}"
            pages = f"<p><strong>Pages in this issue:</strong> {span}. <a href='stamped/{esc(name)}'>Stamped PDF</a></p>"
        elif work["id"] not in accepted_ids:
            pages = "<p>This paper is not in the bound issue.</p>"
        paper_blocks.append(
            "<section><h2>"
            + esc(paper_code(issue, work))
            + " · "
            + esc(work["title"])
            + "</h2><p><strong>Status:</strong> "
            + esc(STATUSES[work["status"]])
            + " · "
            + esc(work["article_type"])
            + "</p><p><strong>Authors:</strong> "
            + esc(work["author_name"])
            + "</p><p><strong>Email:</strong> "
            + esc(work["author_email"])
            + " · <strong>Affiliation:</strong> "
            + esc(work["author_affiliation"])
            + "</p><p><strong>Coauthors:</strong> "
            + esc(work["coauthors"] or "None")
            + "</p><p><strong>Submitted:</strong> "
            + esc(pretty_date(work["created_at"]))
            + "</p><p>"
            + esc(work["abstract_text"])
            + "</p>"
            + pages
            + "<h3>Files</h3><ul>"
            + "".join(file_items)
            + "</ul>"
            + "".join(round_html)
            + "</section>"
        )
    accepted_lines = []
    for work, start, end, name in ranges:
        span = f"page {start}" if start == end else f"pages {start}–{end}"
        accepted_lines.append(
            f"<li>{esc(paper_code(issue, work))} · {esc(work['title'])}: {span} (<a href='stamped/{esc(name)}'>PDF</a>)</li>"
        )
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Confidential issue record</title>"
        "<style>body{font:16px/1.5 Georgia,serif;max-width:820px;margin:32px auto;color:#1e1a16}"
        "a{color:#1d4a38} section{border-top:1px solid #e2d9cc;margin-top:24px;padding-top:8px}"
        ".warn{background:#f8efdc;padding:12px 14px}</style></head><body>"
        "<p class='warn'><strong>Confidential.</strong> This history stays with the workshop. "
        "It is not part of the public issue and must not be published.</p>"
        "<h1>"
        + esc(header_line(issue))
        + "</h1><p><strong>Chief editor:</strong> "
        + editor_line
        + "</p><p><strong>Opened:</strong> "
        + esc(pretty_date(issue["opened_at"]))
        + " · <strong>Produced:</strong> "
        + esc(pretty_date(now()))
        + "</p><p><strong>Submitted:</strong> "
        + str(submitted)
        + " · <strong>Accepted:</strong> "
        + str(accepted)
        + " · <strong>Rejected:</strong> "
        + str(rejected)
        + " · <strong>Pages:</strong> "
        + str(page_count)
        + "</p><p><a href='issue.pdf'>Bound issue PDF</a></p><h2>Accepted papers</h2><ol>"
        + "".join(accepted_lines)
        + "</ol><h2>Every paper</h2>"
        + "".join(paper_blocks)
        + "</body></html>"
    )


def login_page(message: str = "", issue=None) -> str:
    note = f"<p class='error'>{esc(message)}</p>" if message else ""
    inner = (
        "<div class='stack'><p class='lede'>The chief editor, members, and reviewers each sign in here.</p>"
        + note
        + "<form class='form-grid card' method='post' action='/login'>"
        + "<label>Email<input name='email' type='email' required></label>"
        + "<label>Password<input name='password' type='password' required></label>"
        + "<div class='actions'><button type='submit'>Sign in</button></div></form></div>"
    )
    return layout("Sign in", inner, None, issue)


def setup_page(conn) -> str:
    inner = (
        "<div class='stack'><p class='lede'>Create the chief editor for this workshop. This screen is used once.</p>"
        "<form class='form-grid card' method='post' action='/setup'>"
        "<label>Your name<input name='name' required></label>"
        "<label>Email<input name='email' type='email' required></label>"
        "<label>Password<span class='hint'>At least 8 characters.</span><input name='password' type='password' required></label>"
        "<label>Journal or proceeding name<input name='journal_name' value='JoSIER' required></label>"
        "<label>Volume<span class='hint'>Optional.</span><input name='volume'></label>"
        "<label>Issue<span class='hint'>Optional. Leave both blank for a conference proceeding.</span><input name='issue_number'></label>"
        "<div class='actions'><button type='submit'>Create the workshop</button></div></form></div>"
    )
    return layout("Set up the workshop", inner, None, current_issue(conn))


def cookie(token: str, clear: bool = False) -> str:
    secure = "; Secure" if os.environ.get("WORKSHOP_SECURE_COOKIE") == "1" else ""
    if clear:
        return "workshop=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" + secure
    return f"workshop={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200{secure}"


def content_type(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".pdf"):
        return "application/pdf"
    if lower.endswith(".txt"):
        return "text/plain; charset=utf-8"
    if lower.endswith(".html"):
        return "text/html; charset=utf-8"
    if lower.endswith(".css"):
        return "text/css; charset=utf-8"
    if lower.endswith(".js"):
        return "text/javascript; charset=utf-8"
    return "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    server_version = "IssueWorkshop"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def log_message(self, fmt: str, *args) -> None:
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def route(self, method: str) -> None:
        self.user = None
        self.issue = None
        try:
            with db() as conn:
                self.user = load_user(conn, self)
                self.issue = current_issue(conn)
                path = urlparse(self.path).path
                if method == "GET":
                    self.handle_get(conn, path)
                else:
                    self.handle_post(conn, path)
        except AppError as err:
            body = layout(
                "Please check",
                f"<p class='error'>{esc(err)}</p><p><a href='/'>Back</a></p>",
                self.user,
                self.issue,
            )
            self.send_html(body, 400)
        except Exception:
            traceback.print_exc()
            body = layout(
                "Please check",
                "<p class='error'>Something went wrong. Please try that again.</p><p><a href='/'>Back</a></p>",
                self.user,
                None,
            )
            self.send_html(body, 500)

    def handle_get(self, conn, path: str) -> None:
        if path.startswith("/static/"):
            self.send_static(path[len("/static/") :])
            return
        if path == "/favicon.ico":
            self.send_bytes(b"", "image/x-icon", "favicon.ico")
            return
        if account_count(conn) == 0:
            self.send_html(setup_page(conn))
            return
        if self.user is None:
            query = parse_qs(urlparse(self.path).query)
            self.user = user_by_token(conn, field(query, "s"))
        if self.user is None:
            self.send_html(login_page(issue=self.issue))
            return
        if path.startswith("/files/"):
            self.send_saved_file(conn, path.split("/")[2] if path.count("/") >= 2 else "")
            return
        if path.startswith("/productions/"):
            self.send_production(conn, path)
            return
        if path in ("/", ""):
            query = parse_qs(urlparse(self.path).query)
            self.send_html(
                home_page(
                    conn,
                    self.user,
                    field(query, "made"),
                    field(query, "saved"),
                    field(query, "heading"),
                    field(query, "fresh"),
                )
            )
            return
        if path == "/works/new":
            if self.user["role"] != "member":
                raise AppError("Only a member can upload a paper.")
            self.send_html(new_work_page(conn, self.user))
            return
        if path == "/produce":
            if self.user["role"] != "chief":
                raise AppError("Only the chief editor can produce the issue.")
            self.send_html(produce_page(conn, self.user))
            return
        if path == "/issue":
            if self.user["role"] != "chief":
                raise AppError("Only the chief editor can edit the heading.")
            self.send_html(issue_page(conn, self.user))
            return
        if path == "/issue/new":
            if self.user["role"] != "chief":
                raise AppError("Only the chief editor can start a new issue.")
            self.send_html(new_issue_page(conn, self.user))
            return
        if path == "/people":
            if self.user["role"] != "chief":
                raise AppError("Only the chief editor can open People.")
            self.send_html(people_page(conn, self.user))
            return
        if path in ("/people/member", "/people/reviewer"):
            if self.user["role"] != "chief":
                raise AppError("Only the chief editor can open People.")
            role = "member" if path.endswith("/member") else "reviewer"
            self.send_html(new_person_page(conn, self.user, role))
            return
        if path.startswith("/works/"):
            work_id = path.split("/")[2]
            work = load_work(conn, self.user, work_id)
            self.send_html(work_page(conn, self.user, work))
            return
        raise AppError("That page was not found.")

    def handle_post(self, conn, path: str) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > PDF_LIMIT + 1_000_000:
            raise AppError("That upload is too large.")
        body = self.rfile.read(length) if length else b""
        fields, files = parse_body(self.headers.get("Content-Type", ""), body)
        if self.user is None:
            self.user = user_by_token(conn, field(fields, "session"))
        if path == "/setup":
            self.create_workshop(conn, fields)
            return
        if path == "/login":
            self.sign_in(conn, fields)
            return
        require_csrf(self.user, fields)
        if path == "/logout":
            conn.execute("DELETE FROM signins WHERE token = ?", (self.user["token"],))
            self.user = None
            self.redirect("/", clear_cookie=True)
            return
        if path == "/accounts":
            self.create_account(conn, fields)
            return
        if path == "/works":
            self.create_work(conn, fields, files)
            return
        if path == "/produce":
            production_id = produce_issue(conn, self.user, fields)
            self.redirect("/?made=" + production_id)
            return
        if path == "/issue":
            self.update_issue(conn, fields)
            return
        if path == "/issue/new":
            self.begin_new_issue(conn, fields)
            return
        parts = [part for part in path.split("/") if part]
        if len(parts) == 3 and parts[0] == "accounts" and parts[2] == "remove":
            self.remove_account(conn, parts[1])
            return
        if len(parts) == 3 and parts[0] == "works":
            work = load_work(conn, self.user, parts[1])
            action = parts[2]
            if action == "revision":
                self.upload_revision(conn, work, fields, files)
            elif action == "final":
                self.upload_final(conn, work, files)
            elif action == "assign":
                self.assign_reviewers(conn, work, fields)
            elif action == "clear":
                self.clear_reviewers(conn, work)
            elif action == "agree":
                self.reply_to_review(conn, work, "agreed")
            elif action == "decline":
                self.reply_to_review(conn, work, "declined")
            elif action == "replace":
                self.replace_reviewer(conn, work, fields)
            elif action == "decision":
                self.record_decision(conn, work, fields)
            elif action == "desk":
                self.desk_reject(conn, work, fields)
            elif action == "report":
                self.record_report(conn, work, fields, files)
            else:
                raise AppError("That action was not found.")
            self.redirect("/works/" + work["id"])
            return
        raise AppError("That action was not found.")

    def create_workshop(self, conn, fields) -> None:
        if account_count(conn) != 0:
            raise AppError("The workshop is already set up.")
        name = required(field(fields, "name"), "Enter your name.", 200)
        email = clean_email(field(fields, "email"))
        password = clean_password(field(fields, "password"))
        journal, volume, issue_number = read_issue_heading(fields)
        digest = hash_password(password)
        conn.execute(
            "INSERT INTO editor (id, name, email, password_hash) VALUES (1, ?, ?, ?)",
            (name, email, digest),
        )
        conn.execute(
            "INSERT INTO issue (id, journal_name, volume, issue_number, opened_at) VALUES (1, ?, ?, ?, ?)",
            (journal, volume, issue_number, now()),
        )
        account_id = new_id()
        conn.execute(
            """INSERT INTO accounts (id, name, email, affiliation, password_hash, role, created_at)
               VALUES (?, ?, ?, '', ?, 'chief', ?)""",
            (account_id, name, email, digest, now()),
        )
        self.start_session(conn, account_id)

    def update_issue(self, conn, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can edit the heading.")
        journal, volume, issue_number = read_issue_heading(fields)
        conn.execute(
            "UPDATE issue SET journal_name = ?, volume = ?, issue_number = ? WHERE id = 1",
            (journal, volume, issue_number),
        )
        self.redirect("/?heading=1")

    def begin_new_issue(self, conn, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can start a new issue.")
        start_new_issue(conn, fields)
        self.redirect("/?fresh=1")

    def sign_in(self, conn, fields) -> None:
        email = clean_email(field(fields, "email"))
        password = field(fields, "password")
        account = conn.execute(
            "SELECT * FROM accounts WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
        if account is None or not check_password(password, account["password_hash"]):
            raise AppError("That email or password does not match.")
        self.start_session(conn, account["id"])

    def start_session(self, conn, account_id: str) -> None:
        token = secrets.token_urlsafe(24)
        csrf = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO signins (token, account_id, csrf, created_at) VALUES (?, ?, ?, ?)",
            (token, account_id, csrf, now()),
        )
        conn.commit()
        account = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        self.user = {
            "token": token,
            "csrf": csrf,
            "id": account["id"],
            "name": account["name"],
            "email": account["email"],
            "affiliation": account["affiliation"],
            "role": account["role"],
        }
        target = keep(self.user, "/")
        body = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            + f"<meta http-equiv='refresh' content='0;url={target}'>"
            + f"<script>location.replace('{target}')</script></head>"
            + f"<body><p><a href='{target}'>Continue</a></p></body></html>"
        )
        self.send_html(body, token=token)

    def create_account(self, conn, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can create accounts.")
        role = field(fields, "role")
        if role not in ("member", "reviewer"):
            raise AppError("Choose member or reviewer.")
        name = required(field(fields, "name"), "Enter the person's name.", 200)
        email = clean_email(field(fields, "email"))
        affiliation = optional(field(fields, "affiliation"), 300)
        password = clean_password(field(fields, "password"))
        exists = conn.execute(
            "SELECT id FROM accounts WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
        if exists:
            raise AppError("That email is already signed up.")
        conn.execute(
            """INSERT INTO accounts (id, name, email, affiliation, password_hash, role, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (new_id(), name, email, affiliation, hash_password(password), role, now()),
        )
        conn.commit()
        self.send_html(people_page(conn, self.user, name, role), token=self.user["token"])

    def remove_account(self, conn, account_id: str) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can remove an account.")
        account = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        if account is None or account["role"] == "chief":
            raise AppError("That account cannot be removed.")
        if conn.execute("SELECT 1 FROM works WHERE member_id = ?", (account_id,)).fetchone():
            raise AppError("This person already has a paper, so the account stays.")
        if conn.execute("SELECT 1 FROM assignments WHERE reviewer_id = ?", (account_id,)).fetchone():
            raise AppError("This person already has a review, so the account stays.")
        conn.execute("DELETE FROM signins WHERE account_id = ?", (account_id,))
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.commit()
        self.send_html(people_page(conn, self.user), token=self.user["token"])

    def create_work(self, conn, fields, files) -> None:
        if self.user["role"] != "member":
            raise AppError("Only a member can upload a paper.")
        title = required(field(fields, "title"), "Enter the title.", 500)
        article_type = optional(field(fields, "article_type"), 100)
        author_name = required(field(fields, "author_name"), "Enter the author names.", 500)
        author_email = clean_email(field(fields, "author_email"))
        affiliation = required(field(fields, "author_affiliation"), "Enter the affiliation.", 300)
        coauthors = optional(field(fields, "coauthors"), 2000)
        abstract_text = required(field(fields, "abstract_text"), "Enter the abstract.", 8000)
        keywords = optional(field(fields, "keywords"), 500)
        original, data = require_pdf(files.get("manuscript"), "anonymous PDF")
        work_id = new_id()
        moment = now()
        paper_no = next_paper_no(conn)
        conn.execute(
            """INSERT INTO works
               (id, member_id, title, article_type, author_name, author_email, author_affiliation,
                coauthors, abstract_text, keywords, status, revision_count, paper_no, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted', 0, ?, ?, ?)""",
            (
                work_id,
                self.user["id"],
                title,
                article_type,
                author_name,
                author_email,
                affiliation,
                coauthors,
                abstract_text,
                keywords,
                paper_no,
                moment,
                moment,
            ),
        )
        save_file(conn, self.user, work_id, "anonymous", 0, original, data)
        self.redirect("/works/" + work_id)

    def upload_revision(self, conn, work, fields, files) -> None:
        if self.user["role"] != "member" or work["member_id"] != self.user["id"]:
            raise AppError("Only the member who uploaded this paper can revise it.")
        if work["status"] != "revision":
            raise AppError("The chief editor has not asked for a revision.")
        if work["revision_count"] < 1 or work["revision_count"] > 3:
            raise AppError("This paper cannot take another revision.")
        original, data = require_pdf(files.get("manuscript"), "revised PDF")
        response_name, response_data = require_response(files.get("response_file"), field(fields, "response_text"))
        save_file(conn, self.user, work["id"], "anonymous", work["revision_count"], original, data)
        save_file(conn, self.user, work["id"], "response", work["revision_count"], response_name, response_data)
        conn.execute(
            "UPDATE works SET status = 'submitted', updated_at = ? WHERE id = ?",
            (now(), work["id"]),
        )

    def upload_final(self, conn, work, files) -> None:
        if self.user["role"] != "member" or work["member_id"] != self.user["id"]:
            raise AppError("Only the member who uploaded this paper can send the final PDF.")
        if work["status"] != "accepted":
            raise AppError("Upload the final PDF after the paper is accepted.")
        original, data = require_pdf(files.get("manuscript"), "final PDF")
        save_file(conn, self.user, work["id"], "final", 0, original, data)
        conn.execute("UPDATE works SET updated_at = ? WHERE id = ?", (now(), work["id"]))

    def assign_reviewers(self, conn, work, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can assign reviewers.")
        if work["status"] != "submitted":
            raise AppError("Reviewers can be assigned when the paper is waiting.")
        if file_row(conn, work["id"], "anonymous", work["revision_count"]) is None:
            raise AppError("The anonymous PDF for this round is not here yet.")
        chosen = []
        for reviewer_id in field_all(fields, "reviewer_id"):
            if reviewer_id not in chosen:
                chosen.append(reviewer_id)
        if len(chosen) not in (2, 3):
            raise AppError("Choose 2 or 3 reviewers.")
        existing = conn.execute(
            "SELECT 1 FROM assignments WHERE work_id = ? AND round_no = ?",
            (work["id"], work["revision_count"]),
        ).fetchone()
        if existing:
            raise AppError("Reviewers are already assigned for this round.")
        moment = now()
        for reviewer_id in chosen:
            reviewer = conn.execute(
                "SELECT id FROM accounts WHERE id = ? AND role = 'reviewer'",
                (reviewer_id,),
            ).fetchone()
            if reviewer is None:
                raise AppError("Choose reviewers from the reviewer list.")
            conn.execute(
                """INSERT INTO assignments (id, work_id, reviewer_id, round_no, created_at, response)
                   VALUES (?, ?, ?, ?, ?, 'pending')""",
                (new_id(), work["id"], reviewer_id, work["revision_count"], moment),
            )
        conn.execute(
            "UPDATE works SET status = 'in_review', updated_at = ? WHERE id = ?",
            (moment, work["id"]),
        )

    def clear_reviewers(self, conn, work) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can change the reviewers.")
        if work["status"] != "in_review":
            raise AppError("The reviewers can be changed only while their reports are not in.")
        reported = conn.execute(
            """SELECT 1 FROM reports r
               JOIN assignments a ON a.id = r.assignment_id
               WHERE a.work_id = ? AND a.round_no = ?""",
            (work["id"], work["revision_count"]),
        ).fetchone()
        if reported:
            raise AppError("A report is already in, so these reviewers stay.")
        replied = conn.execute(
            """SELECT 1 FROM assignments
               WHERE work_id = ? AND round_no = ? AND response != 'pending'""",
            (work["id"], work["revision_count"]),
        ).fetchone()
        if replied:
            raise AppError("A reviewer has already replied. Choose a replacement when someone declines.")
        conn.execute(
            "DELETE FROM assignments WHERE work_id = ? AND round_no = ?",
            (work["id"], work["revision_count"]),
        )
        conn.execute(
            "UPDATE works SET status = 'submitted', updated_at = ? WHERE id = ?",
            (now(), work["id"]),
        )

    def reply_to_review(self, conn, work, response: str) -> None:
        if self.user["role"] != "reviewer":
            raise AppError("Only the assigned reviewer can answer this.")
        if work["status"] != "in_review":
            raise AppError("This paper is not waiting for a reply.")
        if response not in ("agreed", "declined"):
            raise AppError("Choose agree or decline.")
        assignment = conn.execute(
            """SELECT * FROM assignments
               WHERE work_id = ? AND reviewer_id = ? AND round_no = ?""",
            (work["id"], self.user["id"], work["revision_count"]),
        ).fetchone()
        if assignment is None:
            raise AppError("This round is not assigned to you.")
        if assignment["response"] != "pending":
            raise AppError("You have already answered this request.")
        conn.execute(
            "UPDATE assignments SET response = ?, responded_at = ? WHERE id = ?",
            (response, now(), assignment["id"]),
        )

    def replace_reviewer(self, conn, work, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can assign a replacement.")
        if work["status"] != "in_review":
            raise AppError("A replacement can be chosen while the paper is with reviewers.")
        declined_id = required(field(fields, "declined_id"), "Choose the reviewer who declined.", 80)
        declined = conn.execute(
            """SELECT * FROM assignments
               WHERE id = ? AND work_id = ? AND round_no = ? AND response = 'declined'""",
            (declined_id, work["id"], work["revision_count"]),
        ).fetchone()
        if declined is None:
            raise AppError("That reviewer has not declined.")
        if conn.execute("SELECT 1 FROM assignments WHERE replaces_id = ?", (declined_id,)).fetchone():
            raise AppError("A replacement is already assigned.")
        reviewer_id = required(field(fields, "reviewer_id"), "Choose a replacement reviewer.", 80)
        if reviewer_id == declined["reviewer_id"]:
            raise AppError("Choose a different reviewer.")
        reviewer = conn.execute(
            "SELECT id FROM accounts WHERE id = ? AND role = 'reviewer'",
            (reviewer_id,),
        ).fetchone()
        if reviewer is None:
            raise AppError("Choose a reviewer from the reviewer list.")
        existing = conn.execute(
            """SELECT 1 FROM assignments
               WHERE work_id = ? AND reviewer_id = ? AND round_no = ?""",
            (work["id"], reviewer_id, work["revision_count"]),
        ).fetchone()
        if existing:
            raise AppError("That reviewer is already on this paper.")
        conn.execute(
            """INSERT INTO assignments
               (id, work_id, reviewer_id, round_no, created_at, response, replaces_id)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            (new_id(), work["id"], reviewer_id, work["revision_count"], now(), declined_id),
        )

    def desk_reject(self, conn, work, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can desk-reject a paper.")
        if work["status"] != "submitted":
            raise AppError("Desk reject is for a paper that has not gone to reviewers.")
        assigned = conn.execute(
            "SELECT 1 FROM assignments WHERE work_id = ? AND round_no = ?",
            (work["id"], work["revision_count"]),
        ).fetchone()
        if assigned:
            raise AppError("This paper has already gone to reviewers. Use your decision instead.")
        note = optional(field(fields, "note"), 4000)
        moment = now()
        conn.execute(
            """INSERT INTO decisions (id, work_id, round_no, decision, note, created_at, desk)
               VALUES (?, ?, ?, 'reject', ?, ?, 1)""",
            (new_id(), work["id"], work["revision_count"], note, moment),
        )
        conn.execute(
            "UPDATE works SET status = 'rejected', updated_at = ? WHERE id = ?",
            (moment, work["id"]),
        )

    def record_decision(self, conn, work, fields) -> None:
        if self.user["role"] != "chief":
            raise AppError("Only the chief editor can decide.")
        if work["status"] != "in_review":
            raise AppError("Decide while the paper is with reviewers, or desk-reject it before that.")
        decision = field(fields, "decision")
        allowed = {"accept", "reject"} if work["revision_count"] >= 3 else {"accept", "revise", "reject"}
        if decision not in allowed:
            raise AppError("Choose Accept, Revise, or Reject.")
        note = optional(field(fields, "note"), 4000)
        moment = now()
        conn.execute(
            """INSERT INTO decisions (id, work_id, round_no, decision, note, created_at, desk)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (new_id(), work["id"], work["revision_count"], decision, note, moment),
        )
        if decision == "revise":
            conn.execute(
                """UPDATE works SET status = 'revision', revision_count = revision_count + 1, updated_at = ?
                   WHERE id = ?""",
                (moment, work["id"]),
            )
        else:
            conn.execute(
                "UPDATE works SET status = ?, updated_at = ? WHERE id = ?",
                ("accepted" if decision == "accept" else "rejected", moment, work["id"]),
            )

    def record_report(self, conn, work, fields, files) -> None:
        if self.user["role"] != "reviewer":
            raise AppError("Only an assigned reviewer can send a report.")
        if work["status"] != "in_review":
            raise AppError("This paper is not waiting for a report.")
        assignment = conn.execute(
            """SELECT * FROM assignments
               WHERE work_id = ? AND reviewer_id = ? AND round_no = ?""",
            (work["id"], self.user["id"], work["revision_count"]),
        ).fetchone()
        if assignment is None:
            raise AppError("This round is not assigned to you.")
        if assignment["response"] != "agreed":
            raise AppError("Agree to review before you send a report.")
        existing = conn.execute(
            "SELECT id FROM reports WHERE assignment_id = ?",
            (assignment["id"],),
        ).fetchone()
        if existing:
            raise AppError("You already sent a report for this round.")
        recommendation = field(fields, "recommendation")
        if recommendation not in RECOMMENDATIONS:
            raise AppError("Choose Accept, Revise, or Reject.")
        comments = optional(field(fields, "comments"), 8000)
        editor_note = optional(field(fields, "editor_note"), 8000)
        upload = files.get("report")
        file_id = None
        if upload and upload[1]:
            original, data = require_pdf(upload, "report PDF")
            file_id = save_file(conn, self.user, work["id"], "report", work["revision_count"], original, data)
        conn.execute(
            """INSERT INTO reports
               (id, assignment_id, recommendation, comments, editor_note, file_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (new_id(), assignment["id"], recommendation, comments, editor_note, file_id, now()),
        )
        conn.execute("UPDATE works SET updated_at = ? WHERE id = ?", (now(), work["id"]))

    def send_saved_file(self, conn, file_id: str) -> None:
        require_user(self.user)
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            raise AppError("That file was not found.")
        work = load_work(conn, self.user, row["work_id"])
        if not can_download(conn, self.user, work, row):
            raise AppError("That file is not open to this sign-in.")
        path = stored_path(row["stored_name"])
        if not path.is_file():
            raise AppError("That file was not found.")
        name = download_name(self.user, row)
        inline = name.lower().endswith(".txt")
        self.send_bytes(path.read_bytes(), content_type(name), name, inline=inline)

    def send_production(self, conn, path: str) -> None:
        if self.user is None or self.user["role"] != "chief":
            raise AppError("Only the chief editor can open the issue files.")
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3:
            raise AppError("That file was not found.")
        production = conn.execute(
            "SELECT folder_name FROM productions WHERE id = ?",
            (parts[1],),
        ).fetchone()
        if production is None or not re.fullmatch(r"\d{8}-\d{6}", production["folder_name"]):
            raise AppError("That file was not found.")
        root = (data_root() / "productions" / production["folder_name"]).resolve()
        target = (root / "/".join(parts[2:])).resolve()
        if target != root and root not in target.parents:
            raise AppError("That file was not found.")
        if not target.is_file():
            raise AppError("That file was not found.")
        inline = target.suffix.lower() in (".html", ".txt")
        self.send_bytes(target.read_bytes(), content_type(target.name), target.name, inline=inline)

    def send_static(self, relative: str) -> None:
        root = (ROOT / "static").resolve()
        path = (root / relative).resolve()
        if path != root and root not in path.parents or not path.is_file():
            self.send_html(layout("Please check", "<p class='error'>That file was not found.</p>", None, None), 404)
            return
        self.send_bytes(path.read_bytes(), content_type(path.name), path.name, inline=True)

    def redirect(self, location: str, clear_cookie: bool = False) -> None:
        if self.user and not clear_cookie:
            location = keep(self.user, location)
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if clear_cookie:
            self.send_header("Set-Cookie", cookie("", clear=True))
        elif self.user:
            self.send_header("Set-Cookie", cookie(self.user["token"]))
        self.end_headers()

    def send_html(self, body: str, status: int = 200, token: str | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        session = token or (self.user["token"] if self.user else "")
        if session:
            self.send_header("Set-Cookie", cookie(session))
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(self, data: bytes, mime: str, name: str, inline: bool = False) -> None:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-") or "file"
        disposition = "inline" if inline else "attachment"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'{disposition}; filename="{safe}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.user:
            self.send_header("Set-Cookie", cookie(self.user["token"]))
        self.end_headers()
        self.wfile.write(data)


class Server(ThreadingHTTPServer):
    allow_reuse_address = True


def main() -> None:
    init_db()
    try:
        server = Server((HOST, PORT), Handler)
    except OSError:
        print("The workshop is already open on this computer.", flush=True)
        print("Use that window, or close it and start again.", flush=True)
        return
    url = f"http://{HOST}:{PORT}/"
    print(f"Issue workshop: {url}", flush=True)
    print("Keep this window open while you use it. Closing the window stops the workshop.", flush=True)
    if os.environ.get("WORKSHOP_NO_BROWSER") != "1":
        try:
            webbrowser.open(url)
        except Exception:
            pass
    server.serve_forever()


if __name__ == "__main__":
    main()
