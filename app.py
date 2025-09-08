import re
import os
import logging
import time
import redis
from typing import Optional
from datetime import date, datetime, timedelta
from dateutil.relativedelta import relativedelta
from flask import Flask, request, jsonify, session, g, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from flask_cors import CORS
from flask_session import Session
from functools import wraps
import traceback
import pymysql

load_dotenv()
DB_URL = os.getenv("DB_URL")
ABSOLUTE_TIMEOUT_SEC = int(os.getenv("ABSOLUTE_TIMEOUT_SEC", "0"))
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=[os.getenv("CF_ORIGIN")])
app.config['JSON_AS_ASCII'] = False
app.secret_key = os.getenv("SECRET_KEY", "dev-change-me")
app.config.update(
    SESSION_TYPE="redis",
    SESSION_REDIS=redis.from_url(os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")),
    SESSION_USE_SIGNER=True,             # 쿠키 변조 방지
    SESSION_PERMANENT=True,              # 'permanent' 세션으로 운용
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),  # ★ 유효기간 1시간
    SESSION_COOKIE_NAME="oi_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.getenv("COOKIE_SECURE", "0") == "1"),  # HTTPS면 1
    SESSION_REFRESH_EACH_REQUEST=True,  # ✅ 매 요청마다 만료 갱신(쿠키 측)
)
Session(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

engine = create_engine(
    DB_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    future=True,
    isolation_level="AUTOCOMMIT",
)

def normalize_phone(s: str) -> str:
    return re.sub(r'\D+', '', s or '')

def fail(code: str, http: int = 400, message: Optional[str] = None, **extra):
    payload = {"ok": False, "code": code}
    if message:
        payload["message"] = message
    payload.update(extra)
    resp = jsonify(payload)
    resp.status_code = http
    return resp

def login_required(fn):
    @wraps(fn)
    def _wrap(*a, **kw):
        if "uid" not in session:
            return jsonify(ok=False, code="unauth", message="로그인이 필요합니다."), 401
        return fn(*a, **kw)
    return _wrap

def login_required_view(f):
    @wraps(f)
    def _w(*a, **kw):
        if "uid" not in session:
            nxt = request.path
            return redirect(f"/login?next={nxt}")
        return f(*a, **kw)
    return _w

@app.get("/api/payment")
@login_required_view
def payment_page():
    # 템플릿/정적파일 제공 방식에 맞게
    return app.send_static_file("payment.html")

@app.before_request
def _touch_session_and_absolute_timeout():
    # 항상 쿠키 만료 갱신(클라이언트 측)
    session.modified = True

    # 로그인 세션에만 절대타임아웃 적용
    if "uid" in session and ABSOLUTE_TIMEOUT_SEC > 0:
        t0 = session.get("login_at")
        if t0 and time.time() - t0 > ABSOLUTE_TIMEOUT_SEC:
            session.clear()
            return jsonify(ok=False, code="session_expired",
                           message="세션이 만료되었습니다. 다시 로그인해 주세요."), 401

@app.get("/api/healthz")
def health():
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify(status="ok"), 200
    except Exception as e:
        logger.error("HEALTH_FAILED: %s", e)
        return jsonify(status="ng"), 500

@app.get("/api/services")
def services():
    with engine.begin() as conn:
        rows = conn.execute(text("""
          SELECT service_id, service_name, category, price, max_seats, billing_cycle
          FROM services ORDER BY service_name
        """)).mappings().all()
    return jsonify([dict(r) for r in rows])

@app.post("/api/users/verify")
def users_verify():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    phone = normalize_phone(data.get("phone"))
    if not email or not phone:
        return jsonify({"ok": False, "reason": "missing"}), 400

    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT phone_number AS phone
            FROM users
            WHERE LOWER(email)=:email
            LIMIT 1
        """), {"email": email}).mappings().first()

    if not row:
        return jsonify({"ok": False})
    return jsonify({"ok": normalize_phone(row["phone"]) == phone})

@app.get("/api/work/")
@app.get("/api/work")
@app.get("/api/works")
def works():
    q = (request.args.get("q") or "").strip()
    service_id = request.args.get("service_id")
    conds = []
    params = {}
    if q:
        conds.append("c.contents_name LIKE :q")
        params["q"] = f"%{q}%"
    if service_id:
        conds.append("c.service_id = :sid")
        params["sid"] = int(service_id)
    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    sql = f"""
      SELECT c.content_id, c.contents_name, s.service_name, c.service_id
      FROM contents c JOIN services s ON s.service_id = c.service_id
      {where}
      ORDER BY c.content_id DESC LIMIT 200
    """
    with engine.begin() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
    return jsonify([dict(r) for r in rows])

def next_period(start: date, cycle: str) -> date:
    return start + (relativedelta(years=1) if cycle == "yearly" else relativedelta(months=1))

@app.post("/api/checkout")
def checkout():

    if "uid" not in session:
        return jsonify(ok=False, message="로그인이 필요합니다."), 401

    # 1) 요청 파싱
    body = request.get_json(force=True) or {}
    email = (body.get("email") or "").strip().lower()
    phone = normalize_phone(body.get("phone"))
    service_ids = body.get("service_ids") or []

    # 2) 기본 검증
    if not email or not phone:
        return fail("missing_user_info")
    if not service_ids:
        return fail("no_services")

    # 3) 사용자 인증
    with engine.begin() as conn:
        u = conn.execute(text("""
            SELECT user_id, phone_number AS phone
            FROM users
            WHERE LOWER(email)=:email
            LIMIT 1
        """), {"email": email}).mappings().first()
    if (not u) or normalize_phone(u["phone"]) != phone:
         return fail("user_not_matched")
    uid = int(u["user_id"])

    created, joined, activated = [], [], []
    skipped = []
    lines = []

    try:
        # ★ 트랜잭션: 이 블록에서 예외 나면 전부 롤백
        with engine.begin() as conn:
            for sid in service_ids:
                # 서비스 확인 (없으면 실패로 간주 → 예외 발생 → 롤백)
                svc = conn.execute(text("""
                    SELECT service_id, price, max_seats, billing_cycle
                    FROM services
                    WHERE service_id = :sid
                """), {"sid": sid}).mappings().first()
                if not svc:
                    raise RuntimeError(f"invalid_service:{sid}")

                # 이미 해당 서비스에 속해 있으면 건너뛰기
                already = conn.execute(text("""
                    SELECT mgm.group_id
                    FROM match_group_members AS mgm
                    WHERE mgm.user_id = :uid AND mgm.service_id = :sid
                    LIMIT 1
                """), {"uid": uid, "sid": sid}).first()

                if already:
                    skipped.append(int(sid))
                    continue

                # 열린 그룹 탐색 (정원은 services.max_seats 기준)
                open_group = conn.execute(text("""
                    SELECT mg.group_id,
                           s.max_seats AS capacity,
                           COUNT(mgm.user_id) AS members
                    FROM match_groups mg
                    JOIN services s ON s.service_id = mg.service_id
                    LEFT JOIN match_group_members mgm ON mgm.group_id = mg.group_id
                    WHERE mg.service_id = :sid
                    GROUP BY mg.group_id, capacity
                    HAVING members < capacity
                    ORDER BY mg.group_id ASC
                    LIMIT 1
                """), {"sid": sid}).mappings().first()

                # 없으면 새 그룹 생성 (초기 target_size는 임시값; 가입 후 실제 인원으로 동기화)
                if not open_group:
                    g = conn.execute(text("""
                        INSERT INTO match_groups (service_id, target_size)
                        VALUES (:sid, :size)
                    """), {"sid": sid, "size": int(svc["max_seats"])})
                    group_id = int(g.lastrowid)
                    created.append(group_id)
                else:
                    group_id = int(open_group["group_id"])

                lines.append({
                    "service_id": int(sid),
                    "group_id": int(group_id),
                    "price": int(svc["price"]),
                })

                # 멤버로 참여 (중복만 무시, 그 외 오류는 raise → 롤백)
                try:
                    conn.execute(text("""
                        INSERT INTO match_group_members (group_id, user_id, service_id)
                        VALUES (:gid, :uid, :sid)
                    """), {"gid": group_id, "uid": uid, "sid": sid})
                    joined.append(group_id)
                except IntegrityError as ie:
                    # Duplicate entry만 허용 (같은 유저가 같은 그룹에 이미 있음)
                    if "1062" in str(ie.orig) or "Duplicate" in str(ie.orig):
                        pass
                    else:
                        raise

                # ✨ 참여 후 target_size를 현재 인원수로 동기화 (옵션2 핵심)
                conn.execute(text("""
                    UPDATE match_groups mg
                    SET target_size = (
                        SELECT COUNT(*) FROM match_group_members WHERE group_id = :gid
                    )
                    WHERE mg.group_id = :gid
                """), {"gid": group_id})

                # 그룹이 꽉 찼는지 확인 (capacity = services.max_seats)
                cur = conn.execute(text("""
                    SELECT mg.group_id,
                           s.max_seats AS capacity,
                           COUNT(mgm.user_id) AS members
                    FROM match_groups mg
                    JOIN services s ON s.service_id = mg.service_id
                    LEFT JOIN match_group_members mgm ON mgm.group_id = mg.group_id
                    WHERE mg.group_id = :gid
                    GROUP BY mg.group_id, capacity
                """), {"gid": group_id}).mappings().first()

                if not cur:
                    raise RuntimeError("group_state_error")

                if int(cur["members"]) >= int(cur["capacity"]):
                    exist = conn.execute(text("""
                        SELECT 1
                        FROM subscriptions
                        WHERE group_id = :gid AND service_id = :sid AND user_id = :uid
                        LIMIT 1
                    """), {"gid": group_id, "sid": sid, "uid": uid}).first()
                    if not exist:
                        start = date.today()
                        end = next_period(start, svc["billing_cycle"])
                        conn.execute(text("""
                            INSERT INTO subscriptions
                                (group_id, service_id, user_id, current_period_start, current_period_end)
                            VALUES (:gid, :sid, :uid, :s, :e)
                        """), {"gid": group_id, "sid": sid, "uid": uid, "s": start, "e": end})
                        activated.append(group_id)

        # ★ 여기까지 예외 없으면 COMMIT

    except Exception as e:
        app.logger.exception("checkout failed email=%s services=%s", email, service_ids)
        # 실패 → 위에서 자동 ROLLBACK됨
        return fail("checkout_failed", message=str(e)[:200])

    if not (created or joined or activated) and skipped:
        return fail("already_subscribed",
                    message="이미 구독 중인 서비스입니다.",
                    skipped=skipped)

    paid_at = datetime.utcnow().isoformat()
    oid = f"OI-{int(datetime.utcnow().timestamp())}"

    return jsonify({
        "ok": True,
        "created_groups": created,
        "joined_groups": joined,
        "activated_groups": activated,
        "skipped": skipped,
        "lines": lines,
        "paid_at": paid_at,
        "oid": oid,
        "redirect": "/paycomp?plan=group&services=joined&amount=0"
    })


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify(message="이메일/비밀번호를 입력해 주세요."), 400

    try:
        with engine.begin() as conn:
            row = conn.execute(text("""
                SELECT user_id, user_name, name, password_hash
                FROM users WHERE email=:email LIMIT 1
            """), {"email": email}).mappings().first()

        if not row or not check_password_hash(row["password_hash"], password):
            return jsonify(message="이메일 또는 비밀번호가 올바르지 않습니다."), 401

        session.clear()
        session["uid"] = int(row["user_id"])
        session["uname"] = row["user_name"]
        session["name"] = row.get("name")
        session.permanent = True
        session["login_at"] = time.time()

        return jsonify(ok=True, message="ok"), 200

    except Exception:
        logger.exception("LOGIN_FAILED")
        return jsonify(message="서버 오류가 발생했습니다."), 500

@app.get("/api/me")
def me():
    if "uid" not in session:
        return jsonify(ok=False, message="unauthorized"), 401

    try:
        with engine.begin() as conn:
            row = conn.execute(text("""
                SELECT user_id, user_name, name, email, phone_number, created_at
                FROM users
                WHERE user_id=:uid
                LIMIT 1
            """), {"uid": session["uid"]}).mappings().first()

        if not row:
            return jsonify(ok=False, message="not found"), 404

        payload = dict(row)
        ca = payload.get("created_at")
        if ca is not None and not isinstance(ca, str):
            payload["created_at"] = ca.isoformat()  # ← 직렬화 안전

        payload["ok"] = True
        return jsonify(payload), 200

    except Exception:
        logger.exception("ME_FAILED")
        return jsonify(ok=False, message="서버 오류가 발생했습니다."), 500

@app.post("/api/logout")
def logout():
    session.clear()
    
    # 세션 쿠키 이름 가져오기 (기본값: 'session')
    cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")

    # 쿠키 값 강제 디코딩 (있을 경우)
    cookie_value = request.cookies.get(cookie_name)
    if isinstance(cookie_value, bytes):
        try:
            cookie_value = cookie_value.decode('utf-8')
        except Exception:
            cookie_value = ""

    # 응답 생성 후 쿠키 삭제
    resp = jsonify(ok=True)
    resp.delete_cookie(cookie_name)
    return resp




@app.post("/api/register")
def register():
    try:
        data = request.get_json(silent=True) or {}
        user_name = (data.get("userid") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        phone_number = (data.get("phone") or "").strip()
        real_name = (data.get("name") or "").strip() or None

        if not user_name or not email or len(password) < 8:
            return jsonify(message="입력 값이 올바르지 않습니다."), 400

        pw_hash = generate_password_hash(password)

        with engine.begin() as conn:
            exists = conn.execute(text("""
                SELECT user_id FROM users WHERE email=:email OR user_name=:uname
            """), {"email": email, "uname": user_name}).first()
            if exists:
                return jsonify(message="이미 존재하는 사용자입니다."), 409

            conn.execute(text("""
                INSERT INTO users (user_name, email, phone_number, password_hash, name)
                VALUES (:uname, :email, :phone, :phash, :rname)
            """), {
                "uname": user_name,
                "email": email,
                "phone": phone_number,
                "phash": pw_hash,
                "rname": real_name,
            })

        return jsonify(message="registered"), 201
    except Exception:
        logger.exception("REGISTER_FAILED")
        return jsonify(message="서버 오류가 발생했습니다."), 500

# --- 로그인된 사용자의 구독 목록을 반환하는 API ---
@app.route("/api/subscriptions")
def subscriptions():
    uid = session.get("uid")
    uid_plus_one = uid
    print("▶ 세션 UID:", uid_plus_one)  # 로그 출력
    # ➊ 세션에서 사용자 ID 확인 (로그인 필수)
    if "uid" not in session:
        return jsonify(message="unauthorized"), 401
    try:
        # ➋ DB 연결
        with engine.begin() as conn:
            # ➌ 해당 사용자와 연결된 구독 항목을 조회
            rows = conn.execute(text("""
                SELECT s.service_name, s.price
                FROM match_group_members sub
                JOIN services s ON sub.service_id = s.service_id
                JOIN users u ON sub.user_id = u.user_id
                WHERE u.user_id = :uid
             """), {"uid": uid_plus_one}).mappings().all()
            print("▶ DB UID:", uid_plus_one)  # 로그 출력
        if not rows:
            return jsonify(message="not found"), 404
        # ➍ 구독 목록 JSON으로 반환
        print("▶ rows:", rows)  # 로그 출력
        result = [dict(row) for row in rows]
        print("▶ result:", result)  # 로그 출력
        return jsonify(result), 200

    except Exception as e:
        # ➎ 예외 발생 시 500 에러 반환
        print("ERROR:", e)
        return jsonify({"error": "Server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

from flask_session.sessions import RedisSessionInterface
import redis

class PatchedRedisSessionInterface(RedisSessionInterface):
    def save_session(self, app, session, response):
        session_id = session.sid
        if isinstance(session_id, bytes):  # ⛑️ 핵심 수정
            session_id = session_id.decode("utf-8")
        response.set_cookie(
            app.config.get("SESSION_COOKIE_NAME", "session"),
            session_id,
            httponly=True,
            secure=False  # 필요 시 True로
        )
        return super().save_session(app, session, response)

# 🔧 Redis 연결 설정
redis_connection = redis.Redis(
    host="my-redis-master.caching.svc.cluster.local",
    port=6379
)

# ✅ 필수 인자 모두 명시
app.session_interface = PatchedRedisSessionInterface(
    redis=redis_connection,
    key_prefix="session:",      # 세션 키 접두사
    use_signer=False,           # 필요 시 True
    permanent=True              # True: 영구 세션, False: 브라우저 종료 시 삭제
)

