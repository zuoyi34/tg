from fastapi import FastAPI, HTTPException, Header, Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3
import time
import uuid
import json
from fastapi.staticfiles import StaticFiles
import threading

app = FastAPI(title="TG群发助手后台")

# 静态文件目录
#app.mount("/static", StaticFiles(directory="static"), name="static")

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "app.db"

# ---------------- 数据库初始化 ----------------
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # 管理员表
        c.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        # 密钥表
        c.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                token TEXT PRIMARY KEY,
                valid_until INTEGER NOT NULL,
                remark TEXT DEFAULT NULL,
                created_at INTEGER NOT NULL DEFAULT 0
            )
        """)
        # 会话表（hwid 允许空字符串）
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                token TEXT NOT NULL,
                login_time INTEGER NOT NULL,
                last_active INTEGER NOT NULL,
                hwid TEXT DEFAULT ""
            )
        """)
        # 配置表
        c.execute("""
            CREATE TABLE IF NOT EXISTS configs (
                token TEXT PRIMARY KEY,
                config_json TEXT NOT NULL
            )
        """)
        # 默认管理员
        c.execute("SELECT * FROM admins WHERE username = 'admin'")
        if not c.fetchone():
            c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", "admin123"))
        conn.commit()

init_db()

# ---------------- Pydantic 模型 ----------------
class AdminLoginRequest(BaseModel):
    username: str
    password: str

class LicenseCreateRequest(BaseModel):
    token: str
    valid_until: int  # 0表示永久有效
    remark: Optional[str] = None

class LicenseUpdateRequest(BaseModel):
    valid_until: Optional[int] = None
    remark: Optional[str] = None

class LoginRequest(BaseModel):
    token: str

class LogoutRequest(BaseModel):
    session_id: str

class ValidateRequest(BaseModel):
    token: str

class ConfigData(BaseModel):
    key_list: Optional[str] = ""
    reply_content: Optional[str] = ""
    is_listene_private_msg: Optional[int] = 0
    is_listene_public_channel_msg: Optional[int] = 0
    is_rand_reply: Optional[int] = 0
    send_content: Optional[str] = ""
    start_time_hour: Optional[int] = 0
    start_time_min: Optional[int] = 0
    end_time_hour: Optional[int] = 23
    end_time_min: Optional[int] = 59
    single_sleep_time: Optional[int] = 3
    send_sleep_time: Optional[int] = 5
    is_sand_all_reply: Optional[int] = 0
    suffix_index: Optional[int] = 0
    use_api: Optional[int] = 0
    api_id: Optional[str] = ""
    api_hash: Optional[str] = ""
    use_proxy: Optional[int] = 0
    proxy: Optional[str] = ""
    forward_msg: Optional[int] = 0
    forward_user: Optional[str] = ""
    session_path: Optional[str] = ""

class SaveConfigRequest(ConfigData):
    pass

# ---------------- 工具函数 ----------------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def check_admin_auth(auth: Optional[str], conn):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "未授权")
    token = auth[7:]
    c = conn.cursor()
    # 直接比对明文密码
    c.execute("SELECT username FROM admins WHERE password = ?", (token,))
    if not c.fetchone():
        raise HTTPException(401, "无效管理员token")

def get_license(token, conn):
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE token = ?", (token,))
    return c.fetchone()

def create_session(token, conn, hwid=""):
    session_id = str(uuid.uuid4())
    now = int(time.time())
    c = conn.cursor()
    c.execute(
        "INSERT INTO sessions (session_id, token, login_time, last_active, hwid) VALUES (?, ?, ?, ?, ?)",
        (session_id, token, now, now, hwid)
    )
    conn.commit()
    return session_id

def get_session(session_id, conn):
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    return c.fetchone()

def update_session_active(session_id, conn):
    now = int(time.time())
    c = conn.cursor()
    c.execute("UPDATE sessions SET last_active = ? WHERE session_id = ?", (now, session_id))
    conn.commit()

def get_session_or_401(token: str):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM sessions WHERE token = ?", (token,))
        session = c.fetchone()
        if not session:
            raise HTTPException(401, "无效的 token 或 session")
        update_session_active(session["session_id"], conn)
        return session

def get_config(token, conn):
    c = conn.cursor()
    c.execute("SELECT config_json FROM configs WHERE token = ?", (token,))
    row = c.fetchone()
    return row["config_json"] if row else None

def save_config(token, config_json, conn):
    c = conn.cursor()
    c.execute("REPLACE INTO configs (token, config_json) VALUES (?, ?)", (token, config_json))
    conn.commit()

# ---------------- 管理后台接口 ----------------
@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT password FROM admins WHERE username = ?", (req.username,))
        row = c.fetchone()
        if not row or row["password"] != req.password:
            raise HTTPException(401, "用户名或密码错误")
        # 直接返回明文密码作为token
        return {"code": 0, "msg": "登录成功", "token": row["password"]}

@app.get("/admin/licenses")
def admin_list_licenses(Authorization: Optional[str] = Header(None)):
    with get_db() as conn:
        check_admin_auth(Authorization, conn)
        c = conn.cursor()
        c.execute("SELECT token, valid_until, remark, created_at FROM licenses")
        licenses = [dict(row) for row in c.fetchall()]
        return {"code": 0, "msg": "成功", "data": licenses}

@app.post("/admin/licenses")
def admin_create_license(req: LicenseCreateRequest, Authorization: Optional[str] = Header(None)):
    with get_db() as conn:
        check_admin_auth(Authorization, conn)
        c = conn.cursor()
        c.execute("SELECT token FROM licenses WHERE token = ?", (req.token,))
        if c.fetchone():
            raise HTTPException(400, "该密钥已存在")
        now = int(time.time())
        c.execute(
            "INSERT INTO licenses (token, valid_until, remark, created_at) VALUES (?, ?, ?, ?)",
            (req.token, req.valid_until, req.remark, now)
        )
        conn.commit()
        return {"code": 0, "msg": "密钥创建成功"}

@app.put("/admin/licenses/{token}")
def admin_update_license(token: str = Path(...), req: LicenseUpdateRequest = None, Authorization: Optional[str] = Header(None)):
    with get_db() as conn:
        check_admin_auth(Authorization, conn)
        c = conn.cursor()
        c.execute("SELECT token FROM licenses WHERE token = ?", (token,))
        if not c.fetchone():
            raise HTTPException(404, "密钥不存在")
        if req.valid_until is not None:
            c.execute("UPDATE licenses SET valid_until = ? WHERE token = ?", (req.valid_until, token))
        if req.remark is not None:
            c.execute("UPDATE licenses SET remark = ? WHERE token = ?", (req.remark, token))
        conn.commit()
        return {"code": 0, "msg": "密钥更新成功"}

@app.delete("/admin/licenses/{token}")
def admin_delete_license(token: str = Path(...), Authorization: Optional[str] = Header(None)):
    with get_db() as conn:
        check_admin_auth(Authorization, conn)
        c = conn.cursor()
        c.execute("DELETE FROM licenses WHERE token = ?", (token,))
        c.execute("DELETE FROM sessions WHERE token = ?", (token,))
        c.execute("DELETE FROM configs WHERE token = ?", (token,))
        conn.commit()
        return {"code": 0, "msg": "密钥删除成功"}

# ---------------- 客户端接口 ----------------
SESSION_TIMEOUT = 30 * 60  # 30分钟

@app.post("/api/login")
def api_login(req: LoginRequest):
    with get_db() as conn:
        license = get_license(req.token, conn)
        if not license:
            raise HTTPException(401, "无效密钥")
        now = int(time.time())
        if license["valid_until"] != 0 and now > license["valid_until"]:
            raise HTTPException(403, "密钥已过期")
        session_id = create_session(req.token, conn, hwid="")
        return {"code": 0, "msg": "登录成功", "session_id": session_id}

@app.post("/api/logout")
def api_logout(req: LogoutRequest):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE session_id = ?", (req.session_id,))
        conn.commit()
        return {"code": 0, "msg": "登出成功"}

@app.post("/api/validate")
def api_validate(req: ValidateRequest):
    session = get_session_or_401(req.token)
    return {"code": 0, "msg": "密钥验证成功", "token": session["token"]}

@app.get("/api/config")
def api_get_config(session_id: str):
    session = get_session_or_401(session_id)
    with get_db() as conn:
        config_json = get_config(session["token"], conn)
        return {"code": 0, "msg": "成功", "config": json.loads(config_json) if config_json else {}}

@app.post("/api/config")
def api_save_config(req: SaveConfigRequest, session_id: str):
    session = get_session_or_401(session_id)
    config_dict = req.dict()
    config_json = json.dumps(config_dict, ensure_ascii=False)
    with get_db() as conn:
        save_config(session["token"], config_json, conn)
    return {"code": 0, "msg": "配置保存成功"}

# ---------------- 后台清理过期 session ----------------
def cleanup_sessions():
    while True:
        with get_db() as conn:
            now = int(time.time())
            expire_threshold = now - SESSION_TIMEOUT
            c = conn.cursor()
            c.execute("SELECT session_id FROM sessions WHERE last_active < ?", (expire_threshold,))
            expired = c.fetchall()
            for row in expired:
                c.execute("DELETE FROM sessions WHERE session_id = ?", (row["session_id"],))
            conn.commit()
        time.sleep(600)  # 每10分钟清理一次

threading.Thread(target=cleanup_sessions, daemon=True).start()
