from fastapi import FastAPI, HTTPException, Header, Path, Depends
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import time
import uuid

app = FastAPI(title="Simple License Backend")

DB_FILE = "app.db"

# ---------- 初始化数据库 ----------
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # 管理员表，存用户名密码
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
                created_at INTEGER NOT NULL
            )
        """)
        # 默认管理员，用户名：admin 密码：admin123
        c.execute("SELECT * FROM admins WHERE username = 'admin'")
        if not c.fetchone():
            c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", "admin123"))
        conn.commit()

init_db()

# ---------- Pydantic模型 ----------
class AdminLoginRequest(BaseModel):
    username: str
    password: str

class LicenseCreateRequest(BaseModel):
    token: str
    valid_until: int  # 0 表示永久有效
    remark: Optional[str] = None

class LicenseUpdateRequest(BaseModel):
    valid_until: Optional[int] = None
    remark: Optional[str] = None

class LoginRequest(BaseModel):
    token: str

# ---------- 工具函数 ----------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def check_admin_auth(auth: Optional[str]):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "未授权")
    token = auth[7:]
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM admins WHERE password = ?", (token,))
        if not c.fetchone():
            raise HTTPException(401, "无效管理员token")

def get_license(token: str):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM licenses WHERE token = ?", (token,))
        return c.fetchone()

# ---------- 管理后台接口 ----------
@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT password FROM admins WHERE username = ?", (req.username,))
        row = c.fetchone()
        if not row or row["password"] != req.password:
            raise HTTPException(401, "用户名或密码错误")
        return {"code": 0, "msg": "登录成功", "token": row["password"]}

@app.get("/admin/licenses")
def admin_list_licenses(Authorization: Optional[str] = Header(None)):
    check_admin_auth(Authorization)
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT token, valid_until, remark, created_at FROM licenses")
        licenses = [dict(row) for row in c.fetchall()]
        return {"code": 0, "msg": "成功", "data": licenses}

@app.post("/admin/licenses")
def admin_create_license(req: LicenseCreateRequest, Authorization: Optional[str] = Header(None)):
    check_admin_auth(Authorization)
    with get_db() as conn:
        c = conn.cursor()
        if get_license(req.token):
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
    check_admin_auth(Authorization)
    with get_db() as conn:
        c = conn.cursor()
        if not get_license(token):
            raise HTTPException(404, "密钥不存在")
        if req.valid_until is not None:
            c.execute("UPDATE licenses SET valid_until = ? WHERE token = ?", (req.valid_until, token))
        if req.remark is not None:
            c.execute("UPDATE licenses SET remark = ? WHERE token = ?", (req.remark, token))
        conn.commit()
        return {"code": 0, "msg": "密钥更新成功"}

@app.delete("/admin/licenses/{token}")
def admin_delete_license(token: str = Path(...), Authorization: Optional[str] = Header(None)):
    check_admin_auth(Authorization)
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM licenses WHERE token = ?", (token,))
        conn.commit()
        return {"code": 0, "msg": "密钥删除成功"}

# ---------- 客户端接口 ----------
@app.post("/api/login")
def api_login(req: LoginRequest):
    license = get_license(req.token)
    if not license:
        raise HTTPException(401, "无效密钥")
    now = int(time.time())
    if license["valid_until"] != 0 and now > license["valid_until"]:
        raise HTTPException(403, "密钥已过期")
    return {"code": 0, "msg": "登录成功"}

@app.post("/api/validate")
def api_validate(req: LoginRequest):
    license = get_license(req.token)
    if not license:
        raise HTTPException(401, "无效密钥")
    now = int(time.time())
    if license["valid_until"] != 0 and now > license["valid_until"]:
        raise HTTPException(403, "密钥已过期")
    return {"code": 0, "msg": "密钥有效"}

