import base64, hashlib, hmac, json, os, secrets, sqlite3, time
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="FocusFlow Cloud")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
if USE_PG:
      import psycopg2
      from psycopg2.extras import RealDictCursor

def get_db():
      if USE_PG:
                url = DATABASE_URL.replace("postgres://", "postgresql://", 1) if DATABASE_URL.startswith("postgres://") else DATABASE_URL
                return psycopg2.connect(url, cursor_factory=RealDictCursor)
            conn = sqlite3.connect("focusflow.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
      conn = get_db(); cur = conn.cursor()
    id_col = "SERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    cur.execute(f"CREATE TABLE IF NOT EXISTS users (id {id_col}, name TEXT, email TEXT UNIQUE, pw TEXT)")
    cur.execute(f"CREATE TABLE IF NOT EXISTS tasks (id {id_col}, user_id INTEGER, title TEXT, priority TEXT, category TEXT, due_date TEXT, completed INTEGER DEFAULT 0)")
    conn.commit(); conn.close()

init_db()
P = "%s" if USE_PG else "?"

def hash_pw(pw: str, salt: Optional[str] = None) -> str:
      salt = salt or secrets.token_hex(8)
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()}"

def make_token(uid: int, email: str, name: str) -> str:
      b = base64.urlsafe_b64encode(json.dumps({"sub": uid, "email": email, "name": name}).encode()).decode().rstrip("=")
    s = hmac.new(SECRET_KEY.encode(), b.encode(), hashlib.sha256).hexdigest()
    return f"{b}.{s}"

def current_user(authorization: Optional[str] = Header(default=None)):
      if not authorization or not authorization.startswith("Bearer "):
                raise HTTPException(401, "Unauthorized")
            try:
                      b, s = authorization.split(" ", 1)[1].split(".", 1)
                      if not hmac.compare_digest(s, hmac.new(SECRET_KEY.encode(), b.encode(), hashlib.sha256).hexdigest()):
                                    raise ValueError()
                                return json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)).decode())
except Exception:
        raise HTTPException(401, "Invalid token")

class AuthReq(BaseModel):
      name: Optional[str] = "User"
    email: str
    password: str

class TaskReq(BaseModel):
      title: str
    priority: str = "medium"
    category: str = "Personal"
    dueDate: str = ""
    completed: int = 0

@app.post("/api/auth/signup")
def signup(req: AuthReq):
      conn = get_db(); cur = conn.cursor()
    cur.execute(f"SELECT id FROM users WHERE email = {P}", (req.email.lower(),))
    if cur.fetchone():
              conn.close(); raise HTTPException(400, "Email already registered")
    if USE_PG:
              cur.execute("INSERT INTO users (name, email, pw) VALUES (%s, %s, %s) RETURNING id", (req.name, req.email.lower(), hash_pw(req.password)))
        uid = cur.fetchone()["id"]
else:
        cur.execute("INSERT INTO users (name, email, pw) VALUES (?, ?, ?)", (req.name, req.email.lower(), hash_pw(req.password)))
        uid = cur.lastrowid
    conn.commit(); conn.close()
    return {"token": make_token(uid, req.email.lower(), req.name or "User"), "user": {"id": uid, "name": req.name, "email": req.email.lower()}}

@app.post("/api/auth/login")
def login(req: AuthReq):
      conn = get_db(); cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE email = {P}", (req.email.lower(),))
    u = cur.fetchone(); conn.close()
    if not u or u["pw"] != hash_pw(req.password, u["pw"].split("$")[0]):
              raise HTTPException(401, "Invalid credentials")
    return {"token": make_token(u["id"], u["email"], u["name"]), "user": {"id": u["id"], "name": u["name"], "email": u["email"]}}

@app.get("/api/tasks")
def get_tasks(u=Depends(current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute(f"SELECT * FROM tasks WHERE user_id = {P} ORDER BY id DESC", (u["sub"],))
    rows = [dict(r) for r in cur.fetchall()]; conn.close()
    return {"tasks": rows}

@app.post("/api/tasks")
def add_task(req: TaskReq, u=Depends(current_user)):
      conn = get_db(); cur = conn.cursor()
    cur.execute(f"INSERT INTO tasks (user_id, title, priority, category, due_date, completed) VALUES ({P},{P},{P},{P},{P},0)",
                                (u["sub"], req.title, req.priority, req.category, req.dueDate))
    conn.commit(); conn.close()
    return {"ok": True}

@app.put("/api/tasks/{tid}")
def toggle_task(tid: int, u=Depends(current_user)):
      conn = get_db(); cur = conn.cursor()
    cur.execute(f"UPDATE tasks SET completed = CASE WHEN completed = 1 THEN 0 ELSE 1 END WHERE id = {P} AND user_id = {P}", (tid, u["sub"]))
    conn.commit(); conn.close()
    return {"ok": True}

@app.delete("/api/tasks/{tid}")
def del_task(tid: int, u=Depends(current_user)):
      conn = get_db(); cur = conn.cursor()
    cur.execute(f"DELETE FROM tasks WHERE id = {P} AND user_id = {P}", (tid, u["sub"]))
    conn.commit(); conn.close()
    return {"ok": True}

HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FocusFlow Cloud</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f6f9;color:#1e293b;max-width:680px;margin:32px auto;padding:0 16px}.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,.06);margin-bottom:16px}input,select,button{padding:10px 12px;border-radius:8px;border:1px solid #cbd5e1;font-size:14px}button{background:#2563eb;color:#fff;border:none;font-weight:600;cursor:pointer}.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}.task{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #e2e8f0}.done{text-decoration:line-through;color:#94a3b8}.badge{font-size:12px;padding:2px 8px;border-radius:99px;background:#e2e8f0;margin-left:6px}</style></head>
<body><div class="card" id="authBox"><h2>FocusFlow Login / Sign Up</h2><div class="row"><input id="name" placeholder="Name (for Sign Up)"><input id="email" placeholder="Email"><input id="pw" type="password" placeholder="Password"><button onclick="auth('login')">Login</button><button onclick="auth('signup')" style="background:#0f766e">Sign Up</button></div><p id="msg" style="color:#dc2626"></p></div>
<div class="card" id="appBox" style="display:none"><div style="display:flex;justify-content:space-between;align-items:center"><h2>My Synced Tasks</h2><button onclick="logout()" style="background:#64748b">Logout</button></div>
<div class="row"><input id="title" placeholder="New task..." style="flex:1"><select id="prio"><option>medium</option><option>high</option><option>low</option></select><select id="cat"><option>Personal</option><option>Work</option><option>Errands</option></select><input type="date" id="due"><button onclick="addTask()">Add</button></div>
<div id="list" style="margin-top:16px"></div></div>
<script>let tok=localStorage.getItem('ff_tok')||'';
async function api(p,m='GET',b=null){const r=await fetch(p,{method:m,headers:{'Content-Type':'application/json',...(tok?{Authorization:'Bearer '+tok}:{})},body:b?JSON.stringify(b):null});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Error');return d;}
async function auth(mode){try{const d=await api('/api/auth/'+mode,'POST',{name:name.value||'User',email:email.value,password:pw.value});tok=d.token;localStorage.setItem('ff_tok',tok);load();}catch(e){msg.textContent=e.message;}}
function logout(){tok='';localStorage.removeItem('ff_tok');authBox.style.display='block';appBox.style.display='none';}
async function load(){if(!tok)return;try{const d=await api('/api/tasks');authBox.style.display='none';appBox.style.display='block';list.innerHTML=d.tasks.map(t=>`<div class="task"><span class="${t.completed?'done':''}" onclick="toggle(${t.id})" style="cursor:pointer">${t.completed?'':'⬜'} ${t.title} <span class="badge">${t.priority}</span><span class="badge">${t.category}</span></span><button onclick="del(${t.id})" style="background:#dc2626;padding:5px 10px">✕</button></div>`).join('');}catch(e){logout();}}
async function addTask(){if(!title.value)return;await api('/api/tasks','POST',{title:title.value,priority:prio.value,category:cat.value,dueDate:due.value});title.value='';load();}
async function toggle(id){await api('/api/tasks/'+id,'PUT');load();}
async function del(id){await api('/api/tasks/'+id,'DELETE');load();}
load();</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
def index():
      return HTML
