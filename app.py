import psycopg2
import psycopg2.extras
import hashlib
import datetime
import re
import csv
import os
from functools import wraps
from flask import (Flask, request, session, redirect, url_for,
                   get_flashed_messages, flash, send_file)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key")
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
LOG_PATH  = os.path.join(BASE_DIR, "logs.txt")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:1234@localhost:5432/authshield")

app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=7)
app.config["SESSION_PERMANENT"] = True

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username   TEXT PRIMARY KEY,
            password   TEXT,
            role       TEXT,
            failed     INTEGER DEFAULT 0,
            locked     INTEGER DEFAULT 0,
            created_at TEXT,
            last_login TEXT
        )
    """)
    conn.commit()
    cur.execute("SELECT 1 FROM users WHERE username=%s", ("admin",))
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users VALUES (%s,%s,%s,%s,%s,%s,%s)",
            ("admin", hash_password("Admin@123"), "Admin", 0, 0,
             str(datetime.datetime.now()), "Never")
        )
        conn.commit()
        print("[Shield AuthShield] Default admin created -> username: admin | password: Admin@123")
    cur.close()
    conn.close()

def get_user(username):
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def is_strong_password(pw):
    if len(pw) < 8:
        return False, "At least 8 characters required"
    if not re.search(r"[A-Z]", pw):
        return False, "At least one uppercase letter required"
    if not re.search(r"[a-z]", pw):
        return False, "At least one lowercase letter required"
    if not re.search(r"\d", pw):
        return False, "At least one digit required"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        return False, "At least one special character required"
    return True, None

def write_log(msg):
    with open(LOG_PATH, "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

def flash_html():
    out = ""
    for cat, msg in get_flashed_messages(with_categories=True):
        out += f'<div class="alert alert-{cat}">{msg}</div>\n'
    return out

def fmt_dt(val):
    if not val or val == "Never":
        return "Never"
    return val[:16]

# ─────────────────────────────────────────────
# DECORATORS
# ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "Admin":
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# SHARED CSS
# ─────────────────────────────────────────────
CSS = """
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="manifest" href="/static/manifest.json">
<meta name="theme-color" content="#00e5ff">
<style>
:root{--bg:#080c10;--surface:#0d1117;--panel:#111820;--border:#1e2d3d;
--accent:#00e5ff;--green:#00ff88;--danger:#ff3e3e;--warning:#ffaa00;
--text:#c9d4e0;--muted:#4a5a6a;
--mono:'Share Tech Mono',monospace;--sans:'Rajdhani',sans-serif;}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;min-height:100vh;
background-image:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.012) 2px,rgba(0,229,255,.012) 4px);}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:0 20px;height:56px;
background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;gap:10px;}
.topbar-brand{font-family:var(--mono);font-size:14px;color:var(--accent);letter-spacing:2px;display:flex;align-items:center;gap:8px;white-space:nowrap;}
.topbar-brand .shield-icon{font-size:18px;line-height:1;}
.topbar-brand .brand-sub{font-size:9px;color:var(--muted);letter-spacing:3px;display:block;line-height:1;}
.topbar-right{display:flex;align-items:center;gap:12px;flex-shrink:0;}
.topbar-user{font-family:var(--mono);font-size:11px;color:var(--muted);}
.topbar-user strong{color:var(--green);}
.badge{font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:2px;letter-spacing:1px;text-transform:uppercase;}
.badge-admin{background:rgba(0,229,255,.12);color:var(--accent);border:1px solid rgba(0,229,255,.3);}
.badge-user{background:rgba(0,255,136,.10);color:var(--green);border:1px solid rgba(0,255,136,.25);}
.btn-logout{font-family:var(--mono);font-size:11px;padding:6px 14px;background:transparent;
border:1px solid var(--danger);color:var(--danger);text-decoration:none;letter-spacing:1px;transition:all .2s;border-radius:2px;}
.btn-logout:hover{background:var(--danger);color:#fff;}
.layout{display:flex;min-height:calc(100vh - 56px);}
.sidebar{width:225px;background:var(--surface);border-right:1px solid var(--border);padding:20px 0;flex-shrink:0;}
.sidebar-section{font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:3px;padding:0 18px 6px;text-transform:uppercase;}
.sidebar a{display:flex;align-items:center;gap:10px;padding:9px 18px;color:var(--muted);text-decoration:none;
font-family:var(--sans);font-size:14px;font-weight:500;letter-spacing:.5px;border-left:2px solid transparent;transition:all .15s;}
.sidebar a .nav-icon{font-size:15px;width:20px;text-align:center;}
.sidebar a:hover{color:var(--text);background:rgba(255,255,255,.03);}
.sidebar a.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.05);}
.sidebar-divider{margin:10px 0;border:none;border-top:1px solid var(--border);}
.main{flex:1;padding:28px 32px;overflow-x:hidden;}
.page-header{margin-bottom:24px;padding-bottom:14px;border-bottom:1px solid var(--border);}
.page-header h1{font-family:var(--sans);font-size:21px;font-weight:700;color:#fff;letter-spacing:1px;text-transform:uppercase;display:flex;align-items:center;gap:10px;}
.page-header h1 .ph-icon{font-size:20px;}
.page-header p{color:var(--muted);font-size:12px;margin-top:4px;font-family:var(--mono);}
.card{background:var(--panel);border:1px solid var(--border);border-radius:3px;padding:22px;margin-bottom:18px;}
.card-title{font-size:10px;font-family:var(--mono);letter-spacing:2px;color:var(--accent);text-transform:uppercase;margin-bottom:16px;}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:3px;padding:16px 18px;position:relative;overflow:hidden;}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);}
.stat-card.danger::before{background:var(--danger);}
.stat-card.success::before{background:var(--green);}
.stat-card.warning::before{background:var(--warning);}
.stat-emoji{font-size:20px;margin-bottom:6px;}
.stat-label{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
.stat-value{font-size:30px;font-weight:700;color:#fff;margin-top:4px;}
.profile-grid{display:grid;grid-template-columns:1fr 1fr;gap:0;background:var(--border);}
.profile-field{background:var(--panel);padding:14px 18px;}
.profile-key{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}
.profile-val{font-size:15px;font-weight:600;color:#fff;}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.form-grid.single{grid-template-columns:1fr;}
.form-group{display:flex;flex-direction:column;gap:6px;}
.form-group label{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
.form-group input,.form-group select{background:var(--bg);border:1px solid var(--border);color:var(--text);
padding:10px 14px;font-family:var(--mono);font-size:13px;border-radius:2px;outline:none;transition:border-color .2s;}
.form-group input:focus,.form-group select:focus{border-color:var(--accent);}
.form-group select option{background:var(--panel);}
.btn{font-family:var(--mono);font-size:12px;letter-spacing:1.5px;text-transform:uppercase;padding:10px 20px;
border-radius:2px;cursor:pointer;border:none;transition:all .2s;text-decoration:none;display:inline-flex;align-items:center;gap:6px;}
.btn-primary{background:var(--accent);color:#000;font-weight:700;}
.btn-primary:hover{background:#00cfec;box-shadow:0 0 18px rgba(0,229,255,.35);}
.btn-success{background:var(--green);color:#000;font-weight:700;}
.btn-success:hover{background:#00e67a;}
.btn-danger{background:transparent;border:1px solid var(--danger);color:var(--danger);}
.btn-danger:hover{background:var(--danger);color:#fff;}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--muted);}
.btn-ghost:hover{border-color:var(--text);color:var(--text);}
.btn-sm{padding:5px 12px;font-size:10px;}
.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:13px;}
thead tr{border-bottom:1px solid var(--border);}
thead th{font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;padding:10px 12px;text-align:left;}
tbody tr{border-bottom:1px solid rgba(30,45,61,.5);transition:background .1s;}
tbody tr:hover{background:rgba(255,255,255,.025);}
tbody td{padding:10px 12px;color:var(--text);}
.td-mono{font-family:var(--mono);font-size:12px;}
.alert{padding:11px 14px;border-radius:2px;font-family:var(--mono);font-size:12px;margin-bottom:18px;
border-left:3px solid;display:flex;align-items:center;gap:8px;}
.alert-success{background:rgba(0,255,136,.07);color:var(--green);border-color:var(--green);}
.alert-error{background:rgba(255,62,62,.07);color:var(--danger);border-color:var(--danger);}
.alert-warning{background:rgba(255,170,0,.07);color:var(--warning);border-color:var(--warning);}
.chip{display:inline-block;font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:2px;letter-spacing:1px;}
.chip-locked{background:rgba(255,62,62,.15);color:var(--danger);}
.chip-active{background:rgba(0,255,136,.1);color:var(--green);}
.chip-admin{background:rgba(0,229,255,.1);color:var(--accent);}
.chip-user{background:rgba(255,255,255,.06);color:var(--muted);}
.log-block{background:var(--bg);border:1px solid var(--border);border-radius:2px;padding:14px;
font-family:var(--mono);font-size:12px;color:var(--green);max-height:420px;overflow-y:auto;line-height:1.9;}
.log-ts{color:var(--muted);}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);padding:20px;
background-image:radial-gradient(ellipse 70% 50% at 50% -10%,rgba(0,229,255,.06),transparent),
repeating-linear-gradient(0deg,transparent,transparent 40px,rgba(0,229,255,.015) 40px,rgba(0,229,255,.015) 41px),
repeating-linear-gradient(90deg,transparent,transparent 40px,rgba(0,229,255,.015) 40px,rgba(0,229,255,.015) 41px);}
.login-box{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:6px;
padding:44px 40px;position:relative;box-shadow:0 20px 60px rgba(0,0,0,.6);}
.login-box::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
background:linear-gradient(90deg,var(--accent),var(--green));border-radius:6px 6px 0 0;}
.login-brand{display:flex;align-items:center;gap:10px;margin-bottom:20px;}
.login-shield{font-size:36px;line-height:1;}
.login-logo{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:4px;text-transform:uppercase;}
.login-title{font-size:24px;font-weight:700;color:#fff;letter-spacing:1px;line-height:1.2;}
.login-title em{color:var(--accent);font-style:normal;}
.login-sub{font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:28px;margin-top:6px;}
.login-box .form-group{margin-bottom:14px;}
.hamburger{display:none;flex-direction:column;justify-content:center;gap:5px;
width:38px;height:38px;cursor:pointer;background:transparent;border:1px solid var(--border);
border-radius:3px;padding:7px;flex-shrink:0;}
.hamburger span{display:block;height:2px;background:var(--accent);border-radius:2px;transition:all .25s;}
.drawer-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:300;}
.drawer-overlay.open{display:block;}
.mobile-drawer{position:fixed;top:0;left:-270px;width:265px;height:100%;
background:var(--surface);border-right:1px solid var(--border);z-index:400;
transition:left .25s ease;overflow-y:auto;display:flex;flex-direction:column;}
.mobile-drawer.open{left:0;}
.drawer-header{display:flex;align-items:center;justify-content:space-between;
padding:16px 18px 14px;border-bottom:1px solid var(--border);}
.drawer-brand{display:flex;align-items:center;gap:8px;}
.drawer-brand-icon{font-size:22px;line-height:1;}
.drawer-brand-name{font-family:var(--mono);font-size:12px;color:var(--accent);letter-spacing:2px;text-transform:uppercase;}
.drawer-close-btn{background:transparent;border:1px solid var(--border);color:var(--muted);
font-size:16px;cursor:pointer;line-height:1;padding:4px 8px;border-radius:2px;}
.mobile-drawer .sidebar-section{padding:12px 18px 5px;}
.mobile-drawer a{display:flex;align-items:center;gap:10px;padding:11px 18px;color:var(--muted);
text-decoration:none;font-family:var(--sans);font-size:14px;font-weight:500;
border-left:2px solid transparent;transition:all .15s;}
.mobile-drawer a .nav-icon{font-size:15px;width:20px;text-align:center;}
.mobile-drawer a:hover,.mobile-drawer a.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.05);}
.mobile-drawer .sidebar-divider{margin:8px 0;border:none;border-top:1px solid var(--border);}
.drawer-footer{margin-top:auto;padding:12px 6px 24px;}
.bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;
background:var(--surface);border-top:1px solid var(--border);z-index:150;
padding:4px 0 calc(4px + env(safe-area-inset-bottom,0px));}
.bn-row{display:flex;justify-content:space-around;}
.bn-item{display:flex;flex-direction:column;align-items:center;gap:3px;flex:1;
padding:7px 2px;text-decoration:none;color:var(--muted);font-family:var(--mono);
font-size:9px;letter-spacing:.3px;text-transform:uppercase;
border-top:2px solid transparent;transition:color .15s;cursor:pointer;background:transparent;border-left:none;border-right:none;border-bottom:none;}
.bn-icon{font-size:18px;line-height:1;}
.bn-item.on{color:var(--accent);border-top-color:var(--accent);}
.bn-item.danger{color:var(--danger);}
.more-popup{display:none;position:fixed;bottom:58px;left:0;right:0;
background:var(--surface);border-top:1px solid var(--border);z-index:160;padding:10px;}
.more-popup.open{display:block;}
.more-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.more-item{display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 6px;
background:var(--panel);border:1px solid var(--border);border-radius:3px;
color:var(--muted);text-decoration:none;font-family:var(--mono);font-size:10px;letter-spacing:.5px;
text-transform:uppercase;transition:all .15s;cursor:pointer;}
.more-item:hover,.more-item.on{color:var(--accent);border-color:rgba(0,229,255,.3);background:rgba(0,229,255,.04);}
.more-item-icon{font-size:20px;line-height:1;}
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
@media(max-width:768px){
  .sidebar{display:none;}
  .hamburger{display:flex;}
  .topbar-user{display:none;}
  .topbar-brand .brand-sub{display:none;}
  .form-grid{grid-template-columns:1fr;}
  .profile-grid{grid-template-columns:1fr;}
  .main{padding:18px 14px 90px;}
  .login-box{padding:36px 24px;}
  .stats-row{grid-template-columns:1fr 1fr;}
  .bottom-nav{display:block;}
  .btn-logout{display:none;}
}
@media(max-width:360px){
  .topbar-brand{font-size:12px;}
  .more-grid{grid-template-columns:repeat(2,1fr);}
}
</style>
"""

PWA_SW = """
<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/static/sw.js');
}
</script>
"""

# ─────────────────────────────────────────────
# PAGE SHELL
# ─────────────────────────────────────────────
def page_shell(content, active=""):
    uname    = session.get("username", "")
    role     = session.get("role", "")
    is_admin = role == "Admin"
    badge    = ('<span class="badge badge-admin">Admin</span>' if is_admin
                else '<span class="badge badge-user">User</span>')

    def slink(label, icon, href, key):
        cls = " active" if active == key else ""
        return f'<a href="{href}" class="{cls}"><span class="nav-icon">{icon}</span>{label}</a>\n'

    admin_sidebar = ""
    if is_admin:
        admin_sidebar = (
            '<hr class="sidebar-divider">'
            '<div class="sidebar-section">Admin</div>'
            + slink("All Users",      "👥", "/users",          "users")
            + slink("Create User",    "➕", "/create-user",     "create_user")
            + slink("Locked Users",   "🔒", "/locked-users",   "locked")
            + slink("Reset Password", "🔑", "/reset-password", "reset_pw")
            + '<hr class="sidebar-divider">'
            + '<div class="sidebar-section">Audit</div>'
            + slink("View Logs",   "📋", "/logs",        "logs")
            + slink("Export Logs", "📥", "/export-logs", "")
        )

    admin_drawer = admin_sidebar

    def bc(key): return " on" if active == key else ""

    more_popup = ""
    more_btn   = ""
    if is_admin:
        more_popup = f"""
<div class="more-popup" id="morePopup">
  <div class="more-grid">
    <a href="/users"          class="more-item{bc('users')}">      <span class="more-item-icon">👥</span>All Users</a>
    <a href="/create-user"    class="more-item{bc('create_user')}"> <span class="more-item-icon">➕</span>Create</a>
    <a href="/locked-users"   class="more-item{bc('locked')}">     <span class="more-item-icon">🔒</span>Locked</a>
    <a href="/reset-password" class="more-item{bc('reset_pw')}">   <span class="more-item-icon">🔑</span>Reset PW</a>
    <a href="/logs"           class="more-item{bc('logs')}">       <span class="more-item-icon">📋</span>Logs</a>
    <a href="/export-logs"    class="more-item">                   <span class="more-item-icon">📥</span>Export</a>
  </div>
</div>"""
        more_btn = '<button class="bn-item" id="moreBtn" onclick="toggleMore()"><span class="bn-icon">&#8943;</span>More</button>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AuthShield - Access Control</title>
{CSS}
</head>
<body>

<div class="drawer-overlay" id="drawerOverlay" onclick="closeDrawer()"></div>

<nav class="mobile-drawer" id="mobileDrawer">
  <div class="drawer-header">
    <div class="drawer-brand">
      <span class="drawer-brand-icon">🛡️</span>
      <span class="drawer-brand-name">AuthShield</span>
    </div>
    <button class="drawer-close-btn" onclick="closeDrawer()">X</button>
  </div>
  <div class="sidebar-section">Navigation</div>
  {slink("Dashboard",       "🏠", "/dashboard",      "dashboard")}
  {slink("My Profile",      "👤", "/profile",         "profile")}
  {slink("Change Password", "🔐", "/change-password", "change_pw")}
  {admin_drawer}
  <div class="drawer-footer">
    <a href="/logout" style="color:var(--danger);">
      <span class="nav-icon">🚪</span>Sign Out
    </a>
  </div>
</nav>

<header class="topbar">
  <div style="display:flex;align-items:center;gap:12px;">
    <button class="hamburger" onclick="openDrawer()" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
    <div class="topbar-brand">
      <span class="shield-icon">🛡️</span>
      <div>
        AuthShield
        <span class="brand-sub">Access Control System</span>
      </div>
    </div>
  </div>
  <div class="topbar-right">
    <div class="topbar-user">Logged in as <strong>{uname}</strong></div>
    {badge}
    <a href="/logout" class="btn-logout">Logout</a>
  </div>
</header>

<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-section">Navigation</div>
    {slink("Dashboard",       "🏠", "/dashboard",      "dashboard")}
    {slink("My Profile",      "👤", "/profile",         "profile")}
    {slink("Change Password", "🔐", "/change-password", "change_pw")}
    {admin_sidebar}
    <hr class="sidebar-divider">
    <a href="/logout" style="color:var(--danger);margin-top:4px;">
      <span class="nav-icon">🚪</span>Sign Out
    </a>
  </nav>
  <main class="main">
    {content}
  </main>
</div>

{more_popup}
<nav class="bottom-nav">
  <div class="bn-row">
    <a href="/dashboard"       class="bn-item{bc('dashboard')}"><span class="bn-icon">🏠</span>Home</a>
    <a href="/profile"         class="bn-item{bc('profile')}">  <span class="bn-icon">👤</span>Profile</a>
    <a href="/change-password" class="bn-item{bc('change_pw')}"><span class="bn-icon">🔐</span>Password</a>
    {more_btn}
    <a href="/logout" class="bn-item danger"><span class="bn-icon">🚪</span>Logout</a>
  </div>
</nav>

<script>
function openDrawer(){{
  document.getElementById('mobileDrawer').classList.add('open');
  document.getElementById('drawerOverlay').classList.add('open');
  document.body.style.overflow='hidden';
}}
function closeDrawer(){{
  document.getElementById('mobileDrawer').classList.remove('open');
  document.getElementById('drawerOverlay').classList.remove('open');
  document.body.style.overflow='';
}}
function toggleMore(){{
  var p=document.getElementById('morePopup');
  if(!p) return;
  var open=p.classList.toggle('open');
  document.body.style.overflow=open?'hidden':'';
}}
document.addEventListener('click',function(e){{
  var p=document.getElementById('morePopup');
  var b=document.getElementById('moreBtn');
  if(p&&p.classList.contains('open')&&!p.contains(e.target)&&b&&!b.contains(e.target)){{
    p.classList.remove('open');
    document.body.style.overflow='';
  }}
}});
</script>
{PWA_SW}
</body>
</html>"""

# ─────────────────────────────────────────────
# LOGIN PAGE
# ─────────────────────────────────────────────
def login_page(alerts=""):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AuthShield - Login</title>
{CSS}
</head>
<body>
<div class="login-wrap">
  <div class="login-box">
    <div class="login-brand">
      <div class="login-shield">🛡️</div>
      <div class="login-brand-text">
        <div class="login-logo">Secure Access System</div>
        <div class="login-title">Auth<em>Shield</em></div>
      </div>
    </div>
    <div class="login-sub">// Enter your credentials to continue</div>
    {alerts}
    <form method="POST" action="/login">
      <div class="form-group" style="margin-bottom:14px;">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="Enter username" autofocus required>
      </div>
      <div class="form-group" style="margin-bottom:20px;">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter password" required>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;padding:12px;font-size:13px;justify-content:center;">
        Authenticate
      </button>
    </form>
  </div>
</div>
{PWA_SW}
</body>
</html>"""

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "username" in session else url_for("login"))

# ── LOGIN ──────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        hashed   = hash_password(password)
        user     = get_user(username)

        if not user:
            flash("User not found", "error")
        elif user["locked"]:
            write_log(f"{username} attempted login on locked account")
            flash("Account locked - contact admin", "error")
        elif hashed == user["password"]:
            prev_login = user["last_login"]
            conn = get_db()
            cur  = conn.cursor()
            cur.execute("UPDATE users SET failed=0, last_login=%s WHERE username=%s",
                        (str(datetime.datetime.now()), username))
            conn.commit()
            cur.close()
            conn.close()
            session.permanent     = True
            session["username"]   = username
            session["role"]       = user["role"]
            session["created"]    = user["created_at"]
            session["last_login"] = prev_login
            write_log(f"{username} logged in")
            return redirect(url_for("dashboard"))
        else:
            failed = user["failed"] + 1
            conn = get_db()
            cur  = conn.cursor()
            if failed >= 4 and user["role"] != "Admin":
                cur.execute("UPDATE users SET failed=%s, locked=1 WHERE username=%s", (failed, username))
                conn.commit()
                cur.close()
                conn.close()
                write_log(f"{username} account locked after {failed} failed attempts")
                flash("Account locked - too many failed attempts. Contact admin.", "error")
            else:
                cur.execute("UPDATE users SET failed=%s WHERE username=%s", (failed, username))
                conn.commit()
                cur.close()
                conn.close()
                remaining = 4 - failed
                if user["role"] != "Admin":
                    flash(f"Incorrect password - {remaining} attempt(s) remaining", "warning")
                else:
                    flash("Incorrect password", "error")
                write_log(f"{username} failed login attempt #{failed}")

        return login_page(alerts=flash_html())

    return login_page(alerts=flash_html())

# ── LOGOUT ─────────────────────────────────
@app.route("/logout")
def logout():
    if "username" in session:
        write_log(f"{session['username']} logged out")
    session.clear()
    return redirect(url_for("login"))

# ── DASHBOARD ──────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    stats = {}
    if session.get("role") == "Admin":
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users"); stats["total"]  = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE locked=1"); stats["locked"] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE role='Admin'"); stats["admins"] = cur.fetchone()[0]
        stats["active"] = stats["total"] - stats["locked"]
        cur.close()
        conn.close()

    stats_html = ""
    if stats:
        stats_html = f"""<div class="stats-row">
  <div class="stat-card">        <div class="stat-emoji">👥</div><div class="stat-label">Total Users</div><div class="stat-value">{stats['total']}</div></div>
  <div class="stat-card success"><div class="stat-emoji">✅</div><div class="stat-label">Active</div>     <div class="stat-value">{stats['active']}</div></div>
  <div class="stat-card danger"> <div class="stat-emoji">🔒</div><div class="stat-label">Locked</div>     <div class="stat-value">{stats['locked']}</div></div>
  <div class="stat-card warning"><div class="stat-emoji">🛡️</div><div class="stat-label">Admins</div>     <div class="stat-value">{stats['admins']}</div></div>
</div>"""

    role_chip = ('<span class="chip chip-admin">Admin</span>' if session.get("role") == "Admin"
                 else '<span class="chip chip-user">User</span>')

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">🏠</span> Dashboard</h1>
  <p>// Welcome back, {session.get('username')} - system overview</p>
</div>
{stats_html}
<div class="card">
  <div class="card-title">Session Info</div>
  <div class="profile-grid">
    <div class="profile-field"><div class="profile-key">Logged in as</div><div class="profile-val">{session.get('username')}</div></div>
    <div class="profile-field"><div class="profile-key">Role</div><div class="profile-val">{role_chip}</div></div>
    <div class="profile-field"><div class="profile-key">Last Login</div><div class="profile-val" style="font-family:var(--mono);font-size:13px;">{session.get('last_login','Never')}</div></div>
    <div class="profile-field"><div class="profile-key">Account Created</div><div class="profile-val" style="font-family:var(--mono);font-size:13px;">{session.get('created','Never')}</div></div>
  </div>
</div>"""
    return page_shell(content, active="dashboard")

# ── PROFILE ────────────────────────────────
@app.route("/profile")
@login_required
def profile():
    role_chip = ('<span class="chip chip-admin">Admin</span>' if session.get("role") == "Admin"
                 else '<span class="chip chip-user">User</span>')
    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">👤</span> My Profile</h1>
  <p>// Your account details</p>
</div>
<div class="card">
  <div class="card-title">Account Information</div>
  <div class="profile-grid">
    <div class="profile-field"><div class="profile-key">Username</div><div class="profile-val">{session.get('username')}</div></div>
    <div class="profile-field"><div class="profile-key">Role</div><div class="profile-val">{role_chip}</div></div>
    <div class="profile-field"><div class="profile-key">Account Created</div><div class="profile-val" style="font-family:var(--mono);font-size:13px;">{session.get('created','Never')}</div></div>
    <div class="profile-field"><div class="profile-key">Last Login</div><div class="profile-val" style="font-family:var(--mono);font-size:13px;">{session.get('last_login','Never')}</div></div>
  </div>
</div>"""
    return page_shell(content, active="profile")

# ── CHANGE PASSWORD ─────────────────────────
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old     = request.form.get("old", "")
        new     = request.form.get("new_pw", "")
        confirm = request.form.get("confirm", "")
        user    = get_user(session["username"])
        if not user or hash_password(old) != user["password"]:
            flash("Incorrect current password", "error")
        elif new != confirm:
            flash("Passwords do not match", "error")
        else:
            valid, reason = is_strong_password(new)
            if not valid:
                flash(f"Weak password - {reason}", "error")
            else:
                conn = get_db()
                cur  = conn.cursor()
                cur.execute("UPDATE users SET password=%s WHERE username=%s",
                            (hash_password(new), session["username"]))
                conn.commit()
                cur.close()
                conn.close()
                write_log(f"{session['username']} changed their own password")
                flash("Password updated successfully", "success")

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">🔐</span> Change Password</h1>
  <p>// Update your credentials</p>
</div>
<div class="card" style="max-width:480px;">
  <div class="card-title">New Credentials</div>
  <form method="POST" action="/change-password">
    <div class="form-grid single">
      <div class="form-group"><label>Current Password</label>
        <input type="password" name="old" placeholder="Enter current password" required></div>
      <div class="form-group"><label>New Password</label>
        <input type="password" name="new_pw" placeholder="Min 8 chars, upper, lower, digit, special" required></div>
      <div class="form-group"><label>Confirm New Password</label>
        <input type="password" name="confirm" placeholder="Repeat new password" required></div>
    </div>
    <br>
    <button type="submit" class="btn btn-primary">Update Password</button>
  </form>
</div>"""
    return page_shell(content, active="change_pw")

# ── ALL USERS ───────────────────────────────
@app.route("/users")
@login_required
@admin_required
def users():
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users ORDER BY username")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    rows_html = ""
    for u in rows:
        uname       = u["username"]
        status_chip = '<span class="chip chip-locked">Locked</span>' if u["locked"] \
                      else '<span class="chip chip-active">Active</span>'
        role_chip   = '<span class="chip chip-admin">Admin</span>' if u["role"] == "Admin" \
                      else '<span class="chip chip-user">User</span>'
        actions     = f'<a href="/edit-user/{uname}" class="btn btn-ghost btn-sm">Edit</a> '
        if u["locked"]:
            actions += f'<a href="/unlock/{uname}" class="btn btn-success btn-sm">Unlock</a> '
        if uname != session["username"]:
            actions += (f'<a href="/delete-user/{uname}" class="btn btn-danger btn-sm" '
                        f'onclick="return confirm(\'Delete {uname}?\')">Delete</a>')
        rows_html += f"""<tr>
  <td class="td-mono" style="font-weight:600;color:#fff;">{uname}</td>
  <td>{role_chip}</td><td>{status_chip}</td>
  <td class="td-mono" style="font-size:11px;color:var(--muted);">{fmt_dt(u['created_at'])}</td>
  <td class="td-mono" style="font-size:11px;color:var(--muted);">{fmt_dt(u['last_login'])}</td>
  <td style="display:flex;gap:5px;flex-wrap:wrap;">{actions}</td>
</tr>"""

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">👥</span> All Users</h1>
  <p>// Manage system accounts</p>
</div>
<div class="card">
  <div class="card-title">User Registry</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Created</th><th>Last Login</th><th>Actions</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>"""
    return page_shell(content, active="users")

# ── CREATE USER ─────────────────────────────
@app.route("/create-user", methods=["GET", "POST"])
@login_required
@admin_required
def create_user():
    if request.method == "POST":
        new_user = request.form.get("username", "").strip()
        new_pass = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        new_role = request.form.get("role", "User").strip().capitalize()

        if not new_user:
            flash("Username cannot be empty", "error")
        elif new_pass != confirm:
            flash("Passwords do not match", "error")
        elif new_role not in ("Admin", "User"):
            flash("Invalid role selected", "error")
        else:
            valid, reason = is_strong_password(new_pass)
            if not valid:
                flash(f"Weak password - {reason}", "error")
            else:
                conn = get_db()
                cur  = conn.cursor()
                try:
                    cur.execute("INSERT INTO users VALUES (%s,%s,%s,%s,%s,%s,%s)",
                                (new_user, hash_password(new_pass), new_role,
                                 0, 0, str(datetime.datetime.now()), "Never"))
                    conn.commit()
                    write_log(f"{session['username']} created user '{new_user}' ({new_role})")
                    flash(f"User '{new_user}' created successfully", "success")
                except psycopg2.errors.UniqueViolation:
                    flash("Username already exists", "error")
                finally:
                    cur.close()
                    conn.close()

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">➕</span> Create User</h1>
  <p>// Add a new system account</p>
</div>
<div class="card" style="max-width:520px;">
  <div class="card-title">New Account</div>
  <form method="POST" action="/create-user">
    <div class="form-grid">
      <div class="form-group"><label>Username</label>
        <input type="text" name="username" placeholder="Choose username" required></div>
      <div class="form-group"><label>Role</label>
        <select name="role"><option value="User">User</option><option value="Admin">Admin</option></select></div>
      <div class="form-group"><label>Password</label>
        <input type="password" name="password" placeholder="Strong password" required></div>
      <div class="form-group"><label>Confirm Password</label>
        <input type="password" name="confirm" placeholder="Repeat password" required></div>
    </div>
    <br>
    <button type="submit" class="btn btn-primary">Create Account</button>
  </form>
</div>"""
    return page_shell(content, active="create_user")

# ── EDIT USER ───────────────────────────────
@app.route("/edit-user/<target>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(target):
    u = get_user(target)
    if not u:
        flash("User not found", "error")
        return redirect(url_for("users"))

    if request.method == "POST":
        new_role = request.form.get("role", "").strip().capitalize()
        if new_role not in ("Admin", "User"):
            flash("Invalid role", "error")
        else:
            conn = get_db()
            cur  = conn.cursor()
            cur.execute("UPDATE users SET role=%s WHERE username=%s", (new_role, target))
            conn.commit()
            cur.close()
            conn.close()
            write_log(f"{session['username']} changed role of '{target}' to '{new_role}'")
            flash(f"Role updated for '{target}'", "success")
            return redirect(url_for("users"))

    sel_u = "selected" if u["role"] == "User"  else ""
    sel_a = "selected" if u["role"] == "Admin" else ""

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">✏️</span> Edit User</h1>
  <p>// Modify role for {target}</p>
</div>
<div class="card" style="max-width:400px;">
  <div class="card-title">Update Role</div>
  <form method="POST" action="/edit-user/{target}">
    <div class="form-grid single">
      <div class="form-group"><label>Username</label>
        <input type="text" value="{target}" disabled></div>
      <div class="form-group"><label>Role</label>
        <select name="role">
          <option value="User" {sel_u}>User</option>
          <option value="Admin" {sel_a}>Admin</option>
        </select></div>
    </div>
    <br>
    <button type="submit" class="btn btn-primary">Save Changes</button>
    <a href="/users" class="btn btn-ghost" style="margin-left:10px;">Cancel</a>
  </form>
</div>"""
    return page_shell(content, active="users")

# ── DELETE USER ─────────────────────────────
@app.route("/delete-user/<target>")
@login_required
@admin_required
def delete_user(target):
    if target == session["username"]:
        flash("You cannot delete your own account", "error")
        return redirect(url_for("users"))
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=%s", (target,))
    conn.commit()
    cur.close()
    conn.close()
    write_log(f"{session['username']} deleted user '{target}'")
    flash(f"User '{target}' deleted", "success")
    return redirect(url_for("users"))

# ── LOCKED USERS ────────────────────────────
@app.route("/locked-users")
@login_required
@admin_required
def locked_users():
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT username, failed FROM users WHERE locked=1")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    if rows:
        rows_html = "".join(
            f'<tr><td class="td-mono" style="font-weight:600;color:#fff;">{r["username"]}</td>'
            f'<td style="color:var(--danger);font-family:var(--mono);font-weight:600;">{r["failed"]}</td>'
            f'<td><a href="/unlock/{r["username"]}" class="btn btn-success btn-sm">Unlock</a></td></tr>'
            for r in rows
        )
        table = f"""<div class="table-wrap"><table>
  <thead><tr><th>Username</th><th>Failed Attempts</th><th>Action</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table></div>"""
    else:
        table = '<p style="color:var(--green);font-family:var(--mono);font-size:13px;">No locked accounts</p>'

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">🔒</span> Locked Users</h1>
  <p>// Accounts pending review</p>
</div>
<div class="card"><div class="card-title">Locked Accounts</div>{table}</div>"""
    return page_shell(content, active="locked")

# ── UNLOCK ──────────────────────────────────
@app.route("/unlock/<target>")
@login_required
@admin_required
def unlock_user(target):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE users SET locked=0, failed=0 WHERE username=%s", (target,))
    conn.commit()
    cur.close()
    conn.close()
    write_log(f"{session['username']} unlocked user '{target}'")
    flash(f"User '{target}' unlocked", "success")
    return redirect(url_for("locked_users"))

# ── RESET PASSWORD ──────────────────────────
@app.route("/reset-password", methods=["GET", "POST"])
@login_required
@admin_required
def reset_password():
    if request.method == "POST":
        target   = request.form.get("username", "").strip()
        new_pass = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        u = get_user(target)
        if not u:
            flash("User not found", "error")
        elif new_pass != confirm:
            flash("Passwords do not match", "error")
        else:
            valid, reason = is_strong_password(new_pass)
            if not valid:
                flash(f"Weak password - {reason}", "error")
            else:
                conn = get_db()
                cur  = conn.cursor()
                cur.execute("UPDATE users SET password=%s, failed=0, locked=0 WHERE username=%s",
                            (hash_password(new_pass), target))
                conn.commit()
                cur.close()
                conn.close()
                write_log(f"{session['username']} reset password for '{target}'")
                flash(f"Password reset for '{target}'", "success")

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">🔑</span> Reset Password</h1>
  <p>// Force password reset for any user</p>
</div>
<div class="card" style="max-width:480px;">
  <div class="card-title">Admin Password Reset</div>
  <form method="POST" action="/reset-password">
    <div class="form-grid single">
      <div class="form-group"><label>Target Username</label>
        <input type="text" name="username" placeholder="Username to reset" required></div>
      <div class="form-group"><label>New Password</label>
        <input type="password" name="password" placeholder="Strong new password" required></div>
      <div class="form-group"><label>Confirm Password</label>
        <input type="password" name="confirm" placeholder="Repeat new password" required></div>
    </div>
    <br>
    <button type="submit" class="btn btn-primary">Reset Password</button>
  </form>
</div>"""
    return page_shell(content, active="reset_pw")

# ── VIEW LOGS ───────────────────────────────
@app.route("/logs")
@login_required
@admin_required
def view_logs():
    log_entries = ""
    try:
        with open(LOG_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" - ", 1)
                ts    = parts[0] if len(parts) > 0 else ""
                event = parts[1] if len(parts) > 1 else line
                log_entries += f'<div><span class="log-ts">{ts}</span>  &mdash;  {event}</div>\n'
    except FileNotFoundError:
        pass

    if not log_entries:
        log_entries = '<span style="color:var(--muted);">No log entries yet.</span>'

    content = f"""{flash_html()}
<div class="page-header">
  <h1><span class="ph-icon">📋</span> System Logs</h1>
  <p>// Full audit trail of all activity</p>
</div>
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
    <div class="card-title" style="margin-bottom:0;">Event Log</div>
    <a href="/export-logs" class="btn btn-ghost btn-sm">Export CSV</a>
  </div>
  <div class="log-block">{log_entries}</div>
</div>"""
    return page_shell(content, active="logs")

# ── EXPORT LOGS ─────────────────────────────
@app.route("/export-logs")
@login_required
@admin_required
def export_logs():
    if not os.path.exists(LOG_PATH):
        flash("No logs to export", "warning")
        return redirect(url_for("view_logs"))

    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(BASE_DIR, f"logs_export_{ts}.csv")

    with open(LOG_PATH) as lf, open(out_path, "w", newline="") as cf:
        w = csv.writer(cf)
        w.writerow(["Timestamp", "Event"])
        for line in lf:
            line = line.strip()
            if " - " in line:
                parts = line.split(" - ", 1)
                w.writerow([parts[0], parts[1]])
            else:
                w.writerow(["", line])

    write_log(f"{session['username']} exported logs to {os.path.basename(out_path)}")
    return send_file(os.path.abspath(out_path), as_attachment=True,
                     download_name=os.path.basename(out_path))

# ── ERROR HANDLERS ──────────────────────────
@app.errorhandler(404)
def not_found(e):
    content = """
<div style="text-align:center;padding:60px 20px;">
  <div style="font-size:64px;margin-bottom:16px;">🔍</div>
  <div style="font-family:var(--mono);font-size:48px;color:var(--danger);margin-bottom:8px;">404</div>
  <div style="font-size:18px;font-weight:700;color:#fff;margin-bottom:8px;">Page Not Found</div>
  <div style="font-family:var(--mono);font-size:12px;color:var(--muted);margin-bottom:28px;">// The page you requested does not exist</div>
  <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
</div>"""
    if "username" in session:
        return page_shell(content), 404
    return content, 404

@app.errorhandler(500)
def server_error(e):
    write_log(f"SERVER ERROR: {str(e)}")
    return "Internal server error - check logs.", 500

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 55)
    print("  AuthShield - Access Control System")
    print("  URL  : http://127.0.0.1:5000")
    print("  Login: admin / Admin@123")
    print("  Change the default password after first login!")
    print("=" * 55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False,
            threaded=True, use_reloader=False)
            
          
  
