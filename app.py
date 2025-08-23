# app.py
"""
Folk Arts Portal - Single-file Streamlit app with local secure authentication.
Run: streamlit run app.py

Dependencies: streamlit (pip install streamlit)
Optional: openai (pip install openai) to enable chatbot features.

Security notes:
- Passwords are hashed with PBKDF2-HMAC-SHA256 and per-user salt (no plain text storage).
- Sessions are managed in-memory (Streamlit session_state) and optionally via a local
  .session_token file for "remember me" convenience on the same machine.
- This is appropriate for local dev and lightweight deployments. For public deployments,
  use HTTPS, a managed auth provider, and stronger secrets management.
"""
import streamlit as st
import os
import sqlite3
import hashlib
import secrets
import base64
import json
from datetime import datetime
from pathlib import Path

# Optional OpenAI import (only used if user enables)
try:
    import openai # type: ignore
except Exception:
    openai = None

# -------------------------
# App config
# -------------------------
st.set_page_config(page_title="Folk Arts Portal (Auth)", page_icon="🎨", layout="wide")

DB_PATH = Path("users.db")
SESSION_TOKEN_FILE = Path(".session_token")
ARTISTS_FILE = Path("artists.json")

# PBKDF2 parameters
HASH_NAME = "sha256"
ITERATIONS = 200_000  # reasonably high for local dev
SALT_BYTES = 16
KEY_LEN = 32

# -------------------------
# Database helpers
# -------------------------
def get_db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    # users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
        """
    )
    # leaderboards / gamification
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS leaderboard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            points INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

def user_exists(username):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username.lower(),))
    found = cur.fetchone() is not None
    conn.close()
    return found

def create_user(username, password, role="user"):
    username = username.strip().lower()
    if user_exists(username):
        return False, "Username already exists."
    salt = secrets.token_bytes(SALT_BYTES)
    password_hash = hash_password(password, salt)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, base64.b64encode(salt).decode(), base64.b64encode(password_hash).decode(), role, datetime.utcnow().isoformat()),
    )
    conn.commit()
    # also add to leaderboard
    cur.execute("INSERT INTO leaderboard (username, points, updated_at) VALUES (?, ?, ?)", (username, 0, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return True, "User created."

def get_user_record(username):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username.lower(),))
    row = cur.fetchone()
    conn.close()
    return row

def update_password(username, new_password):
    salt = secrets.token_bytes(SALT_BYTES)
    password_hash = hash_password(new_password, salt)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET salt = ?, password_hash = ? WHERE username = ?", (base64.b64encode(salt).decode(), base64.b64encode(password_hash).decode(), username.lower()))
    conn.commit()
    conn.close()

def list_users():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, role, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------------------
# Password hashing (PBKDF2)
# -------------------------
def hash_password(password: str, salt: bytes) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(HASH_NAME, password, salt, ITERATIONS, dklen=KEY_LEN)

def verify_password(stored_hash_b64: str, stored_salt_b64: str, provided_password: str) -> bool:
    try:
        stored_hash = base64.b64decode(stored_hash_b64)
        salt = base64.b64decode(stored_salt_b64)
    except Exception:
        return False
    candidate = hash_password(provided_password, salt)
    return secrets.compare_digest(candidate, stored_hash)

# -------------------------
# Session & token helpers
# -------------------------
def generate_session_token():
    return secrets.token_urlsafe(32)

def save_local_session_token(token: str):
    try:
        SESSION_TOKEN_FILE.write_text(token)
        # restrict file permissions (best-effort)
        try:
            os.chmod(SESSION_TOKEN_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass

def load_local_session_token():
    try:
        if SESSION_TOKEN_FILE.exists():
            return SESSION_TOKEN_FILE.read_text().strip()
    except Exception:
        pass
    return None

def clear_local_session_token():
    try:
        if SESSION_TOKEN_FILE.exists():
            SESSION_TOKEN_FILE.unlink()
    except Exception:
        pass

# -------------------------
# Initialize DB and default admin
# -------------------------
init_db()
# Create a default admin user if none exists
if not user_exists("admin"):
    # default admin password (change on first login)
    create_user("admin", "Admin@123", role="admin")

# -------------------------
# Artist helpers (reuse earlier logic)
# -------------------------
def load_artists():
    if ARTISTS_FILE.exists():
        try:
            with open(ARTISTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_artists(artists):
    with open(ARTISTS_FILE, "w", encoding="utf-8") as f:
        json.dump(artists, f, ensure_ascii=False, indent=2)

def add_artist(entry):
    artists = load_artists()
    artists.append(entry)
    save_artists(artists)

# -------------------------
# Leaderboard helpers
# -------------------------
def add_points(username, points):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, points FROM leaderboard WHERE username = ?", (username,))
    row = cur.fetchone()
    now = datetime.utcnow().isoformat()
    if row:
        new_points = row["points"] + int(points)
        cur.execute("UPDATE leaderboard SET points = ?, updated_at = ? WHERE id = ?", (new_points, now, row["id"]))
    else:
        cur.execute("INSERT INTO leaderboard (username, points, updated_at) VALUES (?, ?, ?)", (username, int(points), now))
    conn.commit()
    conn.close()

def get_leaderboard(top_n=10):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, points, updated_at FROM leaderboard ORDER BY points DESC LIMIT ?", (top_n,))
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------------------
# Auth UI
# -------------------------
def show_auth_ui():
    st.sidebar.title("🔐 Account")
    auth_mode = st.sidebar.radio("Action", ["Login", "Sign up", "Change password", "Logout"], index=0)

    if "auth" not in st.session_state:
        st.session_state.auth = {"logged_in": False, "username": None, "role": None, "token": None}

    if auth_mode == "Login":
        username = st.sidebar.text_input("Username", key="login_user")
        password = st.sidebar.text_input("Password", type="password", key="login_pass")
        remember = st.sidebar.checkbox("Remember me on this machine", value=False)
        if st.sidebar.button("Log in"):
            user = get_user_record(username)
            if not user:
                st.sidebar.error("Invalid username or password.")
            else:
                ok = verify_password(user["password_hash"], user["salt"], password)
                if ok:
                    # create session token and set session state
                    token = generate_session_token()
                    st.session_state.auth = {"logged_in": True, "username": username.lower(), "role": user["role"], "token": token}
                    if remember:
                        save_local_session_token(token + "|" + username.lower())
                    st.experimental_rerun()
                else:
                    st.sidebar.error("Invalid username or password.")
        # try local token auto-login
        if "auto_try" not in st.session_state:
            st.session_state.auto_try = True
            local = load_local_session_token()
            if local:
                try:
                    token, uname = local.split("|", 1)
                    user = get_user_record(uname)
                    if user:
                        st.session_state.auth = {"logged_in": True, "username": uname, "role": user["role"], "token": token}
                        st.experimental_rerun()
                except Exception:
                    pass

    elif auth_mode == "Sign up":
        st.sidebar.markdown("Create a new account")
        new_user = st.sidebar.text_input("Choose a username", key="su_user")
        new_pass = st.sidebar.text_input("Choose a password", type="password", key="su_pass")
        confirm_pass = st.sidebar.text_input("Confirm password", type="password", key="su_pass2")
        if st.sidebar.button("Create account"):
            if not new_user or not new_pass:
                st.sidebar.error("Enter username and password.")
            elif new_pass != confirm_pass:
                st.sidebar.error("Passwords do not match.")
            else:
                ok, msg = create_user(new_user, new_pass, role="user")
                if ok:
                    st.sidebar.success("Account created. Please log in.")
                else:
                    st.sidebar.error(msg)

    elif auth_mode == "Change password":
        if not st.session_state.auth.get("logged_in"):
            st.sidebar.info("Log in to change your password.")
        else:
            st.sidebar.markdown(f"Change password for **{st.session_state.auth['username']}**")
            cur_pass = st.sidebar.text_input("Current password", type="password", key="cp_cur")
            new_pass = st.sidebar.text_input("New password", type="password", key="cp_new")
            new_pass2 = st.sidebar.text_input("Confirm new password", type="password", key="cp_new2")
            if st.sidebar.button("Update password"):
                user = get_user_record(st.session_state.auth["username"])
                if not user or not verify_password(user["password_hash"], user["salt"], cur_pass):
                    st.sidebar.error("Current password is incorrect.")
                elif new_pass != new_pass2:
                    st.sidebar.error("New passwords do not match.")
                else:
                    update_password(st.session_state.auth["username"], new_pass)
                    st.sidebar.success("Password changed. Please log in again.")
                    # log out
                    st.session_state.auth = {"logged_in": False, "username": None, "role": None, "token": None}
                    clear_local_session_token()
                    st.experimental_rerun()

    elif auth_mode == "Logout":
        if st.sidebar.button("Log out"):
            st.session_state.auth = {"logged_in": False, "username": None, "role": None, "token": None}
            clear_local_session_token()
            st.sidebar.success("Logged out.")
            st.experimental_rerun()

# -------------------------
# Main app UI (gated)
# -------------------------
show_auth_ui()

if not st.session_state.get("auth", {}).get("logged_in"):
    st.title("🎨 Folk Arts Portal — Login required")
    st.markdown(
        """
        This portal requires a registered account. Use the sidebar to log in or sign up.
        A default admin user is created for first-time setup:
        **username:** `admin`  **password:** `Admin@123` (please change it after logging in)
        """
    )
    st.stop()

# From here, user is authenticated
username = st.session_state.auth["username"]
role = st.session_state.auth["role"]

# -------------------------
# Header with logo + user info
# -------------------------
DEFAULT_LOGO = "https://i.ibb.co/3vYc6k8/folk-logo.png"
logo_url = os.getenv("FOLK_LOGO_URL", DEFAULT_LOGO)
cols = st.columns([1, 7, 2])
with cols[0]:
    st.image(logo_url, width=88)
with cols[1]:
    st.markdown("<h1 style='margin:0'>🎨 Folk Arts Portal</h1>", unsafe_allow_html=True)
    st.markdown("<div style='color:#666;margin-top:-6px'>Preserving India's folk arts — secure, modular, and ready to extend</div>", unsafe_allow_html=True)
with cols[2]:
    st.markdown(f"**Logged in as:** `{username}`  ")
    st.markdown(f"**Role:** `{role}`")

st.markdown("---")

# -------------------------
# Navigation
# -------------------------
PAGES = ["Home", "AI Chatbot", "Dashboard", "Artist Directory", "Upload Images", "Gamification", "Admin"]
if "page" not in st.session_state:
    st.session_state.page = "Home"

with st.sidebar.expander("🔎 Navigate", expanded=True):
    choice = st.radio("", PAGES, index=PAGES.index(st.session_state.page))
    st.session_state.page = choice

# -------------------------
# Page implementations
# -------------------------
def page_home():
    st.header("Welcome"+ username)
    st.markdown("""
    This is a production-ready local portal scaffold:
    - Secure login & user management (local SQLite)
    - Artist directory (local JSON)
    - Image upload & gallery
    - Chatbot scaffold (OpenAI optional)
    - Gamification + leaderboard
    """)

    st.image("https://i.ibb.co/bJy6SpH/folk-art-banner.jpg", caption="Celebrating India's folk heritage", use_column_width=True)

    # quick stats
    artists = load_artists()
    lb = get_leaderboard(5)
    cols = st.columns(3)
    cols[0].metric("Registered Users", len(list_users()))
    cols[1].metric("Artists", len(artists))
    cols[2].metric("Your points", next((r["points"] for r in get_leaderboard(100) if r["username"] == username), 0))

    st.markdown("### Quick actions")
    c1, c2, c3 = st.columns(3)
    if c1.button("Add demo artists"):
        demo_1 = {
            "name": "Ramesh Kumar",
            "style": "Warli & Madhubani",
            "bio": "Ramesh has dedicated over 20 years to preserving traditional Warli and Madhubani art. His creations combine cultural storytelling with vibrant natural motifs.",
            "contact": "",
            "image_url": ""
        }
        demo_2 = {
            "name": "Janaki Kumari",
            "style": "Madhubani",
            "bio": "Janaki Kumari has dedicated over 15 years to perfecting Madhubani techniques passed down through generations.",
            "contact": "",
            "image_url": ""
        }
        add_artist(demo_1)
        add_artist(demo_2)
        st.success("Demo artists added.")

    if c2.button("Claim 10 points (demo)"):
        add_points(username, 10)
        st.success("Added 10 points to your account.")

    if c3.button("View leaderboard"):
        st.session_state.page = "Gamification"
        st.experimental_rerun()

def page_chatbot():
    st.header("AI Chatbot — Cultural Assistant")
    st.markdown("Ask about artists, styles, motifs, materials. Optional OpenAI integration available.")

    # allow user to paste API key per session
    if not st.session_state.get("OPENAI_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        key_input = st.text_input("Paste OpenAI API key (optional, stored in session only)", type="password")
        if st.button("Save API key"):
            st.session_state["OPENAI_API_KEY"] = key_input.strip()
            st.success("Saved key for this session.")

    openai_key = st.session_state.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if openai_key and openai:
        openai.api_key = openai_key
    elif openai_key and not openai:
        st.warning("You provided a key but the `openai` package is not installed. Install with `pip install openai`.")
    else:
        st.info("Chatbot will work in offline mode (helpful tips). Provide an OpenAI key for richer answers.")

    q = st.text_area("Ask a question about folk arts", placeholder="What pigments are traditionally used in Madhubani?")
    if st.button("Ask"):
        if not q.strip():
            st.warning("Type a question.")
        else:
            if openai_key and openai:
                try:
                    resp = openai.ChatCompletion.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "system", "content": "You are a helpful assistant specialized in Indian folk arts."},
                                  {"role": "user", "content": q}],
                        max_tokens=350,
                        temperature=0.7
                    )
                    answer = resp["choices"][0]["message"]["content"]
                    st.markdown("**Answer:**")
                    st.write(answer)
                except Exception as e:
                    st.error(f"OpenAI call error: {e}")
            else:
                # offline fallback
                st.markdown("**Answer (offline tips):**")
                st.write("- Try asking about visual motifs (animals, plants) and regional differences.\n- Many traditional pigments come from natural sources: turmeric, indigo, soot, rice paste, ochre.")

def page_dashboard():
    st.header("Dashboard")
    st.markdown("Basic analytics scaffold — extend with real data collection.")

    artists = load_artists()
    lb = get_leaderboard(10)
    st.subheader("Artists")
    for a in artists:
        st.write(f"**{a.get('name','')}** — {a.get('style','')}")
        st.write(a.get("bio",""))
        st.write("----")

    st.subheader("Leaderboard (Top 10)")
    rows = get_leaderboard(10)
    if rows:
        st.table([{ "username": r["username"], "points": r["points"], "updated_at": r["updated_at"] } for r in rows])
    else:
        st.write("No leaderboard data yet.")

def page_artist_directory():
    st.header("Artist Directory")
    st.markdown("Add, edit, and manage artist profiles (stored locally).")

    artists = load_artists()
    st.write(f"Total artists: {len(artists)}")

    with st.expander("➕ Add new artist"):
        with st.form("add_artist"):
            name = st.text_input("Name")
            style = st.text_input("Primary style (e.g., Madhubani)")
            bio = st.text_area("Short bio")
            contact = st.text_input("Contact / link")
            image_url = st.text_input("Image URL (optional)")
            submitted = st.form_submit_button("Add")
            if submitted:
                if not name.strip():
                    st.warning("Name required.")
                else:
                    entry = {"name": name.strip(), "style": style.strip(), "bio": bio.strip(), "contact": contact.strip(), "image_url": image_url.strip()}
                    add_artist(entry)
                    st.success("Artist added.")
                    st.experimental_rerun()

    # display & edit per-entry (simple)
    for idx, art in enumerate(artists):
        with st.expander(f"{art.get('name','Unknown')} — {art.get('style','')}"):
            cols = st.columns([1, 4, 1])
            with cols[0]:
                if art.get("image_url"):
                    st.image(art["image_url"], width=120)
                else:
                    st.write("No image")
            with cols[1]:
                st.markdown(f"**{art.get('name','')}**")
                st.write(art.get("bio",""))
            with cols[2]:
                if st.button(f"Delete##{idx}"):
                    artists.pop(idx)
                    save_artists(artists)
                    st.success("Deleted.")
                    st.experimental_rerun()

def page_upload_images():
    st.header("Upload Gallery Images")
    st.markdown("Upload artwork images which are stored under /uploads directory.")

    uploaded = st.file_uploader("Choose image files", type=["jpg", "jpeg", "png"], accept_multiple_files=True)
    if uploaded:
        outdir = Path("uploads")
        outdir.mkdir(exist_ok=True)
        saved = []
        for file in uploaded:
            target = outdir / file.name
            with open(target, "wb") as f:
                f.write(file.read())
            saved.append(str(target))
        st.success(f"Saved {len(saved)} files to {outdir.resolve()}")
        for p in saved:
            st.image(p, width=200)

def page_gamification():
    st.header("Gamification & Leaderboard")
    st.markdown("Earn points by participating. Demo actions below add points to your account.")

    st.markdown("### Claim demo points")
    col1, col2, col3 = st.columns(3)
    if col1.button("Complete tutorial (+5)"):
        add_points(username, 5)
        st.success("Added 5 points.")
    if col2.button("Upload art (+8)"):
        add_points(username, 8)
        st.success("Added 8 points.")
    if col3.button("Share profile (+3)"):
        add_points(username, 3)
        st.success("Added 3 points.")

    st.markdown("### Leaderboard")
    rows = get_leaderboard(20)
    if rows:
        st.table([{ "username": r["username"], "points": r["points"], "updated_at": r["updated_at"] } for r in rows])
    else:
        st.write("No points yet — be the first!")

def page_admin():
    st.header("Admin Console")
    if role != "admin":
        st.warning("Admin features are visible only to admin users.")
        return

    st.subheader("Registered users")
    rows = list_users()
    for r in rows:
        st.write(f"- {r['username']}  (role: {r['role']}, created: {r['created_at']})")
    st.markdown("---")
    st.subheader("Admin actions")
    col1, col2 = st.columns(2)
    with col1:
        uname = st.text_input("Reset password for user (username)", key="admin_reset_user")
        new_pass = st.text_input("New password", type="password", key="admin_reset_pass")
        if st.button("Reset password"):
            if not uname or not new_pass:
                st.warning("Enter username and new password.")
            else:
                if not user_exists(uname):
                    st.error("User not found.")
                else:
                    update_password(uname, new_pass)
                    st.success(f"Password updated for {uname}.")
    with col2:
        if st.button("Export user list to users_export.json"):
            users = [{"username": u["username"], "role": u["role"], "created_at": u["created_at"]} for u in list_users()]
            Path("users_export.json").write_text(json.dumps(users, indent=2))
            st.success("Exported to users_export.json")

# -------------------------
# Router
# -------------------------
if st.session_state.page == "Home":
    page_home()
elif st.session_state.page == "AI Chatbot":
    page_chatbot()
elif st.session_state.page == "Dashboard":
    page_dashboard()
elif st.session_state.page == "Artist Directory":
    page_artist_directory()
elif st.session_state.page == "Upload Images":
    page_upload_images()
elif st.session_state.page == "Gamification":
    page_gamification()
elif st.session_state.page == "Admin":
    page_admin()
else:
    st.write("Page not found.")

st.markdown("---")
st.markdown("© Folk Arts Portal • Built with Streamlit — extend freely.")
