from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import smtplib
import sqlite3
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DB_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "trialtrap.db"))
FRONTEND = ROOT_DIR / "index.html"
TOKEN_SECRET = os.getenv("TRIALTRAP_SECRET", "change-this-secret-in-production")

app = FastAPI(title="TrialTrap AI", version="3.0.0", description="AI-powered subscription monitoring and free-trial protection platform")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        cost REAL NOT NULL,
        billing_cycle TEXT NOT NULL DEFAULT 'monthly',
        renewal_date TEXT NOT NULL,
        plan_type TEXT NOT NULL DEFAULT 'paid',
        trial_end_date TEXT,
        category TEXT NOT NULL DEFAULT 'Other',
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'info',
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notification_settings (
        user_id INTEGER PRIMARY KEY,
        email_enabled INTEGER NOT NULL DEFAULT 0,
        whatsapp_enabled INTEGER NOT NULL DEFAULT 0,
        email_address TEXT DEFAULT '',
        whatsapp_number TEXT DEFAULT '',
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    # Migrate old single-user subscription table from previous versions.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(subscriptions)").fetchall()}
    if cols and "user_id" not in cols:
        conn.execute("ALTER TABLE subscriptions RENAME TO subscriptions_legacy")
        conn.execute("""CREATE TABLE subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
            cost REAL NOT NULL, billing_cycle TEXT NOT NULL DEFAULT 'monthly', renewal_date TEXT NOT NULL,
            plan_type TEXT NOT NULL DEFAULT 'paid', trial_end_date TEXT, category TEXT NOT NULL DEFAULT 'Other',
            notes TEXT DEFAULT '', created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)""")
        legacy = conn.execute("SELECT * FROM subscriptions_legacy").fetchall()
        if legacy:
            email = "demo@trialtrap.local"
            ph = hash_password("demo1234")
            cur = conn.execute("INSERT OR IGNORE INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)", ("Demo User", email, ph, datetime.utcnow().isoformat()))
            user_id = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()[0]
            for r in legacy:
                conn.execute("""INSERT INTO subscriptions(user_id,name,cost,billing_cycle,renewal_date,plan_type,trial_end_date,category,notes,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""", (user_id, r[1], r[2], r[3], r[4], r[5] if len(r)>5 else 'paid', r[6] if len(r)>6 else None, 'Other', '', datetime.utcnow().isoformat()))
        conn.execute("DROP TABLE subscriptions_legacy")
    conn.commit(); conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 210_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def make_token(user_id: int) -> str:
    payload = f"{user_id}:{int(datetime.utcnow().timestamp())}"
    sig = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def current_user(authorization: Optional[str]) -> sqlite3.Row:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Login required")
    token = authorization.split(" ", 1)[1]
    try:
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest(), sig):
            raise ValueError
        user_id = int(payload.split(":", 1)[0])
    except Exception:
        raise HTTPException(401, "Invalid session")
    conn = get_db(); user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone(); conn.close()
    if not user: raise HTTPException(401, "User not found")
    return user


class AuthIn(BaseModel):
    name: str = "User"
    email: str
    password: str = Field(min_length=6, max_length=100)

class SubscriptionIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    cost: float = Field(ge=0)
    billing_cycle: str = "monthly"
    renewal_date: str
    plan_type: str = "paid"
    trial_end_date: Optional[str] = None
    category: str = "Other"
    notes: str = ""
    @field_validator("billing_cycle")
    @classmethod
    def cycle(cls, v):
        v=v.lower().strip()
        if v not in {"monthly","yearly"}: raise ValueError("Billing cycle must be monthly or yearly")
        return v
    @field_validator("plan_type")
    @classmethod
    def plan(cls,v):
        v=v.lower().strip()
        if v not in {"paid","free_trial"}: raise ValueError("Plan type must be paid or free_trial")
        return v
    @field_validator("renewal_date","trial_end_date")
    @classmethod
    def dt(cls,v):
        if not v: return v
        datetime.strptime(v,"%Y-%m-%d"); return v

class AssistantIn(BaseModel):
    message: str = Field(min_length=1, max_length=1000)

class SettingsIn(BaseModel):
    email_enabled: bool = False
    whatsapp_enabled: bool = False
    email_address: str = ""
    whatsapp_number: str = ""

init_db()

@app.get("/")
def home():
    return {"message":"TrialTrap AI is running!", "version":"3.0.0", "status":"success"}

@app.get("/health")
def health(): return {"status":"healthy"}

@app.get("/app")
def app_page():
    return FileResponse(FRONTEND)

@app.get("/manifest.json")
def manifest():
    return FileResponse(ROOT_DIR / "manifest.json", media_type="application/manifest+json")

@app.get("/service-worker.js")
def service_worker():
    return FileResponse(ROOT_DIR / "service-worker.js", media_type="application/javascript")

@app.post("/api/auth/register")
def register(data: AuthIn):
    email=data.email.strip().lower()
    if "@" not in email: raise HTTPException(400,"Enter a valid email")
    conn=get_db()
    try:
        cur=conn.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",(data.name.strip() or "User",email,hash_password(data.password),datetime.utcnow().isoformat()))
        uid=cur.lastrowid
        conn.execute("INSERT INTO notification_settings(user_id,email_address) VALUES(?,?)",(uid,email)); conn.commit()
    except sqlite3.IntegrityError: conn.close(); raise HTTPException(409,"Email already registered")
    conn.close(); return {"token":make_token(uid),"user":{"id":uid,"name":data.name.strip() or "User","email":email}}

@app.post("/api/auth/login")
def login(data: AuthIn):
    conn=get_db(); user=conn.execute("SELECT * FROM users WHERE email=?",(data.email.strip().lower(),)).fetchone(); conn.close()
    if not user or not verify_password(data.password,user["password_hash"]): raise HTTPException(401,"Invalid email or password")
    return {"token":make_token(user["id"]),"user":{"id":user["id"],"name":user["name"],"email":user["email"]}}

@app.get("/api/me")
def me(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); return {"id":u["id"],"name":u["name"],"email":u["email"]}


def row_to_dict(r): return dict(r)

def user_subscriptions(uid):
    conn=get_db(); rows=conn.execute("SELECT * FROM subscriptions WHERE user_id=? ORDER BY renewal_date ASC,id DESC",(uid,)).fetchall(); conn.close(); return [row_to_dict(r) for r in rows]

def days_until(v):
    if not v:return None
    return (datetime.strptime(v,"%Y-%m-%d").date()-date.today()).days

def monthly_cost(r): return float(r["cost"])/(12 if r["billing_cycle"]=="yearly" else 1)

def create_notification(uid,title,message,kind="info"):
    conn=get_db(); conn.execute("INSERT INTO notifications(user_id,title,message,kind,created_at) VALUES(?,?,?,?,?)",(uid,title,message,kind,datetime.utcnow().isoformat())); conn.commit(); conn.close()

@app.get("/api/subscriptions")
def subscriptions(authorization: Optional[str]=Header(None)):
    return user_subscriptions(current_user(authorization)["id"])

@app.post("/api/subscriptions")
def add_subscription(data: SubscriptionIn, authorization: Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]
    if data.plan_type=="free_trial" and not data.trial_end_date: raise HTTPException(400,"Free trial requires a trial end date")
    conn=get_db(); cur=conn.execute("""INSERT INTO subscriptions(user_id,name,cost,billing_cycle,renewal_date,plan_type,trial_end_date,category,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",(uid,data.name.strip(),data.cost,data.billing_cycle,data.renewal_date,data.plan_type,data.trial_end_date,data.category.strip() or "Other",data.notes,datetime.utcnow().isoformat())); conn.commit(); sid=cur.lastrowid; conn.close()
    return {"message":"Subscription added","id":sid}

@app.put("/api/subscriptions/{sid}")
def update_subscription(sid:int,data:SubscriptionIn,authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]
    if data.plan_type=="free_trial" and not data.trial_end_date: raise HTTPException(400,"Free trial requires a trial end date")
    conn=get_db(); cur=conn.execute("""UPDATE subscriptions SET name=?,cost=?,billing_cycle=?,renewal_date=?,plan_type=?,trial_end_date=?,category=?,notes=? WHERE id=? AND user_id=?""",(data.name.strip(),data.cost,data.billing_cycle,data.renewal_date,data.plan_type,data.trial_end_date,data.category.strip() or "Other",data.notes,sid,uid)); conn.commit(); ok=cur.rowcount; conn.close()
    if not ok: raise HTTPException(404,"Subscription not found")
    return {"message":"Subscription updated"}

@app.delete("/api/subscriptions/{sid}")
def delete_subscription(sid:int,authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); cur=conn.execute("DELETE FROM subscriptions WHERE id=? AND user_id=?",(sid,uid)); conn.commit(); ok=cur.rowcount; conn.close()
    if not ok: raise HTTPException(404,"Subscription not found")
    return {"message":"Subscription deleted"}

@app.get("/api/dashboard")
def dashboard(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; rows=user_subscriptions(uid)
    monthly=sum(monthly_cost(r) for r in rows); yearly=monthly*12
    alerts=[]; active_trials=0; expiring=0; potential=0
    for r in rows:
        rd=days_until(r["renewal_date"]); td=days_until(r["trial_end_date"]); trial=r["plan_type"]=="free_trial"
        if trial and td is not None and td>=0: active_trials+=1
        if rd is not None and 0<=rd<=7:
            expiring+=1; alerts.append({"type":"renewal","subscription":r["name"],"days_left":rd,"date":r["renewal_date"],"message":f"{r['name']} renews in {rd} days" if rd>1 else (f"{r['name']} renews tomorrow" if rd==1 else f"{r['name']} renews today"),"cost":r["cost"]})
        if trial and td is not None and td<=7:
            if td>=0: potential += float(r["cost"])
            alerts.append({"type":"trial","subscription":r["name"],"days_left":td,"date":r["trial_end_date"],"message":f"{r['name']} free trial ends in {td} days" if td>1 else (f"{r['name']} free trial ends tomorrow" if td==1 else f"{r['name']} free trial ends today" if td==0 else f"{r['name']} free trial expired"),"cost":r["cost"]})
    alerts.sort(key=lambda x:(x["days_left"]<0,x["days_left"]))
    insights=[]
    if rows:
        expensive=max(rows,key=monthly_cost); insights.append(f"{expensive['name']} is your highest monthly-equivalent cost at ₹{monthly_cost(expensive):,.0f}.")
        if yearly>10000: insights.append(f"Your current subscriptions project to about ₹{yearly:,.0f} per year.")
        if active_trials: insights.append(f"You have {active_trials} active free trial(s). Review their end dates to avoid surprise charges.")
        if potential: insights.append(f"₹{potential:,.0f} of trial charges may be approaching within 7 days.")
    return {"total_subscriptions":len(rows),"monthly_spend":round(monthly,2),"yearly_spend":round(yearly,2),"expiring_soon":expiring,"active_trials":active_trials,"potential_trial_charges":round(potential,2),"alerts":alerts,"insights":insights}

@app.get("/api/notifications")
def notifications(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); rows=conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50",(uid,)).fetchall(); unread=conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",(uid,)).fetchone()[0]; conn.close(); return {"items":[dict(r) for r in rows],"unread":unread}

@app.post("/api/notifications/read")
def mark_notifications_read(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(uid,)); conn.commit(); conn.close(); return {"message":"Notifications marked read"}

@app.get("/api/settings")
def get_settings(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); r=conn.execute("SELECT email_enabled,whatsapp_enabled,email_address,whatsapp_number FROM notification_settings WHERE user_id=?",(uid,)).fetchone(); conn.close(); return dict(r) if r else {}

@app.put("/api/settings")
def save_settings(data:SettingsIn,authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); conn.execute("INSERT INTO notification_settings(user_id,email_enabled,whatsapp_enabled,email_address,whatsapp_number) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET email_enabled=excluded.email_enabled,whatsapp_enabled=excluded.whatsapp_enabled,email_address=excluded.email_address,whatsapp_number=excluded.whatsapp_number",(uid,int(data.email_enabled),int(data.whatsapp_enabled),data.email_address.strip(),data.whatsapp_number.strip())); conn.commit(); conn.close(); return {"message":"Settings saved"}


def local_agent(message, rows, dash):
    q=message.lower().strip()
    if any(x in q for x in ["spend","cost","waste","expensive","money"]):
        if not rows:return "You have no subscriptions yet. Add a subscription and I can analyze your spending."
        top=sorted(rows,key=monthly_cost,reverse=True)[:3]
        return "Your top monthly-equivalent costs are: " + ", ".join(f"{r['name']} ₹{monthly_cost(r):,.0f}" for r in top) + f". Total projected spend is ₹{dash['monthly_spend']:,.0f}/month or ₹{dash['yearly_spend']:,.0f}/year."
    if any(x in q for x in ["trial","free"]):
        trials=[r for r in rows if r["plan_type"]=="free_trial"]
        if not trials:return "You currently have no free trials tracked. Add one with Plan Type = Free Trial."
        return "Tracked free trials: " + ", ".join(f"{r['name']} (ends {r['trial_end_date']})" for r in trials) + ". I recommend reviewing any trial ending within 7 days."
    if any(x in q for x in ["renew","upcoming","week","alert"]):
        upcoming=[a for a in dash["alerts"] if a["type"]=="renewal"]
        return "Upcoming renewals: " + (", ".join(f"{a['subscription']} in {a['days_left']} day(s)" for a in upcoming) if upcoming else "none in the next 7 days") + "."
    if "save" in q or "cancel" in q:
        if not rows:return "Add subscriptions first. Then I can identify high-cost items and potential trial charges for review."
        top=sorted(rows,key=monthly_cost,reverse=True)[:2]
        return "Potential review candidates based on cost are " + " and ".join(r["name"] for r in top) + ". This is a data-based prompt for review, not an automatic cancellation decision."
    return "I can analyze spending, free trials, renewals, yearly projections and potential savings. Try: 'Where am I spending the most?', 'What renews this week?', or 'Show my free trials'."

@app.post("/api/ai/assistant")
def assistant(data:AssistantIn,authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; rows=user_subscriptions(uid)
    # Deterministic local agent is always available. Optional LLM hook can be enabled later via an external provider.
    dash=dashboard(authorization)
    answer=local_agent(data.message,rows,dash)
    return {"answer":answer,"mode":"local-smart-agent"}

@app.post("/api/ai/parse-subscription")
def parse_subscription(data:AssistantIn,authorization:Optional[str]=Header(None)):
    current_user(authorization)
    text=data.message
    import re
    amount=re.search(r"(?:₹|rs\.?|inr\s*)(\d+(?:\.\d+)?)",text,re.I)
    date_m=re.search(r"(20\d{2}-\d{2}-\d{2})",text)
    cycle="yearly" if re.search(r"year|annual|yearly",text,re.I) else "monthly"
    trial="trial" in text.lower()
    name=text.split(" for ")[0].strip()[:80] if " for " in text.lower() else text[:80]
    return {"name":name,"cost":float(amount.group(1)) if amount else 0,"billing_cycle":cycle,"renewal_date":date_m.group(1) if date_m else "","plan_type":"free_trial" if trial else "paid","trial_end_date":date_m.group(1) if trial and date_m else None,"category":"Other"}

@app.get("/api/export.csv")
def export_csv(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; rows=user_subscriptions(uid); out=io.StringIO(); w=csv.writer(out); w.writerow(["name","cost","billing_cycle","renewal_date","plan_type","trial_end_date","category","notes"])
    for r in rows:w.writerow([r[k] for k in ["name","cost","billing_cycle","renewal_date","plan_type","trial_end_date","category","notes"]])
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=trialtrap-subscriptions.csv"})

@app.get("/api/calendar.ics")
def calendar(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; rows=user_subscriptions(uid); lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//TrialTrap AI//EN"]
    for r in rows:
        d=datetime.strptime(r["renewal_date"],"%Y-%m-%d").strftime("%Y%m%d"); lines += ["BEGIN:VEVENT",f"UID:trialtrap-{r['id']}@local",f"DTSTART;VALUE=DATE:{d}",f"SUMMARY:TrialTrap: {r['name']} renewal",f"DESCRIPTION:Review {r['name']} before renewal. Amount ₹{r['cost']}","END:VEVENT"]
    lines.append("END:VCALENDAR")
    return StreamingResponse(iter(["\r\n".join(lines)]),media_type="text/calendar",headers={"Content-Disposition":"attachment; filename=trialtrap-renewals.ics"})

@app.post("/api/notifications/test-email")
def test_email(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); s=conn.execute("SELECT * FROM notification_settings WHERE user_id=?",(uid,)).fetchone(); conn.close()
    if not s or not s["email_address"]: raise HTTPException(400,"Set an email address in Settings first")
    host=os.getenv("SMTP_HOST"); port=int(os.getenv("SMTP_PORT","587")); user=os.getenv("SMTP_USER"); pwd=os.getenv("SMTP_PASSWORD"); sender=os.getenv("SMTP_FROM",user or "")
    if not host or not user or not pwd: raise HTTPException(400,"SMTP is not configured. Add SMTP_HOST, SMTP_USER and SMTP_PASSWORD to .env")
    msg=EmailMessage(); msg["Subject"]="TrialTrap AI test alert"; msg["From"]=sender; msg["To"]=s["email_address"]; msg.set_content("TrialTrap AI email notifications are configured successfully.")
    try:
        with smtplib.SMTP(host,port) as smtp:
            smtp.starttls(); smtp.login(user,pwd); smtp.send_message(msg)
    except Exception as e: raise HTTPException(502,f"Email provider error: {e}")
    return {"message":"Test email sent"}

@app.post("/api/notifications/test-whatsapp")
def test_whatsapp(authorization:Optional[str]=Header(None)):
    uid=current_user(authorization)["id"]; conn=get_db(); s=conn.execute("SELECT * FROM notification_settings WHERE user_id=?",(uid,)).fetchone(); conn.close()
    if not s or not s["whatsapp_number"]: raise HTTPException(400,"Set a WhatsApp number in Settings first")
    # Optional Twilio integration. No credentials are stored in the database.
    sid=os.getenv("TWILIO_ACCOUNT_SID"); token=os.getenv("TWILIO_AUTH_TOKEN"); sender=os.getenv("TWILIO_WHATSAPP_FROM")
    if not sid or not token or not sender: raise HTTPException(400,"WhatsApp provider is not configured. Add Twilio credentials to .env")
    try:
        from urllib.request import Request, urlopen
        import urllib.parse
        body=urllib.parse.urlencode({"From":sender,"To":"whatsapp:"+s["whatsapp_number"],"Body":"TrialTrap AI test alert: WhatsApp notifications are configured."}).encode()
        auth=(sid+":"+token).encode(); import base64
        req=Request(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",data=body,headers={"Authorization":"Basic "+base64.b64encode(auth).decode()})
        with urlopen(req,timeout=15) as resp: resp.read()
    except Exception as e: raise HTTPException(502,f"WhatsApp provider error: {e}")
    return {"message":"WhatsApp test sent"}

