from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import string
import time
import urllib.request


PORT = int(os.environ.get("PORT", "8000"))
APP_NAME = "MacroTracker"

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_MONTHLY_PRICE_ID = os.environ.get("STRIPE_MONTHLY_PRICE_ID", "")
STRIPE_YEARLY_PRICE_ID = os.environ.get("STRIPE_YEARLY_PRICE_ID", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
BASE_URL = os.environ.get("BASE_URL", f"http://127.0.0.1:{PORT}")

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
COMPLAINTS_FILE = os.path.join(DATA_DIR, "complaints.json")


def ensure_data_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    for path in (USERS_FILE, COMPLAINTS_FILE):
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump([], f)


def read_json(path):
    ensure_data_files()
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, value):
    ensure_data_files()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2)


def make_friend_code():
    alphabet = string.ascii_uppercase + string.digits
    existing = {u.get("friendCode") for u in read_json(USERS_FILE)}
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(6))
        if code not in existing:
            return code


def upsert_user(email, **updates):
    email = (email or "").strip().lower()
    if not email:
        return None
    users = read_json(USERS_FILE)
    existing = None
    for user in users:
        if user.get("email", "").lower() == email:
            existing = user
            break
    if existing is None:
        existing = {"email": email, "premium": False, "friendCode": make_friend_code(), "createdAt": int(time.time())}
        users.append(existing)
    if not existing.get("friendCode"):
        existing["friendCode"] = make_friend_code()
    existing.update(updates)
    write_json(USERS_FILE, users)
    return existing


def public_user(user):
    clean = dict(user or {})
    clean.pop("passwordHash", None)
    clean.pop("passwordSalt", None)
    return clean


def get_user(email):
    email = (email or "").strip().lower()
    for user in read_json(USERS_FILE):
        if user.get("email", "").lower() == email:
            return user
    return {"email": email, "premium": False}


def get_user_by_friend_code(code):
    code = (code or "").strip().upper()
    for user in read_json(USERS_FILE):
        if user.get("friendCode", "").upper() == code:
            return user
    return None


def set_user_password(email, password):
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")
    salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()
    return upsert_user(email, passwordSalt=salt, passwordHash=hashed)


def verify_user_password(email, password):
    user = get_user(email)
    salt = user.get("passwordSalt")
    stored = user.get("passwordHash")
    if not salt or not stored:
        return False
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()
    return hmac.compare_digest(hashed, stored)



def json_response(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def text_response(handler, status, text, content_type="text/plain"):
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def create_stripe_checkout(email, plan):
    if not STRIPE_SECRET_KEY:
        raise RuntimeError("Missing STRIPE_SECRET_KEY")

    price_id = STRIPE_YEARLY_PRICE_ID if plan == "yearly" else STRIPE_MONTHLY_PRICE_ID
    if not price_id:
        raise RuntimeError("Missing Stripe Price ID for selected plan")

    form = urlencode({
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "customer_email": email,
        "client_reference_id": email,
        "metadata[email]": email,
        "metadata[plan]": plan,
        "success_url": BASE_URL + "/?checkout=success",
        "cancel_url": BASE_URL + "/?checkout=cancel",
        "allow_promotion_codes": "true",
        "billing_address_collection": "auto"
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.stripe.com/v1/checkout/sessions",
        data=form,
        headers={
            "Authorization": "Bearer " + STRIPE_SECRET_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.loads(res.read().decode("utf-8"))


def verify_stripe_signature(payload, signature_header):
    if not STRIPE_WEBHOOK_SECRET:
        return False
    parts = {}
    for item in signature_header.split(","):
        if "=" in item:
            key, value = item.split("=", 1)
            parts.setdefault(key, []).append(value)
    timestamp = parts.get("t", [""])[0]
    signatures = parts.get("v1", [])
    signed = (timestamp + "." + payload.decode("utf-8")).encode("utf-8")
    expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, sig) for sig in signatures)


def fallback_food_estimate():
    return {
        "name": "Estimated meal",
        "cal": 520,
        "p": 32,
        "c": 55,
        "f": 18,
        "note": "OpenAI is not configured, so this is a local fallback estimate."
    }


def ai_food_estimate(image_data_url, scan_type="meal"):
    if not OPENAI_API_KEY:
        return fallback_food_estimate()

    prompts = {
        "label": (
            "Read the nutrition label in this image. Return only valid JSON with keys "
            "name, cal, p, c, f, note. Use one serving if the label is visible. cal is "
            "calories. p, c, and f are grams. If a value is unreadable, estimate carefully "
            "and explain briefly in note."
        ),
        "recipe": (
            "Estimate the recipe or homemade food in this image. Return only valid JSON "
            "with keys name, cal, p, c, f, note. cal is calories. p, c, and f are grams. "
            "Estimate the visible portion and mention it is recipe/photo based in note."
        ),
        "meal": (
            "Estimate the food in this image. Return only valid JSON with keys "
            "name, cal, p, c, f, note. cal is calories. p, c, and f are grams. "
            "Be realistic for the visible serving size. Keep note short."
        )
    }
    prompt = prompts.get(scan_type, prompts["meal"])
    payload = {
        "model": OPENAI_MODEL,
        "input": [{
            "role": "user",
            "content": [
                {"type": "input_text", "text": prompt},
                {"type": "input_image", "image_url": image_data_url}
            ]
        }]
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + OPENAI_API_KEY,
            "Content-Type": "application/json"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as res:
            data = json.loads(res.read().decode("utf-8"))
        text = data.get("output_text", "")
        if not text:
            chunks = []
            for item in data.get("output", []):
                for content in item.get("content", []):
                    if content.get("text"):
                        chunks.append(content["text"])
            text = "\n".join(chunks)
        parsed = json.loads(text[text.find("{"):text.rfind("}") + 1])
        return {
            "name": str(parsed.get("name", "AI scanned food")),
            "cal": int(float(parsed.get("cal", 0))),
            "p": int(float(parsed.get("p", 0))),
            "c": int(float(parsed.get("c", 0))),
            "f": int(float(parsed.get("f", 0))),
            "note": str(parsed.get("note", "AI estimate."))
        }
    except Exception as exc:
        result = fallback_food_estimate()
        result["note"] = "AI scan failed. " + str(exc)[:90]
        return result


MANIFEST = {
    "name": APP_NAME,
    "short_name": "MacroTracker",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#f7fbff",
    "theme_color": "#0b63ce",
    "description": "Track calories, macros, real foods, AI food scans, and barcode logging.",
    "icons": []
}


SERVICE_WORKER = """
self.addEventListener('install', event => {
  event.waitUntil(caches.open('macrotracker-v1').then(cache => cache.addAll(['/'])));
});
self.addEventListener('fetch', event => {
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
"""


APP = r'''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MacroTracker</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0b63ce">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="MacroTracker">
<style>
*{box-sizing:border-box}
:root{
  --bg:#f7fbff;--card:#fff;--ink:#081625;--muted:#607087;--line:#d9e7f7;
  --blue:#0b63ce;--blue2:#54a3ff;--soft:#eaf4ff;--protein:#1e88e5;--carbs:#f6c343;--fat:#e53935;
  --shadow:0 16px 36px rgba(20,72,130,.12)
}
body.dark{
  --bg:#05080d;--card:#101722;--ink:#f5f9ff;--muted:#9aa8ba;--line:#243347;
  --blue:#2f8cff;--blue2:#72b6ff;--soft:#11273f;--shadow:0 18px 42px rgba(0,0,0,.35)
}
body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,Arial,sans-serif}
.shell{max-width:1120px;margin:auto;padding:14px}
header{position:relative;overflow:hidden;background:linear-gradient(135deg,var(--blue),var(--blue2));color:white;padding:22px 16px 78px;border-bottom-left-radius:24px;border-bottom-right-radius:24px}
.gearButton{position:absolute;top:18px;right:18px;width:46px;height:46px;border-radius:50%;display:grid;place-items:center;background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.42);color:white;font-size:24px;z-index:3}
.brand{display:flex;align-items:center;gap:12px;max-width:1120px;margin:auto}
.logo{width:54px;height:54px;border-radius:16px;background:radial-gradient(circle at 28% 24%,#fff 0 16%,#dff0ff 17% 36%,#fff 37% 100%);color:var(--blue);display:grid;place-items:center;font-weight:900;font-size:20px;letter-spacing:.5px;box-shadow:0 14px 30px rgba(0,0,0,.18);position:relative;overflow:hidden}
.logo:after{content:"";position:absolute;right:8px;bottom:8px;width:16px;height:16px;border-radius:50%;background:linear-gradient(135deg,var(--blue),var(--blue2));box-shadow:-12px -10px 0 -5px #f6c343}
.brand h1{margin:0;font-size:30px}.brand p{margin:4px 0 0;opacity:.92}
.hero{max-width:1120px;margin:18px auto 0;display:grid;grid-template-columns:1.15fr .85fr;gap:18px;align-items:end}
.hero h2{font-size:36px;line-height:1.04;margin:0 0 10px}.hero p{font-size:16px;line-height:1.5;opacity:.95;margin:0}
.hero img{width:100%;height:210px;object-fit:cover;border-radius:18px;box-shadow:0 18px 42px rgba(0,0,0,.25)}
.tabs{position:sticky;top:0;z-index:10;margin-top:-52px;padding:8px;background:rgba(255,255,255,.86);backdrop-filter:blur(14px);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);display:grid;grid-template-columns:repeat(9,1fr);gap:6px}
body.dark .tabs{background:rgba(16,23,34,.86)}
button,input,select,textarea{width:100%;font:inherit;border-radius:12px;border:1px solid var(--line);padding:12px;background:var(--card);color:var(--ink)}
button{border:0;background:var(--blue);color:white;font-weight:800;cursor:pointer;transition:transform .22s ease,filter .22s ease}
button:active{transform:scale(.98)}button:hover{filter:brightness(1.04)}
button.secondary{background:var(--soft);color:var(--ink)}button.gold{background:#f6c343;color:#251f03}
.tabs button{padding:10px 6px;font-size:13px;background:transparent;color:var(--ink)}.tabs button.active{background:var(--blue);color:white}
section{display:none;margin-top:14px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:var(--shadow);animation:rise .45s ease both}
section.active{display:block}@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
h2{margin:0 0 12px;font-size:24px}.small{color:var(--muted);font-size:14px;line-height:1.45}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.stat,.card{background:var(--soft);border:1px solid var(--line);border-radius:16px;padding:14px}.stat strong{display:block;font-size:27px;margin-top:4px}
.foodCard{overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:16px}.foodCard img{width:100%;height:130px;object-fit:cover}.foodCard div{padding:12px}
.badge{display:inline-block;margin:4px 4px 0 0;padding:5px 8px;border-radius:999px;background:var(--soft);font-size:13px}.premiumBadge{background:linear-gradient(135deg,#0b63ce,#f6c343);color:white}
.track{height:16px;border-radius:999px;overflow:hidden;background:rgba(125,150,180,.22)}.bar{height:100%;width:0;transition:width 1.05s cubic-bezier(.2,.8,.2,1)}.protein{background:var(--protein)}.carbs{background:var(--carbs)}.fat{background:var(--fat)}.calories{background:var(--blue)}
.macroTop{display:flex;justify-content:space-between;margin:12px 0 6px;font-size:14px}.meal,.foodRow{padding:12px 0;border-bottom:1px solid var(--line)}.meal:last-child,.foodRow:last-child{border:0}.mealGroup{margin-top:14px;border:1px solid var(--line);border-radius:16px;overflow:hidden;background:var(--card)}.mealHead{display:flex;justify-content:space-between;gap:10px;padding:12px 14px;background:var(--soft);font-weight:900}.mealBody{padding:0 14px}.emptyMeal{padding:12px 0;color:var(--muted);font-size:14px}.chart{display:flex;align-items:end;gap:10px;height:230px;padding:16px;border:1px solid var(--line);border-radius:16px;background:var(--soft);overflow-x:auto}.barWrap{min-width:52px;display:flex;flex-direction:column;align-items:center;gap:6px}.chartBar{width:34px;border-radius:10px 10px 4px 4px;background:linear-gradient(180deg,var(--blue2),var(--blue));height:0;transition:height 1.05s cubic-bezier(.2,.8,.2,1)}.chartBar.weight{background:linear-gradient(180deg,#f6c343,#0b63ce)}.chartLabel{font-size:12px;color:var(--muted);text-align:center}.avatar{width:112px;height:112px;border-radius:22px;object-fit:cover;background:var(--soft);border:1px solid var(--line);display:grid;place-items:center;font-weight:900;font-size:34px;color:var(--blue)}.friendCode{font-size:28px;font-weight:900;letter-spacing:3px}
.camera{overflow:hidden;border-radius:16px;background:#05080d;margin:10px 0}.camera video,.preview{width:100%;display:block}.locked{filter:saturate(.6);opacity:.7}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:50;padding:14px}.modal.open{display:flex}.modalBox{max-width:560px;width:100%;background:var(--card);border-radius:20px;padding:20px;border:1px solid var(--line)}
label{display:block;font-weight:800;margin:12px 0 6px}textarea{min-height:120px;resize:vertical}
@media(max-width:820px){.hero{grid-template-columns:1fr}.hero img{height:170px}.tabs{grid-template-columns:repeat(4,1fr)}.cards{grid-template-columns:1fr 1fr}}
@media(max-width:560px){.shell{padding:10px}.grid,.cards{grid-template-columns:1fr}.hero h2{font-size:29px}.brand h1{font-size:25px}.tabs button{font-size:12px}}
</style>
</head>
<body>
<header>
  <button class="gearButton" onclick="showTab('settings')" aria-label="Settings" title="Settings">⚙</button>
  <div class="brand"><div class="logo">MT</div><div><h1>MacroTracker</h1><p>Calories, macros, barcode logging, and Premium AI meal scans.</p></div></div>
  <div class="hero">
    <div><h2>Professional macro tracking that feels simple.</h2><p>Plan your calories, log real foods, scan barcodes, and unlock AI photo estimates with Premium.</p></div>
    <img alt="Healthy meal bowl" src="https://images.unsplash.com/photo-1546069901-ba9599a7e63c?auto=format&fit=crop&w=900&q=80">
  </div>
</header>
<main class="shell">
  <nav class="tabs" id="tabs">
    <button data-tab="dashboard" onclick="showTab('dashboard')">Home</button>
    <button data-tab="account" onclick="showTab('account')">Account</button>
    <button data-tab="profile" onclick="showTab('profile')">Profile</button>
    <button data-tab="foods" onclick="showTab('foods')">Foods</button>
    <button data-tab="scan" onclick="showTab('scan')">Scan</button>
    <button data-tab="hydration" onclick="showTab('hydration')">Hydration</button>
    <button data-tab="progress" onclick="showTab('progress')">Progress</button>
    <button data-tab="shop" onclick="showTab('shop')">Premium</button>
    <button data-tab="support" onclick="showTab('support')">Support</button>
  </nav>

  <section id="dashboard">
    <h2>Today</h2>
    <div class="grid">
      <div class="stat">Calories eaten<strong id="eatenCalories">0</strong></div>
      <div class="stat">Remaining<strong id="remainingCalories">0</strong></div>
      <div class="stat">Protein<strong id="logProtein">0g</strong></div>
      <div class="stat">Premium<strong id="premiumLabel">Free</strong></div>
    </div>
    <div id="logBars"></div>
    <h2 style="margin-top:20px">Food Log</h2>
    <div id="logList"></div>
  </section>

  <section id="account">
    <h2>Account Login</h2>
    <p class="small">Log in or sign up first, then complete your profile setup next.</p>
    <div class="grid">
      <div><label>Email</label><input id="loginEmail" type="email" placeholder="you@example.com"></div>
      <div><label>Password</label><input id="loginPassword" type="password" placeholder="At least 6 characters"></div>
    </div>
    <div class="grid" style="margin-top:14px">
      <button onclick="loginAccount()">Log in</button>
      <button class="secondary" onclick="createOrUpdateAccount()">Create / update password</button>
    </div>
    <button class="secondary" onclick="findAccount()" style="margin-top:12px">Find account by email</button>
    <button class="secondary" onclick="logoutAccount()" style="margin-top:12px">Log out on this device</button>
    <div id="accountStatus" class="small" style="margin-top:12px"></div>
  </section>

  <section id="profile">
    <h2>Your Profile</h2>
    <div class="card" style="margin-bottom:14px">
      <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
        <img id="profilePhotoPreview" class="avatar" alt="Profile photo" style="display:none">
        <div id="profileInitials" class="avatar">MT</div>
        <div style="flex:1;min-width:220px">
          <b id="profileCardName">Your profile</b>
          <p class="small" id="profileCardEmail">Finish profile setup to unlock the app.</p>
          <label>Take or upload profile picture</label>
          <input id="profilePhotoInput" type="file" accept="image/*" capture="user" onchange="loadProfilePhoto(event)">
        </div>
      </div>
    </div>
    <div class="grid">
      <div><label>Email</label><input id="profileEmail" type="email" disabled></div>
      <div><label>Full name</label><input id="profileName"></div>
      <div><label>Date of birth</label><input id="profileDob" type="date"></div>
      <div><label>Sex</label><select id="sex"><option value="female">Female</option><option value="male">Male</option></select></div>
      <div><label>Age</label><input id="age" type="number" value="25"></div>
      <div><label>Height</label><input id="height" type="number" value="165"></div>
      <div><label>Height unit</label><select id="heightUnit"><option value="cm">cm</option><option value="in">inches</option></select></div>
      <div><label>Weight</label><input id="weight" type="number" value="70"></div>
      <div><label>Weight unit</label><select id="weightUnit"><option value="kg">kg</option><option value="lb">lb</option></select></div>
      <div><label>Activity</label><select id="activity"><option value="1.2">Little exercise</option><option value="1.375">Light exercise</option><option value="1.55">Moderate exercise</option><option value="1.725">Hard exercise</option><option value="1.9">Athlete</option></select></div>
      <div><label>Goal</label><select id="goal"><option value="lose">Lose weight</option><option value="maintain">Maintain</option><option value="gain">Gain muscle</option></select></div>
    </div>
    <button onclick="saveProfile()" style="margin-top:14px">Save and calculate plan</button>
    <div class="card" style="margin-top:14px">
      <b>Friends</b>
      <p class="small">Share your friend code or add someone else's code.</p>
      <div class="friendCode" id="friendCodeDisplay">------</div>
      <div class="grid" style="margin-top:12px">
        <input id="friendCodeInput" placeholder="Friend code">
        <button onclick="addFriendByCode()">Add friend</button>
      </div>
      <div id="friendsList" style="margin-top:12px"></div>
    </div>
    <div id="targetCards" style="margin-top:14px"></div>
    <div class="card" style="margin-top:14px">
      <span class="badge premiumBadge">Premium</span>
      <b>Custom macro plan</b>
      <p class="small">Premium members can set calories and choose exactly what percentage comes from protein, carbs, and fat.</p>
      <div class="grid">
        <div><label>Calories</label><input id="customCalories" type="number" min="800" value="2000"></div>
        <div><label>Protein %</label><input id="proteinPct" type="number" min="0" max="100" value="30"></div>
        <div><label>Carbs %</label><input id="carbsPct" type="number" min="0" max="100" value="40"></div>
        <div><label>Fat %</label><input id="fatPct" type="number" min="0" max="100" value="30"></div>
      </div>
      <button onclick="applyPremiumPlan()" style="margin-top:12px">Apply custom plan</button>
      <div id="planAdvisory" class="small" style="margin-top:10px"></div>
    </div>
    <h2 style="margin-top:20px">Suggested Meals</h2>
    <div id="mealPlan"></div>
  </section>

  <section id="foods">
    <h2>Real Foods</h2>
    <input id="search" placeholder="Search chicken, rice, eggs..." oninput="renderFoods()">
    <div class="cards" id="foodCards" style="margin-top:14px"></div>
  </section>

  <section id="scan">
    <h2>Scan</h2>
    <div class="card" id="aiLockCard">
      <span class="badge premiumBadge">Premium</span>
      <b>AI meal, label, and recipe scan</b>
      <p class="small">Premium members can estimate macros from meals, nutrition labels, and homemade recipe photos.</p>
      <button onclick="startFoodCamera()">Open food camera</button>
      <div class="camera" id="foodCamBox" style="display:none"><video id="foodVideo" autoplay playsinline></video></div>
      <button class="secondary" onclick="snapFood()">Scan meal photo</button>
      <input type="file" id="foodPhotoInput" accept="image/*" capture="environment" onchange="scanUploadedFood(event)">
      <label>Scan nutrition label</label>
      <input type="file" id="labelPhotoInput" accept="image/*" capture="environment" onchange="scanUploadedTyped(event,'label')">
      <label>Scan homemade recipe</label>
      <input type="file" id="recipePhotoInput" accept="image/*" capture="environment" onchange="scanUploadedTyped(event,'recipe')">
      <canvas id="foodCanvas" style="display:none"></canvas>
      <div id="aiResult" class="small">Unlock Premium to use AI scan.</div>
    </div>
    <div class="card" style="margin-top:14px">
      <b>Custom or corrected food data</b>
      <p class="small">Use this when a label, barcode, restaurant site, or AI scan has different numbers.</p>
      <div class="grid">
        <div><label>Food name</label><input id="customName" placeholder="Example: My chicken pasta"></div>
        <div><label>Calories</label><input id="customCal" type="number" min="0" value="0"></div>
        <div><label>Protein grams</label><input id="customP" type="number" min="0" value="0"></div>
        <div><label>Carbs grams</label><input id="customC" type="number" min="0" value="0"></div>
        <div><label>Fat grams</label><input id="customF" type="number" min="0" value="0"></div>
        <div><label>Source</label><input id="customSource" placeholder="Label, restaurant site, package, recipe"></div>
      </div>
      <button onclick="addCustomFood()" style="margin-top:12px">Add custom food</button>
    </div>
    <div class="card" style="margin-top:14px">
      <b>Barcode logger</b>
      <p class="small">Works in supported mobile browsers. Manual entry is always available.</p>
      <button onclick="startBarcodeScanner()">Start barcode scan</button>
      <div class="camera" id="barcodeBox" style="display:none"><video id="barcodeVideo" autoplay playsinline></video></div>
      <label>Barcode</label><input id="barcodeInput" placeholder="Example: 012000001640">
      <button class="secondary" onclick="lookupBarcode()">Log barcode</button>
      <div id="barcodeResult" class="small"></div>
    </div>
  </section>

  <section id="shop">
    <h2>MacroTracker Premium</h2>
    <div class="grid">
      <div class="card"><span class="badge premiumBadge">Best value</span><h2>$25 / year</h2><p class="small">Unlock AI scan for a full year.</p><button onclick="buyPremium('yearly')">Buy yearly</button></div>
      <div class="card"><span class="badge">Flexible</span><h2>$5 / month</h2><p class="small">Premium month to month.</p><button onclick="buyPremium('monthly')">Buy monthly</button></div>
    </div>
    <p class="small">Payments are handled by Stripe Checkout. Your app never stores raw card numbers.</p>
  </section>

  <section id="hydration">
    <h2>Hydration</h2>
    <div class="grid">
      <div class="stat">Water today<strong id="waterOunces">0 oz</strong></div>
      <div class="stat">Goal progress<strong id="waterProgress">0%</strong></div>
    </div>
    <div style="margin-top:12px">
      <div class="macroTop"><b>Daily water goal</b><span id="waterGoalLabel">64 oz</span></div>
      <div class="track"><div id="waterBar" class="bar calories"></div></div>
    </div>
    <div class="grid" style="margin-top:14px">
      <button onclick="changeWater(8)">+8 oz</button>
      <button class="secondary" onclick="changeWater(-8)">-8 oz</button>
      <button onclick="changeWater(16)">+16 oz</button>
      <button class="secondary" onclick="changeWater(-16)">-16 oz</button>
    </div>
    <label>Custom ounces</label>
    <input id="waterCustom" type="number" min="1" value="12">
    <div class="grid">
      <button onclick="changeWater(+waterCustom.value||0)">Add ounces</button>
      <button class="secondary" onclick="changeWater(-(+waterCustom.value||0))">Subtract ounces</button>
    </div>
    <label>Daily goal ounces</label>
    <input id="waterGoalInput" type="number" min="1" value="64" onchange="setWaterGoal()">
    <button class="secondary" onclick="resetWater()" style="margin-top:12px">Reset hydration today</button>
  </section>

  <section id="progress">
    <h2>Progress Charts</h2>
    <p class="small">Log your weight and today’s calories to track changes across past days.</p>
    <div class="grid">
      <div><label>Date</label><input id="progressDate" type="date"></div>
      <div><label>Weight</label><input id="progressWeight" type="number" step="0.1" placeholder="Example: 165.4"></div>
      <div><label>Calories</label><input id="progressCalories" type="number" min="0" placeholder="Auto fills from today"></div>
      <div><label>Weight unit</label><select id="progressUnit"><option value="lb">lb</option><option value="kg">kg</option></select></div>
    </div>
    <button onclick="saveProgressEntry()" style="margin-top:12px">Save progress entry</button>
    <h2 style="margin-top:20px">Calories</h2>
    <div id="calorieChart" class="chart"></div>
    <h2 style="margin-top:20px">Weight fluctuation</h2>
    <div id="weightChart" class="chart"></div>
    <div id="progressList" style="margin-top:14px"></div>
  </section>

  <section id="support">
    <h2>Complaint and Bug Report</h2>
    <p class="small">Send bugs, complaints, broken food data, billing issues, or feature requests.</p>
    <label>Subject</label><input id="complaintSubject" placeholder="What went wrong?">
    <label>Priority</label><select id="complaintPriority"><option>Bug</option><option>Billing</option><option>Food data</option><option>Feature request</option><option>Complaint</option></select>
    <label>Details</label><textarea id="complaintBody" placeholder="Describe the issue so it can be patched."></textarea>
    <button onclick="submitComplaint()">Submit report</button>
    <div id="complaintStatus" class="small"></div>
  </section>

  <section id="settings">
    <h2>Settings</h2>
    <div class="grid">
      <button class="secondary" onclick="toggleDark()">Toggle dark mode</button>
      <button class="secondary" onclick="resetToday()">Reset today</button>
    </div>
    <p class="small">Light mode is white and blue. Dark mode is black and blue.</p>
  </section>
</main>

<div class="modal" id="onboardingModal">
  <div class="modalBox">
    <div class="brand" style="color:var(--ink);margin-bottom:12px"><div class="logo">MT</div><div><h2 style="margin:0">Set up MacroTracker</h2><p class="small" style="margin:3px 0">Finish this once before entering the app.</p></div></div>
    <label>Email</label><input id="onEmail" type="email" placeholder="you@example.com">
    <label>Full name</label><input id="onName" placeholder="Your name">
    <label>Date of birth</label><input id="onDob" type="date">
    <label>Password</label><input id="onPassword" type="password" placeholder="At least 6 characters">
    <button onclick="finishOnboarding()" style="margin-top:14px">Enter MacroTracker</button>
  </div>
</div>

<div class="modal" id="foodEditModal">
  <div class="modalBox">
    <h2>Edit Food Data</h2>
    <p class="small">Correct the numbers before adding it to your day.</p>
    <label>Food name</label><input id="editName">
    <div class="grid">
      <div><label>Meal spot</label><select id="editMeal"><option value="auto">Auto by time</option><option value="breakfast">Breakfast</option><option value="lunch">Lunch</option><option value="dinner">Dinner</option><option value="snack">Snack</option></select></div>
      <div><label>Time eaten</label><input id="editTime" type="time"></div>
      <div><label>Base serving grams</label><input id="editBaseGrams" type="number" min="1" value="100"></div>
      <div><label>Grams eaten</label><input id="editGrams" type="number" min="1" value="100"></div>
      <div><label>Calories per base serving</label><input id="editCal" type="number" min="0"></div>
      <div><label>Protein per base serving</label><input id="editP" type="number" min="0"></div>
      <div><label>Carbs per base serving</label><input id="editC" type="number" min="0"></div>
      <div><label>Fat per base serving</label><input id="editF" type="number" min="0"></div>
    </div>
    <label>Source or note</label><input id="editNote" placeholder="Nutrition label, recipe, restaurant site...">
    <div class="grid" style="margin-top:14px">
      <button onclick="saveEditedFood()">Save food</button>
      <button class="secondary" onclick="closeFoodEditor()">Cancel</button>
    </div>
  </div>
</div>

<script>
if("serviceWorker" in navigator){navigator.serviceWorker.register("/sw.js").catch(()=>{})}
const foodImages=[
"https://images.unsplash.com/photo-1604908176997-125f25cc6f3d?auto=format&fit=crop&w=700&q=80",
"https://images.unsplash.com/photo-1467003909585-2f8a72700288?auto=format&fit=crop&w=700&q=80",
"https://images.unsplash.com/photo-1504674900247-0877df9cc836?auto=format&fit=crop&w=700&q=80",
"https://images.unsplash.com/photo-1525351484163-7529414344d8?auto=format&fit=crop&w=700&q=80",
"https://images.unsplash.com/photo-1488477181946-6428a0291777?auto=format&fit=crop&w=700&q=80",
"https://images.unsplash.com/photo-1512621776951-a57141f2eefd?auto=format&fit=crop&w=700&q=80"
];
const foods=[
{name:"Chicken breast cooked 100g",cal:165,p:31,c:0,f:4,img:0},{name:"Salmon cooked 100g",cal:208,p:20,c:0,f:13,img:1},
{name:"Eggs and toast",cal:260,p:18,c:24,f:11,img:3},{name:"Greek yogurt with berries",cal:150,p:18,c:18,f:1,img:4},
{name:"Brown rice cooked 1 cup",cal:216,p:5,c:45,f:2,img:2},{name:"Chicken burrito bowl",cal:650,p:45,c:70,f:20,img:5},
{name:"Turkey sandwich",cal:430,p:30,c:45,f:13,img:2},{name:"Avocado toast",cal:310,p:9,c:32,f:17,img:3},
{name:"Protein shake",cal:120,p:24,c:3,f:2,img:4},{name:"Broccoli 1 cup",cal:55,p:4,c:11,f:1,img:5}
];
const barcodeFoods={"012000001640":{name:"Gatorade 20 oz",cal:140,p:0,c:36,f:0},"049000028911":{name:"Coca-Cola 12 oz",cal:140,p:0,c:39,f:0},"028400064316":{name:"Lay's Classic Chips 1 oz",cal:160,p:2,c:15,f:10},"016000275633":{name:"Nature Valley Oats Bar pack",cal:190,p:4,c:29,f:7}};
let user=JSON.parse(localStorage.getItem("mtUser")||"{}");
let profile=JSON.parse(localStorage.getItem("mtProfile")||"{}");
let targets=JSON.parse(localStorage.getItem("mtTargets")||"{}");
let log=JSON.parse(localStorage.getItem("mtLog")||"[]");
let premium=localStorage.getItem("mtPremium")==="true";
let hydration=Number(localStorage.getItem("mtHydrationOz")||0);
let hydrationGoal=Number(localStorage.getItem("mtHydrationGoalOz")||64);
let progressHistory=JSON.parse(localStorage.getItem("mtProgressHistory")||"[]");
let foodStream=null,barcodeTimer=null,pendingFood=null,pendingEditIndex=null;
function todayISO(){return new Date().toISOString().slice(0,10)}
function showTab(id){document.querySelectorAll("section").forEach(s=>s.classList.remove("active"));document.getElementById(id).classList.add("active");document.querySelectorAll(".tabs button").forEach(b=>b.classList.toggle("active",b.dataset.tab===id));if(id==="foods")renderFoods();if(id==="dashboard")renderLog();if(id==="profile")renderProfile();if(id==="hydration")renderHydration();if(id==="progress")renderProgress();if(id==="account")renderAccount()}
function finishOnboarding(){let email=onEmail.value.trim().toLowerCase(),name=onName.value.trim(),dob=onDob.value,password=onPassword.value;if(!email||!name||!dob||!password){alert("Please fill out email, name, date of birth, and password.");return}if(password.length<6){alert("Password must be at least 6 characters.");return}user={email,name,dob};localStorage.setItem("mtUser",JSON.stringify(user));profileEmail.value=email;profileName.value=name;profileDob.value=dob;document.getElementById("onboardingModal").classList.remove("open");createOrUpdateAccount(email,password,true);showTab("dashboard")}
async function syncUser(){if(!user.email)return;await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(user)}).catch(()=>{});const r=await fetch("/api/user?email="+encodeURIComponent(user.email)).catch(()=>null);if(r){const d=await r.json();premium=!!d.premium;localStorage.setItem("mtPremium",premium?"true":"false");renderLog()}}
function renderAccount(){loginEmail.value=user.email||"";accountStatus.textContent=user.email?`Signed in locally as ${user.email}. Premium: ${premium?"active":"free"}.`:"Not signed in on this device."}
async function loginAccount(){let email=loginEmail.value.trim().toLowerCase(),password=loginPassword.value;if(!email||!password){accountStatus.textContent="Enter your email and password.";return}let r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});let d=await r.json();if(!r.ok||!d.ok){accountStatus.textContent=d.error||"Login failed.";return}user={email:d.user.email,name:d.user.name||"",dob:d.user.dob||""};localStorage.setItem("mtUser",JSON.stringify(user));premium=!!d.user.premium;localStorage.setItem("mtPremium",premium?"true":"false");accountStatus.textContent="Logged in. Account loaded.";renderProfile();renderLog()}
async function createOrUpdateAccount(emailArg=null,passwordArg=null,quiet=false){let email=(emailArg||loginEmail.value).trim().toLowerCase(),password=passwordArg||loginPassword.value;if(!email||!password){accountStatus.textContent="Enter email and password.";return}let r=await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password,name:user.name||profileName?.value||"",dob:user.dob||profileDob?.value||""})});let d=await r.json();if(!r.ok||d.error){if(!quiet)accountStatus.textContent=d.error||"Could not save account.";return}user={email:d.email,name:d.name||user.name||"",dob:d.dob||user.dob||""};localStorage.setItem("mtUser",JSON.stringify(user));premium=!!d.premium;localStorage.setItem("mtPremium",premium?"true":"false");if(!quiet)accountStatus.textContent="Account saved. You can log in with this password later.";renderAccount()}
async function findAccount(){let email=loginEmail.value.trim().toLowerCase();if(!email){accountStatus.textContent="Enter an email first.";return}let r=await fetch("/api/user?email="+encodeURIComponent(email));let d=await r.json();accountStatus.textContent=d.exists?`Account found for ${email}. Premium: ${d.premium?"active":"free"}.`:`No saved account found for ${email}.`}
function logoutAccount(){localStorage.removeItem("mtUser");localStorage.removeItem("mtPremium");user={};premium=false;renderAccount();renderLog()}
function renderProfile(){profileEmail.value=user.email||"";profileName.value=user.name||"";profileDob.value=user.dob||"";if(profile.age){sex.value=profile.sex;age.value=profile.age;height.value=profile.height;heightUnit.value=profile.heightUnit;weight.value=profile.weight;weightUnit.value=profile.weightUnit;activity.value=profile.activity;goal.value=profile.goal}customCalories.value=targets.calories||2000;proteinPct.value=targets.proteinPct||30;carbsPct.value=targets.carbsPct||40;fatPct.value=targets.fatPct||30;renderTargets()}
function calcBasePlan(){let kg=profile.weightUnit==="lb"?profile.weight*.453592:profile.weight,cm=profile.heightUnit==="in"?profile.height*2.54:profile.height;let bmr=profile.sex==="male"?10*kg+6.25*cm-5*profile.age+5:10*kg+6.25*cm-5*profile.age-161;let maintenance=Math.round(bmr*profile.activity);let calories=maintenance;if(profile.goal==="lose")calories-=500;if(profile.goal==="gain")calories+=300;calories=Math.max(1200,Math.round(calories));let protein=Math.round(kg*(profile.goal==="gain"?2:1.7)),fat=Math.round(calories*.25/9),carbs=Math.round((calories-protein*4-fat*9)/4);profile.maintenance=maintenance;profile.bmr=Math.round(bmr);return {calories,protein,carbs,fat,proteinPct:Math.round(protein*4/calories*100),carbsPct:Math.round(carbs*4/calories*100),fatPct:Math.round(fat*9/calories*100)}}
function saveProfile(){user.name=profileName.value.trim();user.dob=profileDob.value;localStorage.setItem("mtUser",JSON.stringify(user));profile={sex:sex.value,age:+age.value,height:+height.value,heightUnit:heightUnit.value,weight:+weight.value,weightUnit:weightUnit.value,activity:+activity.value,goal:goal.value};targets=calcBasePlan();localStorage.setItem("mtProfile",JSON.stringify(profile));localStorage.setItem("mtTargets",JSON.stringify(targets));syncUser();renderProfile();showTab("dashboard")}
function planWarnings(calories,proteinPercent,carbsPercent,fatPercent){let warnings=[];let floor=profile.sex==="male"?1500:1200;if(calories<floor)warnings.push(`Calories are very low. Many ${profile.sex==="male"?"men":"women"} should avoid going below about ${floor} calories without a clinician.`);if(profile.maintenance&&calories<profile.maintenance-750)warnings.push("This is an aggressive calorie deficit. Slower weight loss is usually easier to sustain.");if(profile.maintenance&&calories>profile.maintenance+700)warnings.push("This is a large surplus and may lead to faster fat gain.");if(proteinPercent>45)warnings.push("Protein is very high. Make sure this fits your health needs and hydration.");if(carbsPercent<10)warnings.push("Carbs are very low, which can affect energy and training performance.");if(fatPercent<15)warnings.push("Fat is very low. Dietary fat matters for hormones and vitamin absorption.");if(fatPercent>45)warnings.push("Fat is very high, so keep an eye on total calories and food quality.");if(!warnings.length)warnings.push("This plan looks within a typical range for many adults. Adjust based on hunger, energy, training, and professional advice.");return warnings.join(" ")}
function applyPremiumPlan(){if(!premium){planAdvisory.textContent="Premium is required to customize macro percentages and calories.";showTab("shop");return}let calories=Math.round(+customCalories.value||0),pp=+proteinPct.value||0,cp=+carbsPct.value||0,fp=+fatPct.value||0,total=pp+cp+fp;if(total!==100){planAdvisory.textContent=`Protein, carbs, and fat must add up to 100%. Current total is ${total}%.`;return}targets={calories,protein:Math.round(calories*pp/100/4),carbs:Math.round(calories*cp/100/4),fat:Math.round(calories*fp/100/9),proteinPct:pp,carbsPct:cp,fatPct:fp,custom:true};localStorage.setItem("mtTargets",JSON.stringify(targets));planAdvisory.textContent=planWarnings(calories,pp,cp,fp);renderTargets();renderLog()}
function renderTargets(){targetCards.innerHTML=`<div class="grid"><div class="stat">Calories<strong>${targets.calories||0}</strong></div><div class="stat">Protein<strong>${targets.protein||0}g</strong></div><div class="stat">Carbs<strong>${targets.carbs||0}g</strong></div><div class="stat">Fat<strong>${targets.fat||0}g</strong></div></div>`;customCalories.value=targets.calories||2000;proteinPct.value=targets.proteinPct||30;carbsPct.value=targets.carbsPct||40;fatPct.value=targets.fatPct||30;planAdvisory.textContent=targets.calories?planWarnings(targets.calories,targets.proteinPct||30,targets.carbsPct||40,targets.fatPct||30):"";let meals=profile.goal==="gain"?["Eggs, oatmeal, banana, milk","Chicken burrito bowl","Protein shake and almonds","Lean beef, rice, avocado, vegetables"]:profile.goal==="maintain"?["Eggs, toast, fruit","Turkey sandwich with Greek yogurt","Cottage cheese and berries","Chicken or tofu, potato, vegetables"]:["Greek yogurt, blueberries, oatmeal","Chicken breast, brown rice, broccoli","Apple with peanut butter","Salmon, sweet potato, spinach"];mealPlan.innerHTML=meals.map(m=>`<div class="meal">${m}</div>`).join("")}
function renderFoods(){let q=(search.value||"").toLowerCase();foodCards.innerHTML=foods.filter(f=>f.name.toLowerCase().includes(q)).map((f,i)=>`<div class="foodCard"><img src="${foodImages[f.img]}" alt="${f.name}"><div><b>${f.name}</b><p class="small">${f.cal} cal</p><span class="badge">P ${f.p}g</span><span class="badge">C ${f.c}g</span><span class="badge">F ${f.f}g</span><button style="margin-top:10px" onclick="addFood(${i})">Add</button></div></div>`).join("")}
function currentTime(){let d=new Date();return String(d.getHours()).padStart(2,"0")+":"+String(d.getMinutes()).padStart(2,"0")}
function mealFromTime(time){let h=Number((time||currentTime()).split(":")[0]);if(h>=5&&h<11)return"breakfast";if(h>=11&&h<16)return"lunch";if(h>=16&&h<21)return"dinner";return"snack"}
function mealLabel(key){return {breakfast:"Breakfast",lunch:"Lunch",dinner:"Dinner",snack:"Snack"}[key]||"Snack"}
function cleanFood(f){let baseGrams=Math.max(1,+f.baseGrams||100),grams=Math.max(1,+f.grams||baseGrams),ratio=grams/baseGrams,baseCal=+(f.baseCal??f.cal)||0,baseP=+(f.baseP??f.p)||0,baseC=+(f.baseC??f.c)||0,baseF=+(f.baseF??f.f)||0,time=f.time||currentTime(),mealChoice=f.mealChoice||f.meal||"auto",meal=mealChoice==="auto"?mealFromTime(time):mealChoice;return {name:String(f.name||"Custom food"),baseCal,baseP,baseC,baseF,baseGrams,grams,time,mealChoice,meal,cal:Math.max(0,Math.round(baseCal*ratio)),p:Math.max(0,Math.round(baseP*ratio)),c:Math.max(0,Math.round(baseC*ratio)),f:Math.max(0,Math.round(baseF*ratio)),note:f.note||f.source||""}}
function addFood(i){showFoodEditor({...foods[i]})}
function addFoodObject(f){log.push(cleanFood(f));saveLog();renderLog();showTab("dashboard")}
function saveLog(){localStorage.setItem("mtLog",JSON.stringify(log))}
function sum(k){return log.reduce((t,f)=>t+(+f[k]||0),0)}
function showFoodEditor(f,index=null){pendingFood=cleanFood(f);pendingEditIndex=index;editName.value=pendingFood.name;editMeal.value=pendingFood.mealChoice||pendingFood.meal;editTime.value=pendingFood.time||currentTime();editBaseGrams.value=pendingFood.baseGrams;editGrams.value=pendingFood.grams;editCal.value=pendingFood.baseCal;editP.value=pendingFood.baseP;editC.value=pendingFood.baseC;editF.value=pendingFood.baseF;editNote.value=pendingFood.note||"";foodEditModal.classList.add("open")}
function closeFoodEditor(){foodEditModal.classList.remove("open");pendingFood=null;pendingEditIndex=null}
function saveEditedFood(){let f=cleanFood({name:editName.value,mealChoice:editMeal.value,time:editTime.value,baseGrams:editBaseGrams.value,grams:editGrams.value,baseCal:editCal.value,baseP:editP.value,baseC:editC.value,baseF:editF.value,note:editNote.value});if(pendingEditIndex===null){log.push(f)}else{log[pendingEditIndex]=f}saveLog();closeFoodEditor();renderLog();showTab("dashboard")}
function addCustomFood(){showFoodEditor({name:customName.value||"Custom food",cal:customCal.value,p:customP.value,c:customC.value,f:customF.value,note:customSource.value||"Custom data"})}
function bars(){let eaten=sum("cal"),p=sum("p"),c=sum("c"),f=sum("f");return [["Calories",eaten,targets.calories||2000,"calories"],["Protein",p,targets.protein||150,"protein"],["Carbs",c,targets.carbs||250,"carbs"],["Fat",f,targets.fat||80,"fat"]].map(x=>`<div><div class="macroTop"><b>${x[0]}</b><span>${x[1]}/${x[2]}</span></div><div class="track"><div class="bar ${x[3]}" style="width:${Math.min(100,x[1]/x[2]*100)}%"></div></div></div>`).join("")}
function renderLog(){eatenCalories.textContent=sum("cal");remainingCalories.textContent=(targets.calories||0)-sum("cal");logProtein.textContent=sum("p")+"g";premiumLabel.textContent=premium?"Active":"Free";logBars.innerHTML=bars();let groups=[["breakfast","Breakfast"],["lunch","Lunch"],["dinner","Dinner"],["snack","Snacks"]];logList.innerHTML=groups.map(([key,label])=>{let items=log.map((f,i)=>({...cleanFood(f),i})).filter(f=>(f.meal||"snack")===key).sort((a,b)=>(a.time||"").localeCompare(b.time||"")),total=items.reduce((t,f)=>t+f.cal,0);return `<div class="mealGroup"><div class="mealHead"><span>${label}</span><span>${total} cal</span></div><div class="mealBody">${items.length?items.map(f=>`<div class="foodRow"><b>${f.name}</b><div class="small">${f.time} | ${f.grams}g eaten | ${f.cal} cal | P ${f.p}g | C ${f.c}g | F ${f.f}g${f.mealChoice==="auto"?" | auto placed in "+mealLabel(f.meal):""}${f.note?" | "+f.note:""}</div><div class="grid"><button class="secondary" onclick="showFoodEditor(log[${f.i}],${f.i})">Change meal/time</button><button class="secondary" onclick="log.splice(${f.i},1);saveLog();renderLog()">Remove</button></div></div>`).join(""):`<div class="emptyMeal">No ${label.toLowerCase()} logged yet.</div>`}</div></div>`}).join("");aiLockCard.classList.toggle("locked",!premium)}
async function buyPremium(plan){if(!user.email){document.getElementById("onboardingModal").classList.add("open");return}let r=await fetch("/api/create-checkout",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:user.email,plan})});let d=await r.json();if(d.url)location.href=d.url;else alert(d.error||"Stripe is not configured yet. Add your Stripe keys and Price IDs.")}
function requirePremium(){if(!premium){alert("AI Scan is a Premium feature.");showTab("shop");return false}return true}
async function startFoodCamera(){if(!requirePremium())return;try{foodStream=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});foodVideo.srcObject=foodStream;foodCamBox.style.display="block"}catch(e){aiResult.textContent="Camera blocked. Use upload instead."}}
function snapFood(){if(!requirePremium())return;if(!foodVideo.srcObject){aiResult.textContent="Open the camera first.";return}foodCanvas.width=foodVideo.videoWidth;foodCanvas.height=foodVideo.videoHeight;foodCanvas.getContext("2d").drawImage(foodVideo,0,0);scanImageData(foodCanvas.toDataURL("image/jpeg",.75),"meal")}
function scanUploadedFood(e){scanUploadedTyped(e,"meal")}
function scanUploadedTyped(e,type){if(!requirePremium())return;let file=e.target.files[0];if(!file)return;let reader=new FileReader();reader.onload=()=>scanImageData(reader.result,type);reader.readAsDataURL(file)}
async function scanImageData(image,type="meal"){aiResult.textContent=type==="label"?"Reading nutrition label...":type==="recipe"?"Estimating recipe photo...":"Scanning meal with AI...";let r=await fetch("/api/ai-food",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:user.email,image,scanType:type})});let f=await r.json();if(f.error){aiResult.textContent=f.error;return}pendingFood=cleanFood(f);aiResult.innerHTML=`<b>${pendingFood.name}</b><br>${pendingFood.cal} calories<br><span class="badge">P ${pendingFood.p}g</span><span class="badge">C ${pendingFood.c}g</span><span class="badge">F ${pendingFood.f}g</span><div class="grid" style="margin-top:10px"><button onclick='addFoodObject(pendingFood)'>Add to today</button><button class="secondary" onclick='showFoodEditor(pendingFood)'>Correct data</button></div><p class="small">${pendingFood.note||""}</p>`}
async function startBarcodeScanner(){if(!("BarcodeDetector" in window)){barcodeResult.textContent="Live barcode scan is not supported in this browser. Type it manually.";return}let stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});barcodeVideo.srcObject=stream;barcodeBox.style.display="block";let detector=new BarcodeDetector({formats:["ean_13","ean_8","upc_a","upc_e","code_128"]});clearInterval(barcodeTimer);barcodeTimer=setInterval(async()=>{let codes=await detector.detect(barcodeVideo).catch(()=>[]);if(codes.length){barcodeInput.value=codes[0].rawValue;lookupBarcode();clearInterval(barcodeTimer)}},700)}
function lookupBarcode(){let f=barcodeFoods[barcodeInput.value.trim()];if(!f){barcodeResult.textContent="Barcode not found in starter database.";return}addFoodObject(f);barcodeResult.textContent="Logged "+f.name}
async function submitComplaint(){let subject=complaintSubject.value.trim(),body=complaintBody.value.trim();if(!subject||!body){alert("Please add a subject and details.");return}let r=await fetch("/api/complaint",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:user.email,subject,priority:complaintPriority.value,body})});complaintStatus.textContent=r.ok?"Report submitted. Thank you.":"Could not submit report.";complaintSubject.value="";complaintBody.value=""}
function renderHydration(){waterOunces.textContent=hydration+" oz";waterGoalLabel.textContent=hydrationGoal+" oz";waterGoalInput.value=hydrationGoal;let pct=hydrationGoal?Math.min(100,Math.round(hydration/hydrationGoal*100)):0;waterProgress.textContent=pct+"%";waterBar.style.width=pct+"%"}
function changeWater(oz){hydration=Math.max(0,Math.round(hydration+(+oz||0)));localStorage.setItem("mtHydrationOz",hydration);renderHydration()}
function setWaterGoal(){hydrationGoal=Math.max(1,Math.round(+waterGoalInput.value||64));localStorage.setItem("mtHydrationGoalOz",hydrationGoal);renderHydration()}
function resetWater(){if(confirm("Reset hydration today?")){hydration=0;localStorage.setItem("mtHydrationOz",hydration);renderHydration()}}
function saveProgressEntry(){let entry={date:progressDate.value||todayISO(),weight:+progressWeight.value||0,calories:+progressCalories.value||sum("cal"),unit:progressUnit.value};if(!entry.weight){alert("Enter your weight first.");return}progressHistory=progressHistory.filter(x=>x.date!==entry.date);progressHistory.push(entry);progressHistory.sort((a,b)=>a.date.localeCompare(b.date));progressHistory=progressHistory.slice(-30);localStorage.setItem("mtProgressHistory",JSON.stringify(progressHistory));renderProgress()}
function chartHtml(items,key,kind){if(!items.length)return "<p class='small'>No entries yet.</p>";let vals=items.map(x=>+x[key]||0),max=Math.max(...vals,1),min=kind==="weight"?Math.min(...vals):0,range=Math.max(1,max-min);return items.map(x=>{let val=+x[key]||0,h=kind==="weight"?20+(val-min)/range*180:val/max*200;return `<div class="barWrap"><div class="chartBar ${kind==="weight"?"weight":""}" style="height:${h}px"></div><div class="chartLabel">${val}<br>${x.date.slice(5)}</div></div>`}).join("")}
function renderProgress(){if(!progressDate.value)progressDate.value=todayISO();if(!progressCalories.value)progressCalories.value=sum("cal");let items=[...progressHistory].sort((a,b)=>a.date.localeCompare(b.date)).slice(-14);calorieChart.innerHTML=chartHtml(items,"calories","calories");weightChart.innerHTML=chartHtml(items,"weight","weight");progressList.innerHTML=items.length?items.map(x=>`<div class="foodRow"><b>${x.date}</b><div class="small">${x.weight} ${x.unit||"lb"} | ${x.calories} calories</div><button class="secondary" onclick="progressHistory=progressHistory.filter(e=>e.date!=='${x.date}');localStorage.setItem('mtProgressHistory',JSON.stringify(progressHistory));renderProgress()">Remove</button></div>`).join(""):"<p class='small'>Save your first progress entry to start the charts.</p>"}
function toggleDark(){document.body.classList.toggle("dark");localStorage.setItem("mtTheme",document.body.classList.contains("dark")?"dark":"light")}function resetToday(){if(confirm("Reset today's log and hydration?")){log=[];hydration=0;saveLog();localStorage.setItem("mtHydrationOz",hydration);renderLog();renderHydration()}}
if(localStorage.getItem("mtTheme")==="dark")document.body.classList.add("dark");
const params=new URLSearchParams(location.search);if(params.get("checkout")==="success"){setTimeout(()=>alert("Payment submitted. Premium activates after Stripe confirms the subscription."),400)}
if(!user.email){document.getElementById("onboardingModal").classList.add("open")}else{syncUser()}
showTab("dashboard");renderFoods();renderProfile();renderLog();renderHydration();renderProgress();
</script>
</body>
</html>
'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/manifest.json":
            return json_response(self, 200, MANIFEST)
        if parsed.path == "/sw.js":
            return text_response(self, 200, SERVICE_WORKER, "application/javascript")
        if parsed.path == "/api/user":
            email = parse_qs(parsed.query).get("email", [""])[0]
            found = get_user(email)
            visible = public_user(found)
            visible["exists"] = bool(found.get("createdAt"))
            return json_response(self, 200, visible)
        return text_response(self, 200, APP, "text/html")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)

        if self.path == "/api/register":
            data = json.loads(raw_body.decode("utf-8"))
            email = data.get("email", "")
            if not email:
                return json_response(self, 400, {"error": "Missing email"})
            try:
                if data.get("password"):
                    user = set_user_password(email, data.get("password", ""))
                    user = upsert_user(email, name=data.get("name", user.get("name", "")), dob=data.get("dob", user.get("dob", "")))
                else:
                    user = upsert_user(email, name=data.get("name", ""), dob=data.get("dob", ""))
                return json_response(self, 200, public_user(user))
            except ValueError as exc:
                return json_response(self, 400, {"error": str(exc)})

        if self.path == "/api/login":
            data = json.loads(raw_body.decode("utf-8"))
            email = data.get("email", "")
            password = data.get("password", "")
            if not verify_user_password(email, password):
                return json_response(self, 401, {"ok": False, "error": "Email or password is incorrect."})
            return json_response(self, 200, {"ok": True, "user": public_user(get_user(email))})

        if self.path == "/api/create-checkout":
            data = json.loads(raw_body.decode("utf-8"))
            email = (data.get("email") or "").strip().lower()
            plan = data.get("plan", "monthly")
            if not email:
                return json_response(self, 400, {"error": "Email is required"})
            upsert_user(email)
            try:
                checkout = create_stripe_checkout(email, plan)
                return json_response(self, 200, {"url": checkout["url"]})
            except Exception as exc:
                return json_response(self, 200, {"error": str(exc)})

        if self.path == "/api/ai-food":
            data = json.loads(raw_body.decode("utf-8"))
            user = get_user(data.get("email", ""))
            if not user.get("premium"):
                return json_response(self, 403, {"error": "Premium required"})
            return json_response(self, 200, ai_food_estimate(data.get("image", ""), data.get("scanType", "meal")))

        if self.path == "/api/complaint":
            data = json.loads(raw_body.decode("utf-8"))
            complaints = read_json(COMPLAINTS_FILE)
            complaints.append({
                "email": data.get("email", ""),
                "subject": data.get("subject", ""),
                "priority": data.get("priority", "Bug"),
                "body": data.get("body", ""),
                "createdAt": int(time.time())
            })
            write_json(COMPLAINTS_FILE, complaints)
            return json_response(self, 200, {"ok": True})

        if self.path == "/api/stripe-webhook":
            signature = self.headers.get("Stripe-Signature", "")
            if not verify_stripe_signature(raw_body, signature):
                return json_response(self, 400, {"error": "Invalid signature"})
            event = json.loads(raw_body.decode("utf-8"))
            if event.get("type") == "checkout.session.completed":
                session = event.get("data", {}).get("object", {})
                email = (
                    session.get("client_reference_id")
                    or session.get("customer_details", {}).get("email")
                    or session.get("customer_email")
                )
                upsert_user(email, premium=True, stripeCustomerId=session.get("customer"))
            if event.get("type") in ("customer.subscription.deleted", "customer.subscription.paused"):
                customer = event.get("data", {}).get("object", {}).get("customer")
                users = read_json(USERS_FILE)
                for user in users:
                    if user.get("stripeCustomerId") == customer:
                        user["premium"] = False
                write_json(USERS_FILE, users)
            return json_response(self, 200, {"received": True})

        return json_response(self, 404, {"error": "Not found"})

    def log_message(self, format, *args):
        return


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    ensure_data_files()
    ip = get_ip()
    print(f"{APP_NAME} is running.")
    print(f"Local: http://127.0.0.1:{PORT}")
    print(f"Phone on same WiFi: http://{ip}:{PORT}")
    print("Set STRIPE_SECRET_KEY, STRIPE_MONTHLY_PRICE_ID, STRIPE_YEARLY_PRICE_ID, STRIPE_WEBHOOK_SECRET, OPENAI_API_KEY, and BASE_URL for production.")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
