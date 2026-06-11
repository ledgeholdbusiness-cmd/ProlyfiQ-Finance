from flask import Flask, request, jsonify
import os
import datetime
import firebase_admin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from firebase_admin import credentials, firestore, initialize_app
from dotenv import load_dotenv
from google.cloud.firestore_v1.base_query import FieldFilter

load_dotenv(override=True)

app = Flask(__name__)

# ── CORS — Allow requests from Sedy's operational server ──
CORS(app, origins=[os.environ.get("OPERATIONAL_ORIGIN", "*")])

# ── RATE LIMITER ──
redis_storage_url = os.getenv("REDIS_URL")
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=redis_storage_url or "memory://",
    default_limits=["200 per day"]
)

# ── ENVIRONMENT CONFIGURATION ──
APP_ID = os.getenv('__app_id', 'ledgehold-ghana1')
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
ADMIN_IDS = [id.strip() for id in os.environ.get("ADMIN_IDS", "").split(",") if id.strip()]
ADMIN_PINS = [pin.strip() for pin in os.environ.get("ADMIN_PINS", "").split(",") if pin.strip()]

# Hubtel SMS Auth
from base64 import b64encode
HUB_ID = os.getenv('HUBTEL_CLIENT_ID')
HUB_SECRET = os.getenv('HUBTEL_CLIENT_SECRET')
HUB_AUTH = b64encode(f"{HUB_ID}:{HUB_SECRET}".encode()).decode()


# ── FIREBASE INITIALIZATION ──
if not firebase_admin._apps:
    prod_cred_path = "/etc/secrets/service-account.json"
    local_cred_path = "service-account.json"

    if os.path.exists(prod_cred_path):
        cred = credentials.Certificate(prod_cred_path)
        print("Security Protocol: Production Node Active")
    elif os.path.exists(local_cred_path):
        cred = credentials.Certificate(local_cred_path)
        print("Security Protocol: Local Node Active")
    else:
        cred = None
        print("Warning: No service-account.json found.")

    if cred:
        initialize_app(cred)
    else:
        initialize_app()

db = firestore.client()


# ── IMPORT & INITIALIZE FINANCIAL MODULE ──
from financial import financial_bp, init_financial

init_financial(db, APP_ID, PAYSTACK_SECRET_KEY, ADMIN_IDS, ADMIN_PINS, HUB_AUTH, limiter)
app.register_blueprint(financial_bp)

# ── APPLY RATE LIMITS (after initialization) ──
from financial import initialize_secure_checkout, get_my_order_token, admin_auth, admin_reverse_escrow
limiter.limit("10 per minute")(initialize_secure_checkout)
limiter.limit("20 per minute")(get_my_order_token)
limiter.limit("5 per minute")(admin_auth)
limiter.limit("5 per minute")(admin_reverse_escrow)


# ── HEALTH CHECK ──
@app.route('/healthz')
def health_check():
    return "OK", 200


# ── CRON: CLEANUP STAGED SESSIONS ──
@app.route('/admin/cleanup-staged-sessions', methods=['POST'])
def cleanup_staged_sessions():
    if request.headers.get('X-Cron-Secret') != os.getenv('CRON_SECRET'):
        return "Unauthorized", 401

    now = datetime.datetime.now(datetime.timezone.utc)
    col = (db.collection('artifacts').document(APP_ID)
             .collection('private').document('staged_sessions')
             .collection('tokens'))

    expired = col.where(filter=FieldFilter('expires_at', '<', now)).stream()
    deleted = 0
    for doc in expired:
        doc.reference.delete()
        deleted += 1

    print(f"🧹 Cleanup: deleted {deleted} expired staged sessions.")
    return jsonify({"deleted": deleted}), 200


# ── EXPIRY SWEEP ──
def run_expiry_sweep():
    print(f"🧹 Starting 120-Hour Expiry Sweep at {datetime.datetime.now()}...")
    
    orders_ref = db.collection('artifacts').document(APP_ID)\
                   .collection('public').document('data')\
                   .collection('orders')
    
    query = orders_ref.where(filter=FieldFilter('status', '==', 'paid_in_escrow')).get()
    
    expired_count = 0
    now = datetime.datetime.now(datetime.timezone.utc)
    
    for doc in query:
        data = doc.to_dict()
        created_at = data.get('createdAt')
        
        if created_at:
            order_time = created_at.replace(tzinfo=datetime.timezone.utc)
            time_diff = now - order_time
            
            if time_diff.total_seconds() > (168 * 3600):
                print(f"⚠️ Flagging Order {doc.id} for Administrative Review (Expired 120h).")
                doc.reference.update({"status": "requires_review"})
                expired_count += 1
                
    print(f"✅ Sweep Complete. Flagged {expired_count} dead transactions.")


# ═══════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    try:
        run_expiry_sweep()
    except Exception as e:
        print(f"⚠️ Expiry sweep skipped (network unavailable): {e}")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))