"""
Ledgehold Financial Operations Module
Handles all escrow, payment, verification, webhook, and payout logic.
"""

from flask import Blueprint, request, jsonify
import hmac
import hashlib
import uuid
import traceback
import bcrypt
import datetime
import requests
import os
import resend
from decimal import Decimal
from google.cloud.firestore_v1.base_query import FieldFilter
from firebase_admin import firestore
from base64 import b64encode
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

financial_bp = Blueprint('financial', __name__)

# These will be set by app.py during initialization
db = None
APP_ID = None
PAYSTACK_SECRET_KEY = None
ADMIN_ID = None
ADMIN_PIN = None
HUB_AUTH = None
limiter = None

def init_financial(database, app_id, paystack_key, admin_ids, admin_pins, hub_auth, limiter_instance):
    global db, APP_ID, PAYSTACK_SECRET_KEY, ADMIN_IDS, ADMIN_PINS, HUB_AUTH, limiter
    db = database
    APP_ID = app_id
    PAYSTACK_SECRET_KEY = paystack_key
    ADMIN_IDS = admin_ids
    ADMIN_PINS = admin_pins
    HUB_AUTH = hub_auth
    limiter = limiter_instance


# ═══════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════

def format_gh_phone(raw):
    """Formats a Ghanaian phone number to international 233 format."""
    s = str(raw).strip() if raw else ""
    if not s or s in ["Unknown", "None"]:
        return "Unknown"
    if s.startswith('0'):
        return '233' + s[1:]
    elif not s.startswith('233'):
        return '233' + s
    return s


def send_professional_sms(to_number, message_content):
    """Dispatches SMS via Hubtel API."""
    url = "https://smsc.hubtel.com/v1/messages/send"
    headers = {
        "Authorization": f"Basic {HUB_AUTH}",
        "Content-Type": "application/json"
    }
    payload = {
        "From": "Ledgehold",
        "To": to_number,
        "Content": message_content
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        return response.status_code in [200, 201]
    except Exception as e:
        print(f"❌ Hubtel Connection Exception: {str(e)}")
        return False


def send_handoff_email(order_data, paystack_ref):
    """Triggers an internal audit email via Resend once handoff is confirmed."""
    try:
        email_body = f"""
        <div style="font-family: sans-serif; color: #333; max-width: 600px;">
            <h2 style="color: #22c55e;">Vault Released: Handshake Successful</h2>
            <p>The Gatekeeper has verified the device signature and authorized the payout for the following transaction:</p>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Item</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{order_data.get('item', 'N/A')}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Amount</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">GHS {order_data.get('amount', 0)}</td>
                </tr>
                <tr style="background: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Reference</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>{paystack_ref}</code></td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Buyer Phone</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{order_data.get('buyerPhone', 'N/A')}</td>
                </tr>
            </table>
            
            <p style="font-size: 12px; color: #64748b;">This is an automated audit log for Ledgehold.</p>
        </div>
        """

        resend.Emails.send({
            "from": "Ledgehold System <mail.dataexpress.store>",
            "to": ["ledgehold.business@gmail.com"],
            "subject": f"✅ Handoff Complete: {order_data.get('item')}",
            "html": email_body
        })
        print(f"📧 Resend: Handoff alert dispatched for {paystack_ref}")
        
    except Exception as e:
        print(f"⚠️ Resend Integration Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# ATOMIC TRANSACTIONAL ORDER MUTATION WORKER
# ═══════════════════════════════════════════════════════════════

@firestore.transactional
def create_order_if_not_exists(transaction, order_id, session_token, payload):
    """
    Atomically ensures an order is written once, staging tokens are consumed,
    and no data overwrites occur under concurrent duplicate webhook delivery.
    Includes absolute defensive fallback coverage for missing temporal anchors.
    """
    orders_col = (
        db.collection('artifacts').document(APP_ID)
          .collection('public').document('data')
          .collection('orders')
    )
    order_ref = orders_col.document(order_id)
    
    staged_ref = (
        db.collection('artifacts').document(APP_ID)
          .collection('private').document('staged_sessions')
          .collection('tokens').document(session_token)
    )

    # Reads must execute sequentially at the top of the transaction scope
    order_snapshot = order_ref.get(transaction=transaction)
    staged_snapshot = staged_ref.get(transaction=transaction)

    # Safeguard 1: Structural Idempotency (Order already written)
    if order_snapshot.exists:
        return {"already_created": True}

    # Safeguard 2: Staging token already consumed or wiped
    if not staged_snapshot.exists:
        return {"staging_gone": True}

    staged_data = staged_snapshot.to_dict()
    
    # ── SAFEGUARD 3: DEFENSIVE TIMING & EXPIRY FRAMEWORK ──
    expires_at = staged_data.get('expires_at')
    
    if not expires_at:
        print(f"⚠️ SECURITY AUDIT: Staging token {session_token} is missing an explicit 'expires_at' anchor. Invoking fallback...")
        created_at = staged_data.get('created_at') or staged_data.get('createdAt')
        
        if created_at:
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=datetime.timezone.utc)
            expires_at = created_at + datetime.timedelta(minutes=15)
        else:
            print(f"🚨 DEFENSIVE SHUTDOWN: Token {session_token} has no temporal field maps. Deleting immediately.")
            transaction.delete(staged_ref)
            return {"expired": True}

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        
    if expires_at < datetime.datetime.now(datetime.timezone.utc):
        print(f"⌛ TIMING BLOCK: Staging token {session_token} lifespan exceeded limit. Evicting.")
        transaction.delete(staged_ref)
        return {"expired": True}

    # Atomic Write Execution Block
    device_token = str(uuid.uuid4())
    
    transaction.set(order_ref, {
        "status":            "paid_in_escrow",
        "listing_id":        staged_data['listing_id'],
        "merchant_id":       staged_data.get('merchant_id'),
        "item":              staged_data['item_name'],
        "amount":            staged_data['amount'],
        "total_collected":   staged_data.get('total_charge'),
        "protection_option": staged_data.get('protection_option'),
        "buyerPhone":        staged_data['buyer_phone'],
        "momo":              staged_data['momo'],
        "is_bundled_pack": staged_data.get('is_bundled_pack', False),
        "bundle_units_count": staged_data.get('bundle_units_count', 1),
        "paystack_ref":      order_id,
        "payout_status":     "AWAITING_HANDSHAKE",
        "failed_attempts":   0,
        "createdAt":         firestore.SERVER_TIMESTAMP,
        "securityStamp": {
            "token":      device_token,
            "ip":         payload.get('ip_address', 'unknown'),
            "handoffPin": staged_data['hashed_pin']
        }
    })

    # Atomic consumption of the staging profile key
    transaction.delete(staged_ref)
    
    return {
        "created": True, 
        "staged_data": staged_data, 
        "device_token": device_token
    }


# ═══════════════════════════════════════════════════════════════
# PAYSTACK WEBHOOK
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/paystack/webhook', methods=['POST'])
def paystack_webhook():
    # Cryptographic Validation Handshake
    paystack_signature = request.headers.get('x-paystack-signature')
    if not paystack_signature:
        print("🛡️ SECURITY ALERT: Missing Paystack signature header.")
        return "Unauthorized", 401

    computed_signature = hmac.new(
        bytes(PAYSTACK_SECRET_KEY, 'utf-8'),
        request.data,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed_signature, paystack_signature):
        print("🛡️ SECURITY ALERT: Invalid webhook signature verification.")
        return "Unauthorized", 401

    data = request.json or {}
    event_type = data.get('event')
    print(f"WEBHOOK RECEIVED: {event_type}")

    if event_type == "charge.success":
        payload = data.get('data', {})
        meta = payload.get('metadata', {}).get('custom_fields', [])
        order_id = payload.get('reference')

        try:
            session_token = next(
                (f['value'] for f in meta if f['variable_name'] == 'session_token'), None
            )

            if not session_token:
                print(f"❌ WEBHOOK ATTEMPT REFUSED: No session_token footprint for {order_id}.")
                return "Missing session token", 400

            # Engage the Transaction Isolation Boundary
            transaction = db.transaction()
            result = create_order_if_not_exists(transaction, order_id, session_token, payload)

            if result.get("already_created"):
                print(f"⚠️ IDEMPOTENCY BOUNDARY MET: Order {order_id} handled safely by transaction guard.")
                return "OK", 200

            if result.get("staging_gone") or result.get("expired"):
                print(f"⚠️ WEBHOOK REJECTED: Token staging instance {session_token} missing or spent.")
                return "Session not found", 400

            # Single-run execution confirmation zone
            staged = result["staged_data"]
            print(f"✅ ATOMIC BLOCK SECURED: Order {order_id} established. Transient token {session_token} deleted.")

            # Dual SMS Dispatch Protocol
            try:
                buyer_phone = staged['buyer_phone']
                seller_momo = staged['momo']
                item_name   = staged['item_name']
                listing_id  = staged['listing_id']

                # ── Add bundle context to item name for both parties ──
                bundle_count = staged.get('bundle_units_count', 1)
                is_bundled = staged.get('is_bundled_pack', False)
                display_name = f"{item_name} (Pack of {bundle_count})" if (is_bundled and bundle_count > 1) else item_name

                clean_buyer  = format_gh_phone(buyer_phone)
                clean_seller = format_gh_phone(seller_momo)

                # ── Fetch listing for pickup details ──
                pickup_day = ""
                pickup_time = ""
                pickup_location = ""
                try:
                    listing_doc = (
                        db.collection('artifacts').document(APP_ID)
                          .collection('public').document('data')
                          .collection('market_listings').document(listing_id)
                    ).get()
                    if listing_doc.exists:
                        listing_data = listing_doc.to_dict()
                        schedule = listing_data.get('schedule', '')
                        if schedule and '|' in schedule:
                            parts = schedule.split('|')
                            pickup_day = parts[0].strip() if len(parts) > 0 else ''
                            pickup_time = parts[1].strip() if len(parts) > 1 else ''
                        pickup_location = listing_data.get('landmark', '')
                except Exception:
                    pass  # If listing fetch fails, just send without pickup details

                # ── BUYER SMS 1: Payment confirmation (immediate) ──
                if clean_buyer != "Unknown":
                    seller_display = f"0{clean_seller[3:]}" if clean_seller.startswith('233') else clean_seller
                    buyer_msg = (
                        f"Payment for {display_name} secured! Ref: {order_id}. "
                        f"Call seller: {seller_display}"
                    )
                    send_professional_sms(clean_buyer, buyer_msg)

                    # ── BUYER SMS 2: Pickup details (delayed 15 seconds) ──
                    if pickup_location:
                        import time
                        time.sleep(15)
                        
                        pickup_info = (
                            f"Meetup for your {display_name} is at {pickup_location}"
                        )
                        if pickup_day:
                            pickup_info += f", {pickup_day}"
                        if pickup_time:
                            pickup_info += f" between {pickup_time}"
                        pickup_info += (
                            f". The day can be adjusted with the seller, "
                            f"but the time window and location are fixed for your safety. "
                            f"Ref: {order_id}"
                        )
                        
                        send_professional_sms(clean_buyer, pickup_info)

                # ── SELLER SMS ──
                if clean_seller not in ["Unknown", "None"]:
                    buyer_display = f"0{clean_buyer[3:]}" if clean_buyer.startswith('233') else clean_buyer
                    merchant_msg = (
                        f"Great news! Your {display_name} has been paid for. Order Ref: {order_id}. "
                        f"Call the buyer at {buyer_display} to arrange the handover. "
                        f"Let them scan your QR code when you meet to claim your money."
                    )
                    send_professional_sms(clean_seller, merchant_msg)

            except Exception as sms_err:
                print(f"⚠️ Notification alert delivery execution bypassed: {str(sms_err)}")

        except Exception as e:
            print(f"❌ WEBHOOK TRANSACTION COLLISION CRASH: {str(e)}")
            traceback.print_exc()
            return "Internal Server Error", 500

    # ── CASE B: OUTBOUND PAYOUT SETTLED SUCCESSFUL ──
    elif event_type == "transfer.success":
        payload            = data.get('data', {})
        transfer_reference = payload.get('reference')
        recipient_number   = payload.get('recipient', {}).get('details', {}).get('account_number')

        try:
            query = (
                db.collection('artifacts').document(APP_ID)
                  .collection('public').document('data').collection('orders')
                  .where(filter=FieldFilter('payout_reference', '==', transfer_reference))
                  .limit(1).get()
            )
            if query:
                query[0].reference.update({
                    "payout_status":       "SUCCESS",
                    "payout_settled_at":   payload.get('updated_at') or payload.get('transferred_at'),
                    "paystack_transfer_id": payload.get('id'),
                    "gateway_response":    "Funds successfully deposited into merchant wallet balance.",
                })
                print(f"💸 PAYOUT CONFIRMED: {transfer_reference} → {recipient_number}.")
            else:
                print(f"⚠️ Outbound Transfer reference track matching missed.")
                
        except Exception as e:
            print(f"❌ CRITICAL: Settlement success write failure: {str(e)}")
            traceback.print_exc()
            return "Database Ledger Update Error", 500

    # ── CASE C: OUTBOUND PAYOUT BOUNCED BACK (FAILED) ──
    elif event_type == "transfer.failed":
        payload            = data.get('data', {})
        transfer_reference = payload.get('reference')

        try:
            query = (
                db.collection('artifacts').document(APP_ID)
                  .collection('public').document('data').collection('orders')
                  .where(filter=FieldFilter('payout_reference', '==', transfer_reference))
                  .limit(1).get()
            )
            if query:
                query[0].reference.update({
                    "status":           "payout_failed",
                    "payout_status":    "FAILED",
                    "gateway_response": payload.get('failures') or "Wallet limits hit / Settlement timeout.",
                })
                print(f"🚨 PAYOUT CRASHED: {transfer_reference} bounced.")
                
        except Exception as e:
            print(f"❌ CRITICAL: Settlement failure write logging fault: {str(e)}")
            traceback.print_exc()
            return "Database Ledger Update Error", 500

    return "OK", 200


# ═══════════════════════════════════════════════════════════════
# CHECKOUT INITIALIZATION
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/checkout/init', methods=['POST'])
def initialize_secure_checkout():
    data = request.json or {}

    plaintext_pin     = data.get('plaintextPin')
    buyer_phone       = data.get('buyerPhone')
    listing_id        = data.get('listingId')
    client_gross_amt  = data.get('amount')
    protection_option = data.get('protectionOption')
    item_name         = data.get('itemName', 'Item')

    if not all([plaintext_pin, buyer_phone, listing_id, client_gross_amt, protection_option]):
        return jsonify({"success": False, "error": "Missing required checkout parameters."}), 400

    pin_str = str(plaintext_pin).strip()
    if not pin_str.isdigit() or len(pin_str) != 4:
        return jsonify({"success": False, "error": "PIN must be exactly 4 digits."}), 400

    phone_str = str(buyer_phone).strip().replace(' ', '')
    if not phone_str.startswith('0') or len(phone_str) != 10:
        return jsonify({"success": False, "error": "Invalid phone number format."}), 400

    try:
        # ── FETCH AUTHORITATIVE LISTING DIRECTLY FROM DB ──
        listing_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data')
              .collection('market_listings').document(listing_id)
        ).get()

        if not listing_ref.exists:
            return jsonify({"success": False, "error": "The listing no longer exists."}), 404

        listing_data = listing_ref.to_dict()
        
        # Use server-side item name for security
        item_name = listing_data.get('itemName', 'Item')
        
        # Enforce the authoritative server-side price anchor using precise decimals
        base_price = Decimal(str(listing_data.get('unit_price' if 'unit_price' in listing_data else 'price'))).quantize(Decimal('0.01'))
        
        # Handle bundles correctly if configured
        is_bundled = listing_data.get('is_bundled_pack', False)
        bundle_multiplier = int(listing_data.get('bundle_units_count', 1))
        
        if is_bundled and base_price < Decimal('20.00'):
            authoritative_base_price = (base_price * bundle_multiplier).quantize(Decimal('0.01'))
        else:
            authoritative_base_price = base_price

        # Cross-verify with client request to intercept price manipulation
        if abs(Decimal(str(client_gross_amt)) - authoritative_base_price) > Decimal('0.00'):
            print(f"🛡️ SECURITY ALERT: Intercepted manipulated client checkout price value: GHS {client_gross_amt} for item costing GHS {authoritative_base_price}!")
            return jsonify({"success": False, "error": "Transaction security mismatch detected."}), 400

        protection_option = int(protection_option)

        # Enforce Protection Gating Rules
        if authoritative_base_price >= Decimal('1000.00') and protection_option != 1:
            return jsonify({"success": False, "error": "Protected Escrow is mandatory for high-value items."}), 400
        if authoritative_base_price >= Decimal('100.00') and protection_option == 3:
            return jsonify({"success": False, "error": "Protection cannot be waived for this value bracket."}), 400

        # Compute Premium Using Exact Decimal Arithmetic
        escrow_premium = Decimal('0.00')
        if protection_option == 1:
            escrow_premium = (authoritative_base_price * Decimal('0.02')).quantize(Decimal('0.01'))
        
        total_buyer_charge = (authoritative_base_price + escrow_premium).quantize(Decimal('0.01'))
        amount_in_pesewas = int(total_buyer_charge * 100)

        # Fetch Merchant Context
        merchant_id = listing_data.get('merchantId')
        merchant_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data')
              .collection('verified_merchants').document(str(merchant_id).strip())
        ).get()

        if not merchant_ref.exists:
            return jsonify({"success": False, "error": "Verified owner profile missing."}), 400

        merchant_data = merchant_ref.to_dict()
        merchant_momo = merchant_data.get('phone') or merchant_data.get('momo') or merchant_data.get('merchantPhone')

        # Cache Staging Document
        hashed_pin = bcrypt.hashpw(pin_str.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        session_token = str(uuid.uuid4())
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)

        staged_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('private').document('staged_sessions')
              .collection('tokens').document(session_token)
        )
        
        staged_ref.set({
            "hashed_pin":         hashed_pin,
            "buyer_phone":        phone_str,
            "listing_id":         listing_id,
            "merchant_id":        merchant_id,
            "amount":             float(authoritative_base_price),
            "protection_option":  protection_option,
            "total_charge":       float(total_buyer_charge),
            "momo":               str(merchant_momo).strip(),
            "item_name":          item_name,
            "is_bundled_pack": listing_data.get('is_bundled_pack', False),
            "bundle_units_count": listing_data.get('bundle_units_count', 1),
            "expires_at":         expires_at,
            "created_at":         firestore.SERVER_TIMESTAMP,
        })

        return jsonify({
            "success":           True,
            "sessionToken":      session_token,
            "amountInPesewas":   amount_in_pesewas,
            "secureEmailAnchor": os.getenv("ESCROW_EMAIL", "escrow-node@ledgehold.com"),
        }), 200

    except Exception as e:
        print(f"❌ CHECKOUT INIT CRASH: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": "Internal server configuration error."}), 500


# ═══════════════════════════════════════════════════════════════
# GATEKEEPER VERIFY (FINAL SWIPE & PAYOUT)
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/gatekeeper/verify', methods=['POST'])
def gatekeeper_verify():
    data           = request.json or {}
    order_id       = data.get('orderId') or data.get('listingId')
    buyer_phone    = data.get('buyerPhone')
    incoming_pin   = data.get('handoffPin')

    if not order_id:
        return jsonify({"success": False, "error": "Missing order identifier."}), 400

    final_payout_volume = Decimal('0.00')
    payout_successful   = False
    payout_error_msg    = None

    try:
        orders_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data').collection('orders')
        )

        # Try direct document lookup first (when buyer selected a specific order)
        order_doc = orders_ref.document(order_id).get()

        if order_doc.exists:
            order_data_check = order_doc.to_dict()
            if order_data_check.get('status') in ['paid_in_escrow', 'buyer_reviewing', 'payout_failed', 'processing_payout']:
                target_doc = order_doc
            else:
                return jsonify({"success": False, "error": "No active escrow found."}), 404
        else:
            # Fallback: query by listing_id
            query = (
                orders_ref
                .where(filter=FieldFilter('listing_id', '==', order_id))
                .where(filter=FieldFilter('status', 'in', [
                    'paid_in_escrow', 'buyer_reviewing',
                    'payout_failed',  'processing_payout'
                ]))
                .limit(1).get()
            )

            if not query:
                return jsonify({"success": False, "error": "No active escrow found."}), 404

            target_doc = query[0]

        paystack_ref = target_doc.id
        order_ref    = target_doc.reference

        # ── PRE-TRANSACTION LOCKOUT FAST-PATH ──
        pre_check = target_doc.to_dict()
        if pre_check.get('failed_attempts', 0) >= 5 or pre_check.get('status') == 'locked':
            return jsonify({"success": False, "error": "Transaction locked due to multiple failed attempts. Contact Support."}), 403

        # ── ATOMIC TRANSACTION BOUNDARY ──
        @firestore.transactional
        def verify_and_claim_payout(transaction, order_ref, buyer_phone, incoming_pin):
            snapshot = order_ref.get(transaction=transaction)
            order_data = snapshot.to_dict()

            failed_attempts = order_data.get('failed_attempts', 0)
            if failed_attempts >= 5:
                return {"status": "locked", "order_data": order_data}

            if order_data.get('payout_status') == 'PENDING':
                payout_initiated_at = order_data.get('payout_initiated_at')
                if payout_initiated_at:
                    if payout_initiated_at.tzinfo is None:
                        payout_initiated_at = payout_initiated_at.replace(tzinfo=datetime.timezone.utc)
                    
                    time_delta = datetime.datetime.now(datetime.timezone.utc) - payout_initiated_at
                    if time_delta > datetime.timedelta(minutes=5):
                        print(f"⌛ OVERRIDE DEPLOYED: Stuck PENDING lock on {order_ref.id} timed out after 5 minutes.")
                    else:
                        return {"status": "already_processing", "order_data": order_data}
                else:
                    return {"status": "already_processing", "order_data": order_data}

            stored_pin_hash    = order_data.get('securityStamp', {}).get('handoffPin')
            actual_buyer_phone = order_data.get('buyerPhone')

            is_valid = False
            raw_pin_string = str(incoming_pin).strip() if incoming_pin else ""
            pin_bytes = raw_pin_string.encode('utf-8') if raw_pin_string else b''

            if buyer_phone and stored_pin_hash and pin_bytes:
                p = str(buyer_phone).strip()
                phone_variants = list(set([
                    p,
                    '233' + p[1:] if p.startswith('0') else p,
                    '0'   + p[3:] if p.startswith('233') else p,
                ]))
                if actual_buyer_phone in phone_variants and bcrypt.checkpw(pin_bytes, stored_pin_hash.encode('utf-8')):
                    is_valid = True

            if not is_valid:
                new_failures = failed_attempts + 1
                if new_failures >= 5:
                    transaction.update(order_ref, {
                        "failed_attempts": new_failures,
                        "status": "locked"
                    })
                    return {"status": "just_locked", "order_data": order_data}
                else:
                    transaction.update(order_ref, {"failed_attempts": new_failures})
                    return {"status": "invalid_credentials", "order_data": order_data}

            transaction.update(order_ref, {
                "status":              "processing_payout",
                "payout_status":       "PENDING",
                "payout_initiated_at": firestore.SERVER_TIMESTAMP,
                "failed_attempts":     0
            })
            return {"status": "claimed", "order_data": order_data}

        tx = db.transaction()
        tx_result = verify_and_claim_payout(tx, order_ref, buyer_phone, incoming_pin)
        order_data = tx_result["order_data"]
        item_name  = order_data.get('item', 'your listed item')

        if tx_result["status"] in ["locked", "just_locked"]:
            return jsonify({"success": False, "error": "Listing locked due to multiple failed attempts. Contact Support."}), 403
        if tx_result["status"] == "already_processing":
            return jsonify({"success": False, "error": "Transfer already processing. Please wait a moment."}), 429
        if tx_result["status"] == "invalid_credentials":
            return jsonify({"success": False, "error": "Authentication Failed. Please check your Delivery PIN."}), 404

        # ── PAYOUT PIPELINE ──
        raw_merchant_phone  = order_data.get('momo') or order_data.get('merchantPhone')
        merchant_id_string  = order_data.get('merchantId', 'Verified Merchant')
        gross_amount        = Decimal(str(order_data.get('amount', '0.0'))).quantize(Decimal('0.01'))

        if raw_merchant_phone and gross_amount > Decimal('0.00'):
            try:
                if gross_amount < Decimal('10.00'):
                    order_ref.update({
                        "status": "payout_failed",
                        "payout_status": "MANUAL_AUDIT_REQUIRED",
                        "gateway_responsfe": "Transaction value dropped beneath minimum platform value limits."
                    })
                    return jsonify({"success": False, "error": "Transaction value beneath minimum platform threshold limits."}), 400

                if gross_amount >= Decimal('2000.00'):    merchant_fee_rate = Decimal('0.025')
                elif gross_amount >= Decimal('500.00'):   merchant_fee_rate = Decimal('0.03')
                else:                                     merchant_fee_rate = Decimal('0.035')

                if gross_amount <= Decimal('25.00'):
                    flat_outbound_transfer_fee = Decimal('0.80')
                else:
                    flat_outbound_transfer_fee = Decimal('0.40')

                merchant_commission = (gross_amount * merchant_fee_rate).quantize(Decimal('0.01'))
                final_payout_volume = (gross_amount - merchant_commission - flat_outbound_transfer_fee).quantize(Decimal('0.01'))

                payout_kobo = int(final_payout_volume * 100)
                headers = {
                    "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                    "Content-Type":  "application/json",
                }

                momo_str = str(raw_merchant_phone).strip()
                if momo_str.startswith('233'): 
                    momo_str = '0' + momo_str[3:]

                if momo_str.startswith(('024', '054', '055', '059', '025')):    bank_code = 'MTN'
                elif momo_str.startswith(('020', '050')):                       bank_code = 'TCL'
                elif momo_str.startswith(('027', '057', '026', '056')):         bank_code = 'ATL'
                else:                                                           bank_code = 'MTN'

                rcp_res = requests.post(
                    "https://api.paystack.co/transferrecipient",
                    json={
                        "type":           "mobile_money",
                        "name":           merchant_id_string,
                        "account_number": momo_str,
                        "bank_code":      bank_code,
                        "currency":       "GHS",
                    },
                    headers=headers,
                ).json()

                if rcp_res.get('status'):
                    recipient_code   = rcp_res['data']['recipient_code']
                    payout_track_id  = str(uuid.uuid4())

                    order_ref.update({
                        "payout_reference": payout_track_id,
                        "merchant_fee_deducted": float(merchant_commission),
                        "merchant_transfer_fee": float(flat_outbound_transfer_fee),
                        "net_payout_remitted": float(final_payout_volume)
                    })

                    payout_res = requests.post(
                        "https://api.paystack.co/transfer",
                        json={
                            "source":    "balance",
                            "amount":    payout_kobo,
                            "recipient": recipient_code,
                            "reason":    f"Ledgehold Escrow Release. Ref: {paystack_ref}",
                            "reference": payout_track_id,
                        },
                        headers=headers,
                    ).json()

                    if payout_res.get('status'):
                        returned_gateway_amount = int(payout_res.get('data', {}).get('amount', 0))
                        
                        if returned_gateway_amount == payout_kobo:
                            print(f"💸 PIPELINE SUCCESS: GHS {final_payout_volume} remitted safely to gateway.")
                            payout_successful = True
                        else:
                            payout_error_msg = "Gateway amount verification check failed."
                            print(f"🚨 FRAUD BLOCK: Value mismatch caught! Expected kobo: {payout_kobo} | Got: {returned_gateway_amount}")
                    else:
                        payout_error_msg = payout_res.get('message', 'Paystack Transfer Rejected.')
                        print(f"🚨 TRANSFER REJECTION: {payout_error_msg}")
                else:
                    payout_error_msg = rcp_res.get('message', 'Recipient Setup Rejected.')
                    print(f"🚨 RECIPIENT REJECTION: {payout_error_msg}")

            except Exception as payout_err:
                payout_error_msg = "Internal financial pipeline exception."
                print(f"🚨 PAYOUT PIPELINE CRASH: {str(payout_err)}")
        else:
            payout_error_msg = "Merchant payment profile wallet data missing."
            print("⚠️ PAYOUT SKIPPED: Missing destination parameters.")

        # ── LIFECYCLE RECOVERY ──
        if payout_successful:
            order_ref.update({"status": "completed"})
        else:
            order_ref.update({
                "status": "payout_failed",
                "payout_status": "AWAITING_HANDSHAKE"
            })
            print(f"⚠️ ESCROW CIRCUIT RESET: Order {paystack_ref} unlocked for fallback execution retries.")

        # ── NOTIFICATIONS ──
        try:
            clean_buyer_phone    = format_gh_phone(order_data.get('buyerPhone'))
            clean_merchant_phone = format_gh_phone(raw_merchant_phone)

            if clean_buyer_phone != "Unknown":
                if payout_successful:
                    buyer_msg = f"Handover confirmed for {item_name}! You've successfully released payment to the seller. Thank you for choosing Ledgehold."
                else:
                    buyer_msg = f"Handover confirmed for {item_name}. We're processing your release and will notify you once the transfer is complete. Ref: {paystack_ref}"
                send_professional_sms(clean_buyer_phone, buyer_msg)
            if clean_merchant_phone != "Unknown":
                if payout_successful:
                    merchant_msg = f"Handover complete for {item_name}! Your payment of GHS {float(final_payout_volume):.2f} is processing and will arrive shortly."
                else:
                    merchant_msg = f"Handover confirmed for {item_name}. We're experiencing a brief network delay. Your balance is secure. Support Ref: {paystack_ref}"
                send_professional_sms(clean_merchant_phone, merchant_msg)
        except Exception as sms_err:
            print(f"⚠️ Notification engine dropped: {str(sms_err)}")

        try:
            send_handoff_email(order_data, paystack_ref)
        except Exception as email_err:
            print(f"⚠️ Email receipt logging fault bypassed: {str(email_err)}")

        # ── RESPONSE ──
        response_payload = {
            "success":  payout_successful,
            "verified": payout_successful,
            "item":     item_name,
            "ref":      paystack_ref
        }
        
        if not payout_successful:
            response_payload["error"] = payout_error_msg or "Handshake authenticated, but platform network delay. Please try swiping again."

        return jsonify(response_payload), 200

    except Exception as e:
        print("🚨 CRITICAL GLOBAL CRASH IN VERIFY GATEWAY CONTAINER LAYER:")
        traceback.print_exc()
        return jsonify({"success": False, "verified": False, "error": "Internal platform infrastructure error. Contact Support."}), 500


# ═══════════════════════════════════════════════════════════════
# GATEKEEPER REVIEW (PIN VERIFICATION)
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/gatekeeper/review', methods=['POST'])
def gatekeeper_set_review():
    data        = request.json or {}
    listing_id  = data.get('listingId')
    buyer_phone = data.get('buyerPhone')
    handoff_pin = data.get('handoffPin')

    if not listing_id or not buyer_phone or not handoff_pin:
        return jsonify({"success": False, "error": "Missing parameters."}), 400

    try:
        orders_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data').collection('orders')
        )

        # Get ALL active orders for this listing
        query = (
            orders_ref
            .where(filter=FieldFilter('listing_id', '==', listing_id))
            .where(filter=FieldFilter('status', 'in', ['paid_in_escrow', 'buyer_reviewing']))
            .get()
        )

        if not query:
            return jsonify({"success": False, "requires_manual": True}), 202

        # Filter by phone number
        p = str(buyer_phone).strip()
        phone_variants = set([
            p,
            '233' + p[1:] if p.startswith('0') else p,
            '0'   + p[3:] if p.startswith('233') else p,
        ])

        matching_orders = []
        for doc in query:
            order_data = doc.to_dict()
            stored_phone = str(order_data.get('buyerPhone', '')).strip()
            if stored_phone in phone_variants:
                item_name = order_data.get('item', 'Item')
                bundle_count = order_data.get('bundle_units_count', 1)
                is_bundled = order_data.get('is_bundled_pack', False)
                display_name = f"{item_name} (Pack of {bundle_count})" if (is_bundled and bundle_count > 1) else item_name
                
                matching_orders.append({
                    "order_id": doc.id,
                    "item": display_name,
                    "amount": order_data.get('amount', 0),
                    "status": order_data.get('status')
                })

        if not matching_orders:
            return jsonify({"success": False, "requires_manual": True}), 202

        # ── CHECK IF PRICES DIFFER ──
        unique_prices = set(o['amount'] for o in matching_orders)
        
        if len(unique_prices) > 1:
            return jsonify({
                "success": False,
                "requires_selection": True,
                "options": matching_orders
            }), 300

        # ── SINGLE ORDER OR ALL SAME PRICE ──
        selected = matching_orders[0]
        target_doc = orders_ref.document(selected['order_id']).get()
        order_data = target_doc.to_dict()
        order_ref = target_doc.reference

        failed_attempts = order_data.get('failed_attempts', 0)
        if failed_attempts >= 5:
            return jsonify({"success": False, "error": "Locked. Contact Support."}), 403

        pin_str = str(handoff_pin).strip()
        if not pin_str or not pin_str.isdigit() or len(pin_str) != 4:
            return jsonify({"success": False, "error": "Invalid PIN format."}), 400

        stored_pin_hash = order_data.get('securityStamp', {}).get('handoffPin')
        pin_bytes = pin_str.encode('utf-8')

        if not stored_pin_hash or not bcrypt.checkpw(pin_bytes, stored_pin_hash.encode('utf-8')):
            new_failures = failed_attempts + 1
            update = {"failed_attempts": new_failures}
            if new_failures >= 5:
                update["status"] = "locked"
            order_ref.update(update)
            return jsonify({"success": False, "error": "Incorrect PIN."}), 401

        order_ref.update({"status": "buyer_reviewing", "failed_attempts": 0})
        return jsonify({
            "success": True,
            "order_id": selected['order_id'],
            "item": selected['item'],
            "amount": selected['amount']
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": "Internal error."}), 500


# ═══════════════════════════════════════════════════════════════
# GATEKEEPER REVIEW SELECT (BUYER CHOOSES FROM MULTIPLE ORDERS)
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/gatekeeper/review/select', methods=['POST'])
def gatekeeper_set_review_select():
    data        = request.json or {}
    order_id    = data.get('orderId')
    buyer_phone = data.get('buyerPhone')
    handoff_pin = data.get('handoffPin')

    if not order_id or not buyer_phone or not handoff_pin:
        return jsonify({"success": False, "error": "Missing parameters."}), 400

    try:
        orders_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data').collection('orders')
        )

        target_doc = orders_ref.document(order_id).get()
        if not target_doc.exists:
            return jsonify({"success": False, "error": "Order not found."}), 404

        order_data = target_doc.to_dict()
        order_ref = target_doc.reference

        p = str(buyer_phone).strip()
        phone_variants = set([
            p,
            '233' + p[1:] if p.startswith('0') else p,
            '0'   + p[3:] if p.startswith('233') else p,
        ])
        stored_phone = str(order_data.get('buyerPhone', '')).strip()
        if stored_phone not in phone_variants:
            return jsonify({"success": False, "error": "Unauthorized."}), 403

        failed_attempts = order_data.get('failed_attempts', 0)
        if failed_attempts >= 5:
            return jsonify({"success": False, "error": "Locked. Contact Support."}), 403

        pin_str = str(handoff_pin).strip()
        if not pin_str or not pin_str.isdigit() or len(pin_str) != 4:
            return jsonify({"success": False, "error": "Invalid PIN format."}), 400

        stored_pin_hash = order_data.get('securityStamp', {}).get('handoffPin')
        pin_bytes = pin_str.encode('utf-8')

        if not stored_pin_hash or not bcrypt.checkpw(pin_bytes, stored_pin_hash.encode('utf-8')):
            new_failures = failed_attempts + 1
            update = {"failed_attempts": new_failures}
            if new_failures >= 5:
                update["status"] = "locked"
            order_ref.update(update)
            return jsonify({"success": False, "error": "Incorrect PIN."}), 401
        
        item_name = order_data.get('item', 'Item')
        bundle_count = order_data.get('bundle_units_count', 1)
        is_bundled = order_data.get('is_bundled_pack', False)
        display_name = f"{item_name} (Pack of {bundle_count})" if (is_bundled and bundle_count > 1) else item_name

        order_ref.update({"status": "buyer_reviewing", "failed_attempts": 0})
        return jsonify({
            "success": True,
            "order_id": order_id,
            "item": display_name,
            "amount": order_data.get('amount', 0)
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": "Internal error."}), 500


# ═══════════════════════════════════════════════════════════════
# ORDER TOKEN RETRIEVAL
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/order/my-token', methods=['POST'])
def get_my_order_token():
    data = request.json or {}
    incoming_ref = data.get('ref', '').strip()
    claimed_phone = data.get('buyerPhone', '').strip()
    
    if not incoming_ref or not claimed_phone:
        return jsonify({"success": False, "error": "Missing parameters."}), 400

    try:
        orders_col = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data')
              .collection('orders')
        )

        order_data = None

        direct_doc = orders_col.document(incoming_ref).get()
        if direct_doc.exists:
            order_data = direct_doc.to_dict()
        
        if not order_data:
            query_snap = (
                orders_col
                .where(filter=FieldFilter('listing_id', '==', incoming_ref))
                .where(filter=FieldFilter('status', 'in', [
                    'paid_in_escrow', 'buyer_reviewing', 
                    'processing_payout', 'payout_failed'
                ]))
                .limit(1).get()
            )
            if query_snap:
                order_data = query_snap[0].to_dict()

        if not order_data:
            return jsonify({"deviceToken": None, "status": "processing"}), 202

        stored_phone = str(order_data.get('buyerPhone', '')).strip()
        p = claimed_phone
        phone_variants = list(set([
            p,
            '233' + p[1:] if p.startswith('0') else p,
            '0'   + p[3:] if p.startswith('233') else p,
        ]))

        if stored_phone not in phone_variants:
            print(f"🛡️ SECURITY FRAUD BLOCKED: Unauthorized token request for reference key {incoming_ref}")
            return jsonify({"success": False, "error": "Unauthorized order access profile."}), 403

        token = order_data.get('securityStamp', {}).get('token', '')
        return jsonify({"deviceToken": token, "status": "secured"}), 200

    except Exception as e:
        print(f"🚨 API TOKEN DISTRIBUTION MULTI-TRACK EXCEPTION: {str(e)}")
        return jsonify({"success": False, "error": "Internal ledger query error."}), 500


# ═══════════════════════════════════════════════════════════════
# ADMIN AUTH
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/admin-auth', methods=['POST'])
def admin_auth():
    data = request.json
    user_id = data.get('id', '').strip()
    user_pin = data.get('pin', '').strip()
    
    for i, admin_id in enumerate(ADMIN_IDS):
        if user_id == admin_id and i < len(ADMIN_PINS) and user_pin == ADMIN_PINS[i]:
            return jsonify({"success": True})
    
    return jsonify({"success": False, "message": "Unauthorized"}), 401


# ═══════════════════════════════════════════════════════════════
# ADMIN SMS DISPATCH
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/admin/send_sms', methods=['POST'])
def admin_send_sms():
    data = request.json
    phone = data.get('phone')
    message = data.get('message')

    if not phone or not message:
        return jsonify({"success": False, "error": "Missing parameters"}), 400

    try:
        clean_phone = str(phone).replace("+", "").replace(" ", "").strip()
        if clean_phone.startswith("0"):
            clean_phone = "233" + clean_phone[1:]

        hubtel_client_id = os.environ.get('HUBTEL_CLIENT_ID')
        hubtel_client_secret = os.environ.get('HUBTEL_CLIENT_SECRET')
        sender_id = os.environ.get('HUBTEL_SENDER_ID', 'Ledgehold')

        if not hubtel_client_id or not hubtel_client_secret:
            return jsonify({"success": True, "warning": "Simulated. No credentials."}), 200

        response = requests.get(
            "https://smsc.hubtel.com/v1/messages/send",
            params={
                "clientid": hubtel_client_id,
                "clientsecret": hubtel_client_secret,
                "from": sender_id,
                "to": clean_phone,
                "content": message
            }
        )

        try:
            res_data = response.json()
            success = response.ok and res_data.get('status') in [0, 1, 100]
            
            if success:
                msg_id = res_data.get('messageId', 'Unknown')
                print(f"📨 SMS DISPATCHED: Success to {clean_phone} | Hubtel ID: {msg_id}")
                return jsonify({"success": True}), 200
            else:
                error_msg = res_data.get('message', 'Gateway rejected the message')
                print(f"❌ SMS Gateway Error: {error_msg}")
                return jsonify({"success": False, "error": error_msg}), 502
                
        except Exception:
            if response.ok:
                return jsonify({"success": True, "warning": "Response format unexpected"}), 200
            else:
                return jsonify({"success": False, "error": "Gateway communication failed"}), 502

    except Exception as e:
        print(f"🛡️ SMS Pipeline Exception: {str(e)}")
        return jsonify({"success": False, "error": "Internal Processing Error"}), 500


# ═══════════════════════════════════════════════════════════════
# ADMIN REVERSE ESCROW
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/admin/reverse-escrow', methods=['POST'])
def admin_reverse_escrow():
    data = request.json or {}
    order_id = data.get('orderId')
    admin_id = data.get('adminId')
    admin_pin = data.get('adminPin')
    
    if not order_id or not admin_id or not admin_pin:
        return jsonify({"success": False, "error": "Missing parameters."}), 400
    
    is_valid = False
    for i, aid in enumerate(ADMIN_IDS):
        if admin_id == aid and i < len(ADMIN_PINS) and admin_pin == ADMIN_PINS[i]:
            is_valid = True
            break

    if not is_valid:
        return jsonify({"success": False, "error": "Unauthorized."}), 401
    
    try:
        order_ref = (
            db.collection('artifacts').document(APP_ID)
              .collection('public').document('data')
              .collection('orders').document(order_id)
        )
        
        order_doc = order_ref.get()
        if not order_doc.exists:
            return jsonify({"success": False, "error": "Order not found."}), 404
        
        order_data = order_doc.to_dict()
        reversible_statuses = ['paid_in_escrow', 'buyer_reviewing', 'payout_failed', 'processing_payout']
        if order_data.get('status') not in reversible_statuses:
            return jsonify({
                "success": False, 
                "error": f"Order is in '{order_data.get('status')}' state and cannot be reversed."
            }), 400
        
        order_ref.update({
            "status": "refunded",
            "payout_status": "ADMIN_REVERSED",
            "administrative_override_by": admin_id,
            "overridden_at": firestore.SERVER_TIMESTAMP
        })
        
        print(f"🛡️ ADMIN REVERSAL: Order {order_id} reversed by {admin_id}")
        return jsonify({"success": True}), 200
        
    except Exception as e:
        print(f"❌ Reversal error: {e}")
        traceback.print_exc()
        return jsonify({"success": False, "error": "Internal server error."}), 500


# ═══════════════════════════════════════════════════════════════
# EMAIL DISPATCH
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/api/email/dispatch', methods=['POST'])
def universal_email_dispatch():
    data = request.json
    action_type = data.get('type')
    payload = data.get('payload', {})
    
    if not action_type:
        return jsonify({"success": False, "error": "Missing action type."}), 400

    subject = ""
    html_body = ""

    if action_type == "kyc_submitted":
        merchant_name = payload.get('fullName', 'Unknown Merchant')
        merchant_id = payload.get('merchantId', 'Unknown ID')
        university = payload.get('university', 'Unknown Campus')
        
        subject = f"👤 New Account: KYC Submitted ({merchant_id})"
        html_body = f"""
        <div style="font-family: sans-serif; padding: 20px; color: #0f172a;">
            <h3 style="color: #3b82f6; margin-top: 0;">New Merchant Registration Awaiting Review</h3>
            <hr style="border: 0; border-top: 1px solid #e2e8f0; margin-bottom: 20px;"/>
            <p><b>Name:</b> {merchant_name}</p>
            <p><b>Merchant ID:</b> {merchant_id}</p>
            <p><b>Institution:</b> {university}</p>
            <br/>
            <p><a href="https://prolyfiq.store/admin_controls" style="background: #0f172a; color: white; padding: 12px 24px; text-decoration: none; border-radius: 30px; font-weight: bold; font-size: 13px;">Open Admin Command Center</a></p>
        </div>
        """

    elif action_type == "ad_inquiry":
        business_name = payload.get('businessName', 'Unknown Business')
        contact_email = payload.get('email', 'N/A')
        contact_phone = payload.get('phone', 'N/A')
        
        subject = f"📢 Ad Inquiry: {business_name}"
        html_body = f"""
        <div style="font-family: sans-serif; padding: 20px; color: #0f172a;">
            <h3 style="color: #3b82f6; margin-top: 0;">New Advertisement Request</h3>
            <hr style="border: 0; border-top: 1px solid #e2e8f0; margin-bottom: 20px;"/>
            <p><b>Business Name:</b> {business_name}</p>
            <p><b>Email:</b> <a href="mailto:{contact_email}">{contact_email}</a></p>
            <p><b>Phone/WhatsApp:</b> {contact_phone}</p>
            <br/>
            <p style="font-size: 13px; color: #64748b;">Please reach out to this business to request necessary business info.</p>
        </div>
        """
    
    elif action_type == "merch_request":
        merchant_id = payload.get('merchantId', 'Unknown Merchant')
        campus = payload.get('campus', 'Unknown Campus')
        pickup = payload.get('pickupPoint', 'Unknown Location')
        selection = payload.get('gearSelection', 'No gear specified')
        total_items = payload.get('totalItems', 1)
        
        subject = f"👕 [MERCH ORDER] - {merchant_id} ({total_items} Items)"
        html_body = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #0f172a;">
            <h3 style="color: #10b981; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">
                New Custom Gear Order
            </h3>
            <p style="margin-top: 15px;"><b>Merchant Identifier:</b> {merchant_id}</p>
            <p><b>Distribution Campus:</b> {campus}</p>
            <p><b>Fulfillment Pickup Point:</b> {pickup}</p>
            
            <h4 style="margin-top: 25px; margin-bottom: 10px; color: #475569; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase;">
                Gear Configuration Breakdown
            </h4>
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 12px; font-size: 14px; line-height: 1.6;">
                {selection}
            </div>
            
            <p style="font-size: 11px; color: #94a3b8; margin-top: 30px; border-top: 1px dashed #e2e8f0; padding-top: 15px;">
                Fulfillment SLA: Standard 10-day production loop applies.
            </p>
        </div>
        """

    elif action_type == "merchant_support":
        merchant_id = payload.get('merchantId', 'Unknown/Logged Out')
        contact_email = payload.get('email', 'No email provided')
        issue_desc = payload.get('issue', 'No description provided')
        
        subject = f"🚨 SUPPORT TICKET - {merchant_id}"
        html_body = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #0f172a;">
            <h3 style="color: #ef4444; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">
                Priority Support Request
            </h3>
            <p style="margin-top: 15px;"><b>Merchant Account:</b> {merchant_id}</p>
            <p><b>Contact Email:</b> {contact_email}</p>
            
            <h4 style="margin-top: 25px; margin-bottom: 10px; color: #475569; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase;">
                Issue / Concern Log
            </h4>
            <div style="background: #fff1f2; border: 1px solid #fda4af; padding: 15px; border-radius: 12px; font-size: 14px; line-height: 1.6; color: #9f1239;">
                {issue_desc}
            </div>
            
            <p style="font-size: 11px; color: #94a3b8; margin-top: 30px; border-top: 1px dashed #e2e8f0; padding-top: 15px;">
                This ticket was generated via the Secure Dashboard Support Hub.
            </p>
        </div>
        """

    elif action_type == "refund_request":
        phone = payload.get('phone', 'Not provided')
        ref = payload.get('reference', 'Not provided')
        reason = payload.get('reason', 'Not specified')
        notes = payload.get('notes', 'None')
        submitted_at = payload.get('submittedAt', 'Unknown')
        
        # Human-readable reason
        reason_labels = {
            "item_not_as_described": "Item not as described",
            "item_defective": "Item is defective or damaged",
            "seller_no_show": "Seller did not show up",
            "wrong_item": "Received wrong item",
            "changed_mind": "Changed my mind / No longer needed",
            "duplicate_charge": "Duplicate or incorrect charge",
            "other": "Other"
        }
        reason_display = reason_labels.get(reason, reason)
        
        subject = f"🔙 Refund Request — {ref}"
        html_body = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #0f172a;">
            <h3 style="color: #dc3545; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">
                Refund Request Received
            </h3>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Buyer Phone</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{phone}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Transaction Reference</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>{ref}</code></td>
                </tr>
                <tr style="background: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Reason</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{reason_display}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Additional Notes</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{notes}</td>
                </tr>
                <tr style="background: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Submitted At</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{submitted_at}</td>
                </tr>
            </table>
            
            <p style="text-align: center; margin-top: 30px;">
                <a href="https://prolyfiq.store/financial_view" 
                style="background: #0f172a; color: white; padding: 12px 28px; text-decoration: none; border-radius: 30px; font-weight: bold; font-size: 13px; display: inline-block;">
                    Review in Finance Panel
                </a>
            </p>
            
            <p style="font-size: 11px; color: #94a3b8; margin-top: 30px; border-top: 1px dashed #e2e8f0; padding-top: 15px;">
                This refund request was submitted via the public Support modal on ProlyfiQ.
            </p>
        </div>
        """

    elif action_type == "user_feedback":
        message = payload.get('message', 'No message provided')
        page = payload.get('page', 'Unknown page')
        submitted_at = payload.get('submittedAt', 'Unknown')
        
        subject = f"💬 User Feedback — {page}"
        html_body = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #0f172a;">
            <h3 style="color: #6366f1; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">
                Platform Feedback Received
            </h3>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Page</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><code>{page}</code></td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;"><strong>Submitted At</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{submitted_at}</td>
                </tr>
            </table>
            
            <h4 style="margin-top: 20px; margin-bottom: 10px; color: #475569; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase;">
                Message
            </h4>
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 10px; font-size: 14px; line-height: 1.7; color: #334155;">
                {message}
            </div>
            
            <p style="font-size: 11px; color: #94a3b8; margin-top: 30px; border-top: 1px dashed #e2e8f0; padding-top: 15px;">
                This feedback was submitted via the footer form on ProlyfiQ.
            </p>
        </div>
        """

    else:
        print(f"⚠️ Switchboard Warning: Unregistered action type '{action_type}'")
        return jsonify({"success": False, "error": "Template not found."}), 400

    try:
        response = resend.Emails.send({
            "from": "Ledgehold System <mail.dataexpress.store>",
            "to": ["ledgehold.business@gmail.com"],
            "subject": subject,
            "html": html_body
        })
        print(f"📧 ALERTS DISPATCHED: '{action_type}' email routed to Admin array.")
        return jsonify({"success": True}), 200
        
    except Exception as e:
        print(f"❌ Email Switchboard Exception: {str(e)}")
        return jsonify({"success": False, "error": "Internal server error."}), 500


# ═══════════════════════════════════════════════════════════════
# PAYMENT VERIFICATION
# ═══════════════════════════════════════════════════════════════

@financial_bp.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.json
    reference = data.get('reference')
    
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    
    try:
        response = requests.get(url, headers=headers)
        json_resp = response.json()
        
        if json_resp['status'] is True and json_resp['data']['status'] == "success":
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "failed"})
            
    except Exception as e:
        print(f"Error connecting to Paystack: {e}")
        return jsonify({"status": "error"})