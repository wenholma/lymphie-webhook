import os
import sqlite3
import secrets
from datetime import datetime
from flask import Flask, request, jsonify
import stripe
import resend

app = Flask(__name__)

STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'The Lymphie Sanctuary <info@thelymphiesanctuary.com>')
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/licenses.db')

stripe.api_key = STRIPE_SECRET_KEY
resend.api_key = RESEND_API_KEY

# ------------------------------------------------------------------------------
# DATABASE SETUP
# ------------------------------------------------------------------------------
def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE NOT NULL,
        customer_email TEXT NOT NULL,
        stripe_session_id TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

def save_license_key(license_key, customer_email, stripe_session_id):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (license_key, customer_email, stripe_session_id) VALUES (?, ?, ?)",
        (license_key, customer_email, stripe_session_id)
    )
    conn.commit()
    conn.close()

def generate_license_key():
    part1 = secrets.token_hex(2).upper()
    part2 = secrets.token_hex(2).upper()
    part3 = secrets.token_hex(2).upper()
    return f"LKEY-{part1}-{part2}-{part3}"

# ------------------------------------------------------------------------------
# EMAIL
# ------------------------------------------------------------------------------
def send_license_email(to_email, license_key):
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
        <h2 style="color: #2E7D5E;">🌿 The Lymphie Sanctuary</h2>
        <p>Thank you so much for supporting The Sanctuary — it means a lot.</p>
        <p>Your lifetime license key is:</p>
        <div style="background: #f0f7f4; padding: 20px; border-radius: 10px;
                    text-align: center; margin: 20px 0;">
            <code style="font-size: 24px; font-weight: bold;
                         letter-spacing: 2px;">{license_key}</code>
        </div>
        <p><strong>How to activate:</strong></p>
        <ol>
            <li>Open <a href="https://thelymphiesanctuary.streamlit.app">The Lymphie Sanctuary</a></li>
            <li>Go to <strong>Settings &amp; License</strong></li>
            <li>Copy and paste this key into the box and click <strong>Activate</strong></li>
        </ol>
        <p><strong>💡 Can't copy-paste?</strong> Type it manually in ALL CAPS with a dash after every
        4 characters: <code>LKEY-XXXX-YYYY-ZZZZ</code></p>
        <p>📌 Check your <strong>junk/spam folder</strong> if you need to find this email again —
        search for "Lymphie Sanctuary".</p>
        <p>Keep this email safe — this key is yours forever.
           If you ever lose it, just reply and I'll resend it.</p>
        <p>I hope The Sanctuary brings you a little more clarity
           and a little less overwhelm. 🌿</p>
        <p>With gratitude,<br>
           <strong>Marece</strong><br>
           <small>The Lymphie Sanctuary</small></p>
        <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
        <p style="font-size: 12px; color: #888;">
           The Lymphie Sanctuary – A private, local-first symptom journal.<br>
           Questions? Reply to this email or contact info@thelymphiesanctuary.com
        </p>
    </div>
    """
    try:
        resend.Emails.send({
            "from": FROM_EMAIL,
            "to": [to_email],
            "subject": "Your Lymphie Sanctuary License Key 🌿",
            "html": html_content
        })
        print(f"Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# ------------------------------------------------------------------------------
# WEBHOOK
# ------------------------------------------------------------------------------
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        # Safely convert StripeObject to dict
        session_dict = session.to_dict() if hasattr(session, 'to_dict') else session

        # Extract customer email safely
        customer_email = None
        customer_details = session_dict.get('customer_details')

        if hasattr(customer_details, 'to_dict'):
            customer_details = customer_details.to_dict()

        if isinstance(customer_details, dict):
            customer_email = customer_details.get('email')

        # Fallback
        if not customer_email:
            customer_email = session_dict.get('customer_email')

        stripe_session_id = session_dict.get('id')

        if customer_email:
            license_key = generate_license_key()
            init_db()
            save_license_key(license_key, customer_email, stripe_session_id)
            email_sent = send_license_email(customer_email, license_key)
            if email_sent:
                print(f"✅ License {license_key} sent to {customer_email}")
            else:
                print(f"❌ Failed to send email to {customer_email}")
        else:
            print(f"⚠️ No email found for session {stripe_session_id}")

    return jsonify({'status': 'success'}), 200

# ------------------------------------------------------------------------------
# VALIDATE
# ------------------------------------------------------------------------------
@app.route('/validate', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('license_key', '').strip().upper()

    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()

    # Try exact match first
    c.execute("SELECT * FROM licenses WHERE license_key = ?", (key,))
    result = c.fetchone()

    # If no match, try reformatting — user may have typed without dashes
    # LKEYXXXXXXXXXXXX → LKEY-XXXX-XXXX-XXXX
    if not result and key.startswith('LKEY') and '-' not in key and len(key) == 16:
        formatted = f"LKEY-{key[4:8]}-{key[8:12]}-{key[12:16]}"
        c.execute("SELECT * FROM licenses WHERE license_key = ?", (formatted,))
        result = c.fetchone()

    conn.close()
    return jsonify({'valid': bool(result)}), 200

# ------------------------------------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------------------------------------
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'database': DATABASE_PATH}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
