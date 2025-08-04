from flask import Flask, render_template, request, redirect, session # Import necessary libraries
from flask import url_for # For URL handling
import mysql.connector # For MySQL database connection
import hashlib # For hashing passwords
from config import db_config # Import database configuration
import os # For environment variable management 
# Load environment variables
from  dotenv import load_dotenv  # For loading environment variables from a .env file
load_dotenv() # Load environment variables from .env file
app = Flask(__name__) # Create Flask app instance
app.secret_key = os.getenv("SECRET_KEY", "default-insecure-dev-key")  # Set a secret key for session management


# Database connection
def get_db_connection():
    return mysql.connector.connect(**db_config)


# Login
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        userid = request.form['userid']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM Users WHERE userid=%s AND password_hash=%s", (userid, hashed_password))
        result = cursor.fetchone()
        conn.close()

        if result:
            session['userid'] = userid
            session['role'] = result[0]
            return redirect('/dashboard')
        else:
            error = "Invalid credentials"

    return render_template('login.html', error=error)


# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'userid' not in session:
        return redirect('/')
    return render_template('dashboard.html', user=session['userid'], role=session['role'])
def mask_card_number(data):
    try:
        decoded = data.decode()
        return decoded[:4] + '****' + decoded[-2:]
    except:
        return '********'
def mask_cvv(data):
    return '***'


# Vault
@app.route('/vault', methods=['GET', 'POST'])
def vault():
    if 'userid' not in session:
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()
    encryption_key = os.environ.get("ENCRYPTION_KEY", "fallback-insecure") # Use environment variable for encryption key
    error = None
    cards = []

    if request.method == 'POST':
        card = request.form['card']
        cvv = request.form['cvv']
        name = request.form['name']
        address = request.form['address']

        # Validation checks (inside POST block)
        if not card.isdigit() or not (13 <= len(card) <= 16):
            error = "Card number must be 13 to 16 digits."
        elif not cvv.isdigit() or not (3 <= len(cvv) <= 4):
            error = "CVV must be 3 to 4 digits."
        elif not name or not address:
            error = "Name and address are required."
        else:
            # Check for duplication
            check_query = """
            SELECT COUNT(*) FROM CardDetails 
            WHERE userid = %s AND card_number = AES_ENCRYPT(%s, %s)
            """
            cursor.execute(check_query, (session['userid'], card, encryption_key))
            count = cursor.fetchone()[0]

            if count > 0:
                error = "This card is already stored for this user."
            else:
                insert_query = """
                INSERT INTO CardDetails (userid, card_number, CVV, name, billing_address)
                VALUES (%s, AES_ENCRYPT(%s, %s), AES_ENCRYPT(%s, %s), %s, %s)
                """
                cursor.execute(insert_query, (session['userid'], card, encryption_key, cvv, encryption_key, name, address))
                conn.commit()

    # Now fetch cards after any POST handling
    if session['role'] == 'admin':
        cursor.execute("""
        SELECT id, userid, AES_DECRYPT(card_number, %s), AES_DECRYPT(CVV, %s), name, billing_address
        FROM CardDetails
        """, (encryption_key, encryption_key))
        cards = cursor.fetchall()
        for i in range(len(cards)):
            cards[i] = list(cards[i])
            cards[i][2] = mask_card_number(cards[i][2])
            cards[i][3] = mask_cvv(cards[i][3])
            cards[i] = tuple(cards[i])

    elif session['role'] in ['staff', 'auditor']:
        cursor.execute("""
        SELECT id, userid, card_number, CVV, name, billing_address
        FROM CardDetails
        """)
        cards = cursor.fetchall()
        for i in range(len(cards)):
            cards[i] = list(cards[i])
            cards[i][2] = mask_card_number(cards[i][2])
            cards[i][3] = mask_cvv(cards[i][3])
            cards[i] = tuple(cards[i])

    conn.close()
    return render_template('vault.html', cards=cards, role=session['role'], error=error)


# Route to decrypt card details
@app.route('/decrypt/<int:card_id>') 
def decrypt_card(card_id):
    if 'userid' not in session or session['role'] not in ['admin', 'staff', 'auditor']:
        return redirect('/')

    encryption_key = os.environ.get("ENCRYPTION_KEY", "fallback-insecure")
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT AES_DECRYPT(card_number, %s), AES_DECRYPT(CVV, %s), name, billing_address
        FROM CardDetails WHERE id = %s
    """, (encryption_key, encryption_key, card_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Card not found", 404

    try:
        card_number = row[0].decode()
        cvv = row[1].decode()
    except:
        card_number = str(row[0])
        cvv = str(row[1])

    name = row[2]
    address = row[3]
    
    return render_template(
    'decrypted.html',
    card_number=card_number,
    cvv=cvv,
    name=name,
    address=address
)
    
# Delete card
@app.route('/delete/<int:card_id>', methods=['POST'])
def delete_card(card_id):
    if 'userid' not in session or session['role'] != 'admin':
        return redirect('/')    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM CardDetails WHERE id = %s", (card_id,))
    conn.commit()
    conn.close()
    return redirect('/vault')

# Edit card details
@app.route('/edit/<int:card_id>', methods=['GET', 'POST'])
def edit_card(card_id):
    if 'userid' not in session or session['role'] != 'admin':
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()
    encryption_key = os.environ.get("ENCRYPTION_KEY", "fallback-insecure") # Use environment variable for encryption key

    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        cursor.execute("""
            UPDATE CardDetails SET name=%s, billing_address=%s WHERE id=%s
        """, (name, address, card_id))
        conn.commit()
        conn.close()
        return redirect('/vault')

    # Get the card data first
    cursor.execute("""
        SELECT AES_DECRYPT(card_number, %s), AES_DECRYPT(CVV, %s), name, billing_address 
        FROM CardDetails WHERE id = %s
    """, (encryption_key, encryption_key, card_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Card not found", 404

    try:
        card_number = row[0].decode()
        cvv = row[1].decode()
    except:
        card_number = str(row[0])
        cvv = str(row[1])

    # Only assign name and address if row is valid
    name = row[2]
    address = row[3]

    return render_template('edit_card.html', card_id=card_id, card_number=card_number, cvv=cvv, name=name, address=address)
# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
# Register new user 
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None

    if request.method == 'POST':
        if 'userid' not in request.form or 'password' not in request.form or 'role' not in request.form: # Check if all fields are provided
            error = "All fields are required." 
            return render_template('register.html', error=error, success=success) # Render the registration page with the error message
        userid = request.form['userid'] # Get the user ID from the form
        password = request.form['password'] # Get the password from the form
        if not userid or not password: # Check if user ID and password are not empty
            error = "User ID and password cannot be empty." 
            return render_template('register.html', error=error, success=success)
        role = request.form['role'] # Get the role from the form

        hashed_password = hashlib.sha256(password.encode()).hexdigest() # Hash the password using SHA-256

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO Users (userid, password_hash, role) VALUES (%s, %s, %s)", 
                           (userid, hashed_password, role))
            conn.commit()
            conn.close()
            success = "User registered successfully!"
        except mysql.connector.IntegrityError:
            error = "This email is already registered."

    return render_template('register.html', error=error, success=success)
# start the Flask application
if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
