from flask import Flask, render_template, request, redirect, url_for, g, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret'


def polyEncrypt(text, key):
    encrypted_text = ''
    key_index = 0

    for char in text:
        if char.isalpha():
            # Determine the shift amount based on the key
            shift = ord(key[key_index % len(key)].lower()) - ord('a')

            # Encrypt the character
            if char.isupper():
                encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

            key_index += 1
        else:
            # Leave non-alphabetic characters unchanged
            encrypted_text += char

    return encrypted_text

def polyDecrypt(encrypted_text, key):
    decrypted_text = ''
    key_index = 0

    for char in encrypted_text:
        if char.isalpha():
            # Determine the shift amount based on the key
            shift = ord(key[key_index % len(key)].lower()) - ord('a')

            # Decrypt the character
            if char.isupper():
                decrypted_text += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_text += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))

            key_index += 1
        else:
            # Leave non-alphabetic characters unchanged
            decrypted_text += char

    return decrypted_text


# Fungsi untuk mendapatkan koneksi database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

# Fungsi untuk menutup koneksi database setelah request selesai
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Inisialisasi database
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Tambahkan tabel users jika belum ada
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')

        db.commit()

# Halaman registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()

        # Check if the username already exists
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            return 'Username already exists. Please choose a different username.'

        # Enkripsi password menggunakan Polyalphabetic Cipher
        encrypted_password = polyEncrypt(password, key='secret')

        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted_password))
        db.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


# Halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            # Decrypt the stored password for comparison
            decrypted_password = polyDecrypt(user['password'], key='secret')

            if decrypted_password == password:
                # Set the user session upon successful login
                session['user_id'] = user['id']
                return redirect(url_for('show_users'))
        
        # Redirect to the login failed page
        return render_template('login_failed.html')

    return render_template('login.html')

# Halaman logout
@app.route('/logout')
def logout():
    # Clear the user session
    session.clear()
    return redirect(url_for('login'))

# Tambahkan route untuk menampilkan data pengguna
@app.route('/users')
def show_users():
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    users = cursor.execute('SELECT * FROM users').fetchall()
    return render_template('list_users.html', users=users)

# Tambahkan route untuk menghapus data pengguna
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('show_users'))


if __name__ == '__main__':
    app.teardown_appcontext(close_db)
    init_db()  # Initialize the database
    app.run(debug=True)
