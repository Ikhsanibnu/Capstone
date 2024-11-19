from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, UserMixin, LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
# URL koneksi MySQL
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://C3CP:S.Tr.Kom2024@194.31.53.102:3306/C3CP"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Kunci rahasia untuk session

# Inisialisasi SQLAlchemy dan LoginManager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect ke login jika belum login

# Definisikan model User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # ID pengguna
    nama_lengkap = db.Column(db.String(150), nullable=False)  # Nama lengkap
    alamat = db.Column(db.String(150), nullable=False)  # Alamat pengguna
    kontak = db.Column(db.String(150), nullable=False, unique=True)  # Kontak pengguna (misalnya email)
    jenis_pengguna = db.Column(db.String(50), nullable=False)  # Jenis pengguna (misalnya Admin, User)
    password = db.Column(db.String(150), nullable=False)  # Password pengguna

    def __repr__(self):
        return f'<User {self.nama_lengkap}>'

# Buat database dan tabel user jika belum ada
with app.app_context():
    db.create_all()

# Fungsi untuk mengelola user login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    # If the user is logged in, redirect them to the dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    # If the user is not logged in, redirect them to the login page
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        alamat = request.form['alamat']
        kontak = request.form['kontak']
        jenis_pengguna = request.form['jenis_pengguna']
        password = request.form['password']
        
        # Cek apakah pengguna sudah ada
        if User.query.filter_by(kontak=kontak).first():
            flash('Email sudah terdaftar.', 'danger')
            return redirect(url_for('register'))
        
        # Buat pengguna baru
        new_user = User(
            nama_lengkap=nama_lengkap,
            alamat=alamat,
            kontak=kontak,
            jenis_pengguna=jenis_pengguna,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        kontak = request.form['kontak']
        password = request.form['password']
        
        # Cari pengguna berdasarkan kontak
        user = User.query.filter_by(kontak=kontak).first()
        
        # Verifikasi pengguna dan password
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Login gagal. Periksa kontak atau kata sandi Anda.', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/donasi', methods=['GET', 'POST'])
@login_required
def donasi():
    if request.method == 'POST':
        # Handle the donation form data if necessary
        jenis_donasi = request.form['jenis_donasi']
        # You can process the donation here (save to database, send an email, etc.)
        flash(f'Terima kasih atas donasi Anda berupa {jenis_donasi}!', 'success')
        return redirect(url_for('donasi'))

    return render_template('donasi.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah keluar.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
