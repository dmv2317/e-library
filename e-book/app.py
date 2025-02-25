from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/about')
@login_required
def about():
    return render_template('about.html', username=current_user.username)

@app.route('/my-library')
@login_required
def my_library():
    return render_template('my-library.html', username=current_user.username)

@app.route('/feedback')
@login_required
def feedback():
    return render_template('feedback.html', username=current_user.username)

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html', username=current_user.username)

@app.route('/biographies')
@login_required
def biographies():
    return render_template('biographies.html', username=current_user.username)

@app.route('/fantasy')
@login_required
def fantasy():
    return render_template('fantasy.html', username=current_user.username)

@app.route('/fiction')
@login_required
def fiction():
    return render_template('fiction.html', username=current_user.username)

@app.route('/history')
@login_required
def history():
    return render_template('history.html', username=current_user.username)

@app.route('/science')
@login_required
def science():
    return render_template('science.html', username=current_user.username)

@app.route('/mystery')
@login_required
def mystery():
    return render_template('mystery.html', username=current_user.username)

@app.route('/technology')
@login_required
def technology():
    return render_template('technology.html', username=current_user.username)

@app.route('/eduvault')
@login_required
def eduvault():
    return render_template('eduvault.html', username=current_user.username)

@app.route('/comics')
@login_required
def comics():
    return render_template('comics.html', username=current_user.username)

@app.route('/like/<int:book_id>', methods=['POST'])
@login_required
def like_book(book_id):
    book = Book.query.get_or_404(book_id)
    book.likes += 1
    db.session.commit()
    return jsonify({"message": "Book liked!", "likes": book.likes})

@app.route('/dislike/<int:book_id>', methods=['POST'])
@login_required
def dislike_book(book_id):
    book = Book.query.get_or_404(book_id)
    book.dislikes += 1
    db.session.commit()
    return jsonify({"message": "Book disliked!", "dislikes": book.dislikes})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)