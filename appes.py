import os
import sqlite3
from functools import wraps
import pytesseract
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, json
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import http.client

SECRET_KEY = '34i*u5$gy38H74@r8Ted9s^df'
DATABASE = 'database.db'
DEBUG = True

app = Flask(__name__)

app.config.from_object(__name__)
app.config.update(dict(DATABASE=os.path.join(app.root_path, 'database.db')))
login_manager = LoginManager()
login_manager.init_app(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB
UPLOADED_IMAGE_NAME = 'uploaded_image.jpg'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def connect_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


# Вспомогательная функция для создания таблиц БД
def create_db():
    db = connect_db()
    with app.open_resource('sq_db.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()


# Соединение с БД, если оно еще не установлено
def get_db():
    if not hasattr(g, 'link_db'):
        g.link_db = connect_db()
    return g.link_db


# Закрываем соединение с БД, если оно было установлено
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'link_db'):
        g.link_db.close()


# Главная страница
@app.route('/')
def index():
    return render_template("Index.html")


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Проверка длины имени пользователя
        if len(username) < 6:
            flash('Имя пользователя должно содержать не менее 6 символов', category='error')
            return render_template('register.html')

        # Проверка требований к паролю
        if len(password) < 8:
            flash('Пароль должен содержать не менее 8 символов', category='error')
            return render_template('register.html')

        if not any(char.isupper() for char in password):
            flash('Пароль должен содержать хотя бы одну заглавную букву', category='error')
            return render_template('register.html')

        if not any(char.isdigit() for char in password):
            flash('Пароль должен содержать хотя бы одну цифру', category='error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Пароли не совпадают', category='error')
            return render_template('register.html')

        db = get_db()
        try:
            # Хешируем пароль
            hashed_password = generate_password_hash(password)

            # Вставляем нового пользователя в базу данных
            db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (username, hashed_password))
            db.commit()
            flash('Регистрация прошла успешно', category='success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя пользователя уже занято', category='error')
            return render_template('register.html')

    return render_template('register.html')


class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

    def __repr__(self):
        return f'<User {self.username}>'


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('index'))
        return func(*args, **kwargs)

    return decorated_view


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        if action == 'delete':
            db.execute("DELETE FROM user_history WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            flash('Пользователь и его история успешно удалены', 'success')
        elif action == 'create':
            username = request.form.get('username')
            password = request.form.get('password')
            is_admin = request.form.get('is_admin', 0)

            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                       (username, hashed_password, is_admin))
            db.commit()
            flash('Пользователь успешно создан', 'success')

        users = db.execute("SELECT * FROM users").fetchall()

    return render_template('admin.html', users=users)


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        return User(user['id'], user['username'], user['is_admin'])
    return None


# Вход пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Неверные учетные данные', category='error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    is_admin = current_user.is_admin
    return render_template("profile.html", is_admin=is_admin)


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()

    if user and check_password_hash(user['password'], current_password):
        # Проверка требований к новому паролю
        if len(new_password) < 8:
            flash('Пароль должен содержать не менее 8 символов', category='error')
        elif not any(char.isupper() for char in new_password):
            flash('Пароль должен содержать хотя бы одну заглавную букву', category='error')
        elif not any(char.isdigit() for char in new_password):
            flash('Пароль должен содержать хотя бы одну цифру', category='error')
        elif new_password == confirm_password:
            hashed_password = generate_password_hash(new_password)
            db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, current_user.id))
            db.commit()
            flash('Пароль успешно изменен', category='success')
        else:
            flash('Новые пароли не совпадают', category='error')
    else:
        flash('Неверный текущий пароль', category='error')

    return redirect(url_for('profile'))


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        db = get_db()
        db.execute("DELETE FROM user_history WHERE user_id = ?", (current_user.id,))
        db.execute("DELETE FROM users WHERE id = ?", (current_user.id,))
        db.commit()
        logout_user()
        return redirect(url_for('index'))

    return render_template('delete_account.html')


# редирект с ошибки
@app.errorhandler(404)
def pageNotFount(error):
    return render_template('page404.html'), 404


# редирект с ошибки
@app.errorhandler(401)
def Unauthorized(error):
    return render_template('login.html'), 401


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/tesseract', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Проверка размера файла
        if request.content_length > app.config['MAX_CONTENT_LENGTH']:
            flash('Размер файла превышает ограничение 20 МБ', 'error')
            return redirect(url_for('upload_file'))

        # Получение загруженного файла
        file = request.files['file']

        # Проверка наличия файла и его типа
        if file and allowed_file(file.filename):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], UPLOADED_IMAGE_NAME)

            # Сохранение файла на сервере
            file.save(file_path)

            # Загрузка изображения с использованием PIL
            image = Image.open(file_path)

            # Преобразование изображения в черно-белый формат
            bw_image = image.convert('L')
            bw_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'bw_' + UPLOADED_IMAGE_NAME)
            bw_image.save(bw_file_path)

            # Извлечение текста с помощью pytesseract
            extracted_text = pytesseract.image_to_string(bw_image, lang=request.form.get('language'))

            # Сохранение истории запроса для авторизованного пользователя
            if current_user.is_authenticated:
                db = get_db()
                db.execute("INSERT INTO user_history (user_id, extracted_text) VALUES (?, ?)",
                           (current_user.id, extracted_text))
                db.commit()

            # Передача извлеченного текста и пути к изображению на страницу
            return render_template('tesseract.html', extracted_text=extracted_text,
                                   image_path=os.path.join('/', app.config['UPLOAD_FOLDER'],
                                                           'bw_' + UPLOADED_IMAGE_NAME))

        else:
            flash('Пожалуйста, загрузите изображение в формате PNG, JPG, JPEG или GIF', 'error')
            return redirect(url_for('upload_file'))

    # Если метод запроса GET, отобразить страницу загрузки файла
    return render_template('tesseract.html')


@app.route('/history')
@login_required
def user_history():
    db = get_db()
    history = db.execute(
        "SELECT  extracted_text, timestamp FROM user_history WHERE user_id = ? ORDER BY id DESC LIMIT 10",
        (current_user.id,)).fetchall()
    return render_template('history.html', history=history)


class Bot:
    def __init__(self, api_key, bot_id, base_url="api.coze.com"):
        self.api_key = api_key
        self.bot_id = bot_id
        self.base_url = base_url
        self.conversation_id = None
        self.chat_history = []

    def ask(self, user, query, stream=False):
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Connection': 'keep-alive',
            'Accept': '*/*'
        }

        data = {
            'bot_id': self.bot_id,
            'user': user,
            'query': query,
            'stream': stream,
            'chat_history': self.chat_history
        }

        if self.conversation_id:
            data['conversation_id'] = self.conversation_id

        conn = http.client.HTTPSConnection(self.base_url)
        conn.request("POST", "/open_api/v2/chat", body=json.dumps(data), headers=headers)

        response = conn.getresponse()
        response_data = response.read().decode()

        if response.status == 200:
            response_json = json.loads(response_data)
            self.conversation_id = response_json.get('conversation_id')
            messages = response_json.get('messages', [])
            filtered_messages = []
            for message in messages:
                if message.get('msg_type') == 'generate_answer_finish':
                    print(f"System: {message}")
                elif message.get('content'):
                    filtered_messages.append(message)
                    self.chat_history.append(message)
            return filtered_messages
        else:
            return f"Error: {response.status} - {response_data}"


@app.route('/gpt', methods=['GET', 'POST'])
@login_required
def gpt_chat():
    bot = Bot(api_key="pat_8BIXdKJUqnzXN1vh9CEMLDkh6LZP63cYPxtrd1Duc5TXK7Oqlm7hXSfyTYp2Fr8b",
              bot_id="7376391267590651909")
    user_id = "7376391267590488069"

    if 'chat_history' not in session:
        session['chat_history'] = []

    if request.method == 'POST':
        if 'clear' in request.form:
            session['chat_history'] = []
        else:
            question = request.form['question']
            messages = bot.ask(user_id, question)
            session['chat_history'].extend(messages)

    return render_template('gpt.html', messages=session['chat_history'])
