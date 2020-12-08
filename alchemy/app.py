import os
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, request, redirect, session
from sqlalchemy.schema import *
from sqlalchemy.types import *
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms.fields import *
from wtforms.fields.html5 import *
from wtforms.validators import *
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
from datetime import datetime


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL","postgresql://postgres:password@localhost/flask_db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "9834uoj3493fjkwdfk9h2iowerkjwe")
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# Модели БД
class User(UserMixin, db.Model):
    username = Column(String(20), primary_key=True)
    passwd = Column(String(100))
    authenticated = Column(Boolean, default=False)
    active = Column(Boolean, default=True)

    def __repr__(self):
        return self.username

    def get_id(self):
        return self.username

    @property
    def is_autenticated(self):
        return self.authenticated

    @property
    def is_active(self):
        return self.active

    @property
    def is_anonymous(self):
        return False

class Message(db.Model):
    id = Column(Integer, primary_key=True)
    date_start = Column(DateTime, nullable=False)
    date_stop = Column(DateTime, nullable=False)
    author = Column(String(20), nullable=False)
    subj = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)

    def __repr__(self):
        return f"<message {self.id}>"

db.create_all()

@login_manager.user_loader
def load_user(username):
    return User.query.get(username)


# Формы и валидации
class RegisterForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired()])
    passwd = PasswordField("Пароль", validators=[DataRequired(), Length(min=3, message="Минимальная длинна пароля - %(min)d")])
    passwd2 = PasswordField("Повтор пароля", validators=[DataRequired(), EqualTo("passwd", message="Пароли должны быть одинаковыми")])
    submit = SubmitField(label=("Регистрация"))

class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired()])
    passwd = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField(label=("Войти"))

class MessageForm(FlaskForm):
    id = HiddenField("id")
    date_start = DateTimeLocalField("Дата и время начала (пример 2020-12-23 19:37)", format="%Y-%m-%d %H:%M", validators=[DataRequired()])
    date_stop = DateTimeLocalField("Дата и время окончания (пример 2020-12-23 19:37)", format="%Y-%m-%d %H:%M", validators=[DataRequired()])
    subj = StringField("Тема", validators=[DataRequired()])
    description = TextAreaField("Сообщение")
    submit = SubmitField(label=("Сохранить"))



# Роуты

## Обработка ошибки 404
@app.errorhandler(404)
def pageNotFound(error):
    return render_template("err404.html", title="Страница не найдена"), 404

## Регистрация и авторизация
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Форма регистрации нового пользователя
    """
    if not current_user.is_anonymous:
        return redirect(url_for("index"))
    form = RegisterForm()
    if form.validate_on_submit():
        username = request.form.get("username")
        passwd = request.form.get("passwd")
        user = User(username=username, passwd=bcrypt.generate_password_hash(passwd).decode("utf-8"))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("index"))
    return render_template("register.html", title="Регистрация", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Форма входа зарегистрированного пользователя
    """
    error = ""
    if not current_user.is_anonymous:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.passwd, form.passwd.data):
                login_user(user)
                return redirect(url_for("index"))
            else:
                error = "Пароль не верный."
        else:
            error = "Пользователь не зарегистрирован."
    return render_template("login.html", title="Авторизация", form=form, error=error)

@app.route("/logout")
def logout():
    """
    Выход пользователя
    """
    logout_user()
    return redirect(url_for("index"))


## Эндпоинты
@app.route("/")
@login_required
def index():
    """
    Вывод главной страницы со списком сообщений
    """
    messages = db.session.query(Message).all()
    return render_template("index.html", title="Список сообщений", messages=messages)

@app.route("/new_message", methods=["GET", "POST"])
@login_required
def new_message():
    """
    Форма добавления нового сообщения
    """
    form = MessageForm()
    if form.validate_on_submit():
        date_start = request.form.get("date_start")
        date_stop = request.form.get("date_stop")
        author = session["_user_id"]
        subj = request.form.get("subj")
        description = request.form.get("description")
        new_message = Message(
            date_start=date_start,
            date_stop=date_stop,
            author=author,
            subj=subj,
            description=description
        )
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("message.html", title="Новое сообщение", form=form)

@app.route("/edit_message/<int:message_id>", methods=["GET", "POST"])
@login_required
def edit_message(message_id):
    """
    Форма изменения сообщения
    Сохранение формы доступно только владельцу сообщения
    """
    error = ""
    message = db.session.query(Message).filter(Message.id == int(message_id)).first()
    if message:
        form = MessageForm(obj=message)
        if message.author == session["_user_id"]:
            if form.validate_on_submit():
                message.date_start = datetime.strptime(request.form.get("date_start"), "%Y-%m-%d %H:%M")
                message.date_stop = datetime.strptime(request.form.get("date_stop"), "%Y-%m-%d %H:%M")
                message.subj = request.form.get("subj")
                message.description = request.form.get("description")
                db.session.commit()
                return redirect(url_for("index"))
        else:
            error = "Вы можете редактировать только свои сообщения!"
        return render_template("message.html", title="Редактировать сообщение", form=form, error=error, edit=message.id)
    return redirect(url_for("index"))

@app.route("/delete_message/<int:message_id>")
@login_required
def delete_message(message_id):
    """
    Удаление сообщения
    """
    message = db.session.query(Message).filter(Message.id == int(message_id)).first()
    if message:
        if message.author == session["_user_id"]:
            try:
                db.session.delete(message)
                db.session.commit()
            except:
                return redirect(url_for("index"))
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()