
from utils import allowed_file, UPLOAD_FOLDER
from sqlalchemy import or_, func, and_
from flask import Flask, redirect, url_for, session, request, render_template, flash, jsonify, abort
from sqlalchemy.exc import IntegrityError
from dateutil.relativedelta import relativedelta

from datetime import timedelta  # timedelta теперь из datetime
from flask_login import LoginManager, login_user, logout_user, current_user

from flask_migrate import Migrate
from models import db, User, Item, Payment, License, Investor
from config import Config
from datetime import datetime, date, timezone, timedelta

from utils import get_static_files
from werkzeug.utils import secure_filename
from flask import send_file, flash, redirect, url_for, request, current_app
from flask_login import login_required
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
from authlib.integrations.flask_client import OAuth
from flask import session
import secrets
import locale
from dotenv import load_dotenv

app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

locale.setlocale(locale.LC_TIME,'Russian_Russia.1251')

load_dotenv()
db.init_app(app)
migrate = Migrate(app, db)



login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
oauth = OAuth(app)
# OAuth
oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url=app.config["GOOGLE_DISCOVERY_URL"],
    client_kwargs={
        'scope': 'openid email profile'
    }
)


# Для локальной разработки (разрешить http)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'



# НАСТРОЙКА: политика "до какого дня платить за месяц"
# Варианты:
# 1 — "end_of_month" — до конца месяца (31.07.2025)
# 2 — фиксированный день месяца — например, 15 => до 15 числа месяца (15.07.2025)
# 3 — N дней после даты ожидания — например, 10 дней

PAYMENT_POLICY = {
    "mode": "end_of_month",  # "end_of_month" | "fixed_day" | "grace_days"
    "fixed_day": 15,         # если mode = "fixed_day"
    "grace_days": 10         # если mode = "grace_days"
}



def get_due_date(expected_date):
    """
    expected_date — дата, когда наступил ожидаемый платёжный месяц
    возвращает крайнюю дату оплаты
    """
    if PAYMENT_POLICY["mode"] == "end_of_month":
        # Конец месяца
        next_month = expected_date + relativedelta(months=1)
        due_date = next_month.replace(day=1) - timedelta(days=1)
        return due_date

    elif PAYMENT_POLICY["mode"] == "fixed_day":
        # Фиксированный день месяца (например, до 15 числа месяца)
        next_month = expected_date + relativedelta(months=1)
        due_day = PAYMENT_POLICY["fixed_day"]
        try:
            due_date = next_month.replace(day=due_day)
        except ValueError:
            # Если в месяце нет такого дня (например, 30 февраля), берём последний день месяца
            next_month = next_month + relativedelta(months=1)
            due_date = next_month.replace(day=1) - timedelta(days=1)
        return due_date

    elif PAYMENT_POLICY["mode"] == "grace_days":
        # N дней после ожидаемой даты
        grace_days = PAYMENT_POLICY["grace_days"]
        due_date = expected_date + timedelta(days=grace_days)
        return due_date

    else:
        # По умолчанию — конец месяца
        next_month = expected_date + relativedelta(months=1)
        due_date = next_month.replace(day=1) - timedelta(days=1)
        return due_date



# Для локальной разработки (разрешить http)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))






# Главная страница
@app.route("/")
def home():
    return render_template("home.html")




@app.route("/login")
def login():
    # Генерируем уникальные state и nonce для каждой сессии
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Сохраняем в сессии с временной меткой (используем timezone-aware datetime)
    session['oauth_state'] = {
        'value': state,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    session['nonce'] = nonce
    session['next_url'] = request.args.get('next')  # Сохраняем next URL из запроса

    # Формируем redirect_uri с явным указанием протокола
    redirect_uri = url_for('auth_callback', _external=True)

    return oauth.google.authorize_redirect(
        redirect_uri,
        state=state,
        nonce=nonce,
        prompt="select_account",
        include_granted_scopes="true",
        access_type="offline"
    )

@app.route("/auth/callback")
def auth_callback():
    if 'state' not in request.args:
        return "Missing state parameter", 400

    saved_state = session.pop('oauth_state', None)
    if not saved_state:
        return "Session expired or invalid state", 400

    state_created = datetime.fromisoformat(saved_state['created_at'])
    if datetime.now(timezone.utc) - state_created > timedelta(minutes=10):
        return "State expired", 400

    if request.args['state'] != saved_state['value']:
        return "Invalid state parameter", 400

    nonce = session.pop('nonce', None)
    if not nonce:
        return "Nonce missing", 400

    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        if not user_info or 'email' not in user_info:
            return "Failed to retrieve user info", 400

        email = user_info.get("email", "").lower()
        user = User.query.filter_by(email=email).first()

        if not user:
            # Пользователь не найден → не пускаем
            return render_template("license_required.html")

        # Пользователь найден → логиним
        login_user(user, remember=True)

        # Редиректим
        return redirect(session.pop("next_url", None) or url_for("dashboard"))

    except Exception as e:
        app.logger.error(f"OAuth error: {str(e)}", exc_info=True)
        return "Authentication failed", 400



# 🔒 Страница "Лицензия требуется"
@app.route("/license-required")
def license_required_page():
    return render_template("license_required.html")



# 🔓 Выход
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/admin/users")
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)

    search_query = request.args.get("search")  # Получаем поисковый запрос
    if search_query:
        # Фильтруем пользователей по email (регистронезависимый поиск)
        users = User.query.filter(User.email.ilike(f"%{search_query}%")).all()
    else:
        users = User.query.all()  # Если поиск пустой — выводим всех

    return render_template("admin_users.html", users=users)

@app.route("/admin/add_user", methods=["POST"])
@login_required
def add_user_by_email():
    if not current_user.is_admin:
        abort(403)

    email = request.form.get("email", "").strip().lower()
    if not email:
        return redirect(url_for("admin_users"))

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, is_admin=False)
        db.session.add(user)
        db.session.flush()  # user.id

    # Выдать лицензию на 1 год
    license = License(
        user_id=user.id,
        activated_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        is_active=True,
        activated_by=current_user.id
    )
    db.session.add(license)
    db.session.commit()

    flash("Пользователь добавлен и лицензия выдана", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/toggle_admin/<int:user_id>", methods=["POST"])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    return redirect(url_for("admin_users"))
@app.route("/admin/activate_license/<int:user_id>", methods=["POST"])
@login_required
def activate_license(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    expiration_str = request.form.get("expiration", "").strip()

    if not expiration_str:
        flash("Дата окончания обязательна", "danger")
        return redirect(url_for("admin_users"))

    try:
        expiration_date = datetime.strptime(expiration_str, "%d.%m.%Y")
    except ValueError:
        flash("Неверный формат даты. Используйте дд.мм.гггг", "danger")
        return redirect(url_for("admin_users"))

    # Деактивируем все предыдущие лицензии пользователя
    for license in user.licenses:
        license.is_active = False

    # Создаём новую лицензию
    new_license = License(
        user_id=user.id,
        activated_at=datetime.utcnow(),
        expires_at=expiration_date,
        is_active=True,
        activated_by=current_user.id
    )
    db.session.add(new_license)
    db.session.commit()

    flash(f"Новая лицензия активирована до {expiration_date.strftime('%d.%m.%Y')}", "success")
    return redirect(url_for("admin_users"))

#Страница истории лицензий пользователя
@app.route("/admin/user/<int:user_id>/licenses")
@login_required
def user_license_history(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    licenses = License.query.filter_by(user_id=user.id).order_by(License.activated_at.desc()).all()
    return render_template("license_history.html", user=user, licenses=licenses)

#Роут для деактивации лицензии вручную
@app.route("/admin/deactivate_license/<int:license_id>", methods=["POST"])
@login_required
def deactivate_license(license_id):
    if not current_user.is_admin:
        abort(403)

    license = License.query.get_or_404(license_id)
    license.is_active = False
    db.session.commit()

    flash("Лицензия деактивирована", "warning")
    return redirect(url_for("user_license_history", user_id=license.user_id))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.email == current_user.email:
        # Защита от удаления себя
        return redirect(url_for("admin_users"))

    if user.items or user.licenses:  # 👈 проверяем связи
        flash("Невозможно удалить пользователя — есть связанные данные.", "danger")
        return redirect(url_for("admin_users"))

    db.session.delete(user)
    db.session.commit()
    flash("Пользователь удалён", "success")
    return redirect(url_for("admin_users"))




@app.route('/service-worker.js')
def service_worker():
    from flask import Response
    cached_files = get_static_files()
    content = render_template('service-worker.js.j2', cached_files=cached_files)
    return Response(content, mimetype='application/javascript')

@app.after_request
def add_headers(response):
    if request.path == '/service-worker.js':
        response.headers['Cache-Control'] = 'no-cache'
    return response


#форматирование суммы руб
def format_rubles(value):
    try:
        value = float(value)
        formatted = "{:,.2f}".format(value).replace(",", " ").replace(".", ",")
        return f"{formatted} ₽"
    except (ValueError, TypeError):
        return value

# Регистрируем фильтр в Jinja
app.jinja_env.filters['rub'] = format_rubles


@app.route('/item/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    investors = Investor.query.all()
    if not (current_user.is_admin or item.user_id == current_user.id):
        abort(403)



    if request.method == 'POST':
        item.name = request.form['name']
        item.price = request.form['price']
        item.purchase_price = request.form['purchase_price']
        item.installments = request.form['installments']
        item.client_name = request.form['client_name']
        item.client_phone = request.form['client_phone']
        item.guarantor_name = request.form['guarantor_name']
        item.guarantor_phone = request.form['guarantor_phone']
        item.user_id = current_user.id
        item.investor_id = request.form.get('investor_id') or None
        # Удаление фото
        if 'delete_photo' in request.form and item.photo_url:
            photo_path = os.path.join(current_app.root_path, 'static', 'uploads', item.photo_url)
            if os.path.exists(photo_path):
                os.remove(photo_path)
            item.photo_url = None

        # Загрузка нового фото
        photo = request.files.get('photo')
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item.photo_url = filename

        db.session.commit()
        flash('Товар обновлён успешно.', 'success')
        return redirect(url_for('contracts'))

    return render_template('edit_item.html', item=item, investors=investors)


@app.route('/item/delete/<int:item_id>', methods=['POST'])
@login_required

def delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    if not (current_user.is_admin or item.user_id == current_user.id):
        flash("Доступ запрещён", "danger")
        return redirect(url_for('contracts'))
    if item.payments:
        flash("⚠️ Удаление невозможно — по договору уже были внесены платежи.", "danger")
        return redirect(url_for('contracts'))

    try:
        db.session.delete(item)
        db.session.commit()
        flash("✅ Договор успешно удалён.", "info")
    except IntegrityError:
        db.session.rollback()
        flash("❌ Ошибка при удалении: договор связан с другими данными.", "danger")

    return redirect(url_for('contracts'))





# Личный кабинет / добавление товара
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():

    if request.method == "POST":

        if not current_user.active_license:
            flash("У вас нет активной лицензии. Оформление невозможно.", "danger")
            return redirect(url_for("dashboard"))

        name = request.form.get("name")
        price = float(request.form.get("price"))
        purchase_price = float(request.form["purchase_price"])
        installments = int(request.form.get("installments"))
        client_name = request.form.get("client_name")
        guarantor_name = request.form.get("guarantor_name")
        client_phone = request.form["client_phone"]
        guarantor_phone = request.form["guarantor_phone"]
        photo = request.files.get("photo")
        photo_url = None
        down_payment_str = request.form.get("down_payment", "0")  # По умолчанию "0"
        down_payment = float(down_payment_str) if down_payment_str else 0.0
        investor_id_raw = request.form.get("investor_id")
        print(f"DEBUG: investor_id from form = '{investor_id_raw}'")

        # Безопасная обработка
        if investor_id_raw and investor_id_raw != 'None':
            try:
                investor_id = int(investor_id_raw)
            except ValueError:
                investor_id = None
        else:
            investor_id = None

        created_at_str = request.form.get("created_at")
        created_at = datetime.strptime(created_at_str, "%Y-%m-%d") if created_at_str else datetime.utcnow()

        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            photo_url = filename

        last_number = db.session.query(
            db.func.max(Item.user_contract_number)
        ).filter_by(user_id=current_user.id).scalar()

        item = Item(
            name=name,
            price=price,
            purchase_price=purchase_price,
            buyer=current_user.email,
            user_id=current_user.id,
            status="Оформлен",
            installments=installments,
            client_name=client_name,
            client_phone=client_phone,
            guarantor_name=guarantor_name,
            guarantor_phone=guarantor_phone,
            photo_url=photo_url,
            down_payment=down_payment,
            created_at=created_at,
            user_contract_number=(last_number or 0) + 1,
            investor_id=investor_id  # уже int или None — ОК!
        )
        db.session.add(item)
        db.session.commit()
        flash("Товар успешно оформлен!", "success")
        # 👇 Редирект на dashboard c выбранным инвестором, чтобы он остался выбран
        return redirect(url_for("dashboard", investor_id=investor_id if investor_id else ""))

    # GET-запрос — тут правильно
    selected_id = request.args.get("investor_id", type=int)

    today = date.today()
    items = Item.query.filter(
        Item.user_id == current_user.id,
        db.func.date(Item.created_at) == today
    ).all()

    license_expiration = current_user.active_license.expires_at if current_user.active_license else None

    investors = Investor.query.filter_by(user_id=current_user.id).all()

    return render_template(
        "dashboard.html",
        items=items,
        current_date=date.today().strftime("%Y-%m-%d"),
        license_expiration=license_expiration,
        investors=investors,
        selected_id=selected_id
    )



@app.route("/autocomplete")
@login_required
def autocomplete():
    query = request.args.get("query", "").strip().lower()

    # Поиск по client_name с учетом user_id
    results = (
        db.session.query(Item.client_name)
        .filter(
            Item.user_id == current_user.id,
            Item.client_name.ilike(f"%{query}%")
        )
        .distinct()
        .limit(10)
        .all()
    )

    # Преобразуем к списку строк
    client_names = [name for (name,) in results]

    return jsonify(client_names)



@app.route("/investors/add", methods=["GET", "POST"])
@login_required
def add_investor():
    if request.method == "POST":
        name = request.form["name"]
        investor = Investor(name=name, user_id=current_user.id)
        db.session.add(investor)
        db.session.commit()
        flash("Инвестор добавлен!", "success")
        return redirect(url_for("dashboard"))
    investors = Investor.query.filter_by(user_id=current_user.id).all()
    return render_template("add_investor.html", investors=investors)


@app.route("/investors/delete/<int:investor_id>", methods=["POST"])
@login_required
def delete_investor(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    if investor.user_id != current_user.id:
        abort(403)

    # Проверка: есть ли связанные товары
    if investor.items:
        flash("Нельзя удалить инвестора — есть связанные товары.", "danger")
        return redirect(url_for("add_investor"))

    db.session.delete(investor)
    db.session.commit()
    flash("Инвестор удалён.", "info")
    return redirect(url_for("add_investor"))



#кликабельная строка внутри

@app.route("/payments")
@login_required
def payments():
    try:
        selected_id = request.args.get("investor_id", type=int)

        # Получаем список инвесторов пользователя
        investors = Investor.query.filter_by(user_id=current_user.id).all()

        # Базовый фильтр по пользователю
        item_query = Item.query.filter_by(user_id=current_user.id)
        payment_query = Payment.query.join(Item, Payment.item_id == Item.id).filter(
            Payment.user_id == current_user.id,
            Item.user_id == current_user.id
        )

        # 🔽 Если выбран инвестор — фильтруем
        if selected_id is not None:
            item_query = item_query.filter(Item.investor_id == selected_id)
            payment_query = payment_query.filter(Item.investor_id == selected_id)

        # Выполняем запросы
        items = item_query.all()
        payments = payment_query.all()

        # Отладочные принты (можно потом убрать)
        print(f"DEBUG: selected_id = {selected_id}")
        print(f"DEBUG: items count = {len(items)}")
        print(f"DEBUG: payments count = {len(payments)}")
        for item in items:
            print(f"Item id={item.id}, investor_id={item.investor_id}, price={item.price}, purchase_price={item.purchase_price}")
        for payment in payments:
            print(f"Payment id={payment.id}, amount={payment.amount}, item_id={payment.item_id}, item_investor_id={payment.item.investor_id}")

        # Рассчитываем финансовые показатели
        total_invested = sum(item.purchase_price or 0 for item in items)
        total_paid = sum(payment.amount for payment in payments)

        active_items = [item for item in items if item.status == "Оформлен"]

        monthly_profit = sum(
            ((item.price or 0) - (item.purchase_price or 0)) / item.installments
            for item in active_items
            if item.installments and item.price and item.purchase_price
        )

        total_profit = sum(
            (item.price or 0) - (item.purchase_price or 0)
            for item in items
            if item.price and item.purchase_price
        )

        return render_template(
            "payments.html",
            total_invested=round(total_invested, 2),
            total_paid=round(total_paid, 2),
            monthly_profit=round(monthly_profit, 2),
            total_profit=round(total_profit, 2),
            items=items,
            payments=payments,
            investors=investors,
            selected_id=selected_id
        )

    except Exception as e:
        app.logger.error(f"Error in payments route: {str(e)}")
        return f"Ошибка при загрузке данных: {str(e)}", 500


@app.route("/add_payment", methods=["GET", "POST"])
@login_required
def add_payment():

    selected_client = request.args.get("client_name") or request.form.get("client_name")
    items, payments = [], []
    error = None

    all_clients = sorted(
        [
            c[0]
            for c in db.session.query(Item.client_name)
            .filter(Item.user_id == current_user.id)
            .distinct()
            .all()
            if c[0]
        ],
        key=lambda x: str(x).lower()
    )

    if selected_client:
        try:
            exact_client_name = next(
                (
                    name for name in db.session.query(Item.client_name)
                    .filter(Item.user_id == current_user.id)
                    .distinct()
                    .all()
                    if name[0] and name[0].lower() == selected_client.lower()
                ),
                (selected_client,)
            )[0]

            items = Item.query.filter(
                db.func.lower(Item.client_name) == db.func.lower(exact_client_name),
                Item.user_id == current_user.id,
                Item.status == "Оформлен"

            ).all()

            payments = db.session.query(Payment) \
                .join(Item) \
                .filter(
                    db.func.lower(Item.client_name) == db.func.lower(exact_client_name),
                    Item.user_id == current_user.id,

                ) \
                .order_by(Payment.id.desc()) \
                .all()

        except Exception as e:
            error = f"Ошибка при загрузке данных: {str(e)}"
            items, payments = [], []

    if request.method == "POST":
        if not current_user.active_license:
            flash("У вас нет активной лицензии!", "danger")
            return redirect(url_for("add_payment"))
        try:
            item_id = int(request.form.get("item_id"))
            amount = float(request.form.get("amount"))
            created_at_str = request.form.get("created_at")
            created_at = datetime.strptime(created_at_str, "%Y-%m-%d") if created_at_str else datetime.utcnow()

            # Проверка на принадлежность товара пользователю
            item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
            if not item:
                raise Exception("Товар не найден или не принадлежит текущему пользователю")


            payment = Payment(item_id=item_id,  user_id=current_user.id,  amount=amount, created_at=created_at)
            db.session.add(payment)
            db.session.commit()

            total_paid = sum(p.amount for p in item.payments) + amount
            item.status = "Завершен" if total_paid >= item.price else item.status




            flash("Успешно", "success")
            return redirect(url_for("add_payment", client_name=selected_client))

        except Exception as e:
            error = f"Ошибка при сохранении платежа: {str(e)}"
            db.session.rollback()

    return render_template(
        "add_payment.html",

        client_name=selected_client,
        selected_client=selected_client,
        items=items,
        payments=payments,
        all_clients=all_clients,
        current_date=datetime.today().strftime("%Y-%m-%d"),
        error=error,


    )
@app.route("/search_clients")
@login_required
def search_clients():
    term = request.args.get("term", "")
    clients = (
        db.session.query(Item.client_name)
        .filter(Item.client_name.ilike(f"%{term}%"))
        .filter(Item.user_id == current_user.id)
        .distinct()
        .limit(10)
        .all()
    )
    results = [{"label": name[0], "value": name[0]} for name in clients]
    return jsonify(results)




@app.route("/payments/<int:item_id>", methods=["POST"])
@login_required
def make_payment(item_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()

    monthly_payment = item.price / item.months

    if item.payments_made < item.months:
        item.payments_made += 1

        if item.payments_made >= item.months:
            item.status = "paid"

        payment = Payment(item_id=item.id, amount=monthly_payment)
        db.session.add(payment)
        db.session.commit()

    return redirect(url_for("add_payment"))

@app.route("/api/items_by_client/<client_name>")
@login_required
def items_by_client(client_name):
    items = Item.query.filter_by(client_name=client_name, user_id=current_user.id).all()
    items_data = [
        {"id": item.id, "name": item.name, "price": item.price, "status": item.status}
        for item in items
    ]
    return jsonify(items_data)


@app.route("/delete_payment/<int:payment_id>", methods=["POST"])
@login_required
def delete_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    item = payment.item

    # проверяем права
    if item.user_id != current_user.id and not current_user.is_admin:

       abort(403)

    # удаляем платёж
    db.session.delete(payment)

    # пересчитываем статус и количество
    db.session.flush()  # чтобы item.payments «увидел» удаление в этой же сессии
    item.payments_made = len(item.payments)
    if sum(p.amount for p in item.payments) < item.price:
        item.status = "Оформлен"

    db.session.commit()
    flash("Платёж удалён", "danger")

    client_name = request.form.get("client_name") or item.client_name
    return redirect(url_for("add_payment", client_name=client_name))

# Клиенты


@app.route("/clients", methods=["GET", "POST"])
@login_required
def clients():
    search_query = request.form.get("search", "").strip()

    query = db.session.query(Item.client_name).filter(Item.user_id == current_user.id)

    if search_query:
        query = query.filter(Item.client_name.ilike(f"%{search_query}%"))

    client_names = query.distinct().all()

    all_clients_data = []

    for (client_name,) in client_names:
        items = Item.query.filter_by(client_name=client_name, user_id=current_user.id).all()
        client_data = []
        total_debt = 0

        for item in items:
            total_paid = sum(payment.amount for payment in item.payments)
            installment_price = item.price or 0
            remaining = installment_price - total_paid
            total_debt += remaining

            client_data.append({
                "item": item,
                "payments": item.payments,
                "total_paid": total_paid,
                "remaining": remaining
            })

        all_clients_data.append({
            "client_name": client_name,
            "client_data": client_data,
            "total_debt": total_debt
        })

    return render_template(
        "clients.html",
        all_clients_data=all_clients_data,
        search_query=search_query
    )


@app.route("/clients/<client_name>")
@login_required
def client_detail(client_name):
    # Убедимся, что такие товары есть у текущего пользователя
    items = Item.query.filter_by(client_name=client_name, user_id=current_user.id).all()

    if not items:
        abort(403)

    client_data = []
    total_debt = 0

    for item in items:
        total_paid = sum(payment.amount for payment in item.payments)
        installment_price = item.price or 0
        remaining = installment_price - total_paid
        total_debt += remaining

        client_data.append({
            "item": item,
            "payments": item.payments,
            "total_paid": total_paid,
            "remaining": remaining
        })

    return render_template(
        "client_detail.html",
        client_name=client_name,
        client_data=client_data,
        total_debt=total_debt
    )




@app.route("/items/<int:item_id>/payments", methods=["GET", "POST"])
@login_required
def item_payments(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if request.method == "POST":
        if "add_payment" in request.form:

            try:
                amount = float(request.form.get("amount"))
                created_at_str = request.form.get("created_at")
                created_at = datetime.strptime(created_at_str, "%Y-%m-%d") if created_at_str else datetime.utcnow()

                payment = Payment(item_id=item.id, amount=amount, user_id=current_user.id, date=created_at, created_at=created_at)
                db.session.add(payment)
                db.session.commit()

                total_paid = sum(p.amount for p in item.payments)
                item.status = "Завершен" if total_paid >= item.price else "Оформлен"
                db.session.commit()

                flash("Платёж успешно добавлен", "success")
            except Exception as e:
                flash(f"Ошибка при добавлении платежа: {str(e)}", "danger")

        elif "delete_payment_id" in request.form:
            try:
                payment_id = int(request.form.get("delete_payment_id"))
                payment = Payment.query.get_or_404(payment_id)
                if item.user_id != current_user.id and not current_user.is_admin:
                    abort(403)

                db.session.delete(payment)
                db.session.commit()

                total_paid = sum(p.amount for p in item.payments)
                item.status = "Завершен" if total_paid >= item.price else "Оформлен"
                db.session.commit()

                flash("Платёж удалён", "warning")
            except Exception as e:
                flash(f"Ошибка при удалении платежа: {str(e)}", "danger")

        return redirect(url_for("item_payments", item_id=item_id))

        # Измененная строка - сортировка платежей по дате создания в обратном порядке
    payments = Payment.query.filter_by(item_id=item.id).order_by(Payment.created_at.desc()).all()

    total_paid = sum(payment.amount for payment in payments)
    down_payment = item.down_payment or 0
    installment_price = item.price or 0

    remaining = max(installment_price - total_paid - down_payment, 0)
    current_date = datetime.today().strftime("%Y-%m-%d")

    return render_template(
        "item_payments.html",
        item=item,
        payments=payments,
        total_paid=total_paid,
        remaining=remaining,
        current_date=current_date
    )


#pdf экспорт

@app.route("/export_pdf/<int:item_id>")
@login_required
def export_pdf(item_id):
    # Проверка прав доступа
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    # Получение платежей
    payments = Payment.query.filter_by(item_id=item.id)\
                           .order_by(Payment.created_at.asc())\
                           .all()

    # Создание PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=60,
        rightMargin=40,
        topMargin=40,
        bottomMargin=30
    )

    # Регистрация шрифта
    font_path = os.path.join('static', 'fonts', 'DejaVuSans.ttf')
    pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))

    # Получаем базовые стили
    styles = getSampleStyleSheet()

    # Заголовок
    styleH = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        fontName='DejaVuSans',  # заменяем Tahoma → DejaVuSans
        fontSize=16,
        leading=20,
        spaceAfter=10,
        alignment=1  # центрируем
    )

    # Обычный текст
    styleN = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        fontName='DejaVuSans',  # заменяем Tahoma → DejaVuSans
        fontSize=12,
        leading=15,  # межстрочный интервал
        spaceAfter=6  # отступ после параграфа (немного увеличил с 5 → 6 для читаемости)
    )

    # Содержимое документа
    elements = []
    total_paid = sum(p.amount for p in payments)
    installment_price = item.price or 0
    remaining = installment_price - total_paid

    # Заголовок и основная информация
    elements.extend([
        Paragraph("Акт сверки", styleH),
        Spacer(1, 12),
        Paragraph(f"Клиент: {item.client_name}", styleN),
        Spacer(1, 6),
        Paragraph(f"Товар: {item.name}", styleN),
        Spacer(1, 6),
        Paragraph(f"Дата оформления: {item.created_at.strftime('%d.%m.%Y')}", styleN),
        Spacer(1, 6),
        Paragraph(f"Сумма: {format_rubles(item.price)} ", styleN),
        Spacer(1, 6),
        Paragraph(f"Оплачено: {format_rubles(total_paid)} ", styleN),
        Spacer(1, 6),
        Paragraph(f"Остаток: {format_rubles(remaining)} ", styleN),
        Spacer(1, 6),
        Paragraph(f"Срок рассрочки: {item.installments} мес.", styleN),
        Spacer(1, 6),
        Paragraph(f"Ежемесячный платёж: {round((item.price - item.down_payment) / item.installments)} ₽", styleN),
        Spacer(1, 6),
        Spacer(1, 12)
    ])

    # Таблица платежей
    data = [['№', 'Дата', 'Сумма']]
    for i, p in enumerate(payments, 1):
        data.append([
            str(i),
            p.created_at.strftime('%d.%m.%Y'),
            format_rubles(p.amount)
        ])
    table = Table(data, colWidths=[30, 100, 100], hAlign='LEFT')
    table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'DejaVuSans'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a90e2')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(table)

    # Генерация PDF
    doc.build(elements)
    buffer.seek(0)

    # Отправка файла
    pdf_filename = f"{item.client_name}_акт_сверки.pdf"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=pdf_filename,
        mimetype='application/pdf'
    )

import re

@app.route('/whatsapp_link/<int:item_id>')
@login_required
def whatsapp_link(item_id):


    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if not item.client_phone:
        flash("У клиента не указан номер телефона.", "danger")
        return redirect(url_for('clients'))

    # Очищаем телефон до цифр
    digits = re.sub(r'\D', '', item.client_phone)

    # Заменяем первую 8 на 7 (если пользователь ввёл российский номер с 8)
    if digits.startswith('8'):
        digits = '7' + digits[1:]

    # Если не начинается с 7, добавляем
    if not digits.startswith('7'):
        digits = '7' + digits

    # Генерируем ссылку
    link = f"https://wa.me/{digits}?text=Здравствуйте, вот ваша история платежей: {request.url_root}static/pdfs/{item.client_name}_payments.pdf"

    return redirect(link)




# Все оформленные
@app.route("/contracts")
@login_required
def contracts():
    search_query = request.args.get("q", "").strip()
    created_date_str = request.args.get("created_date", "").strip()

    query = Item.query

    # Фильтрация по текущему пользователю, если не админ
    if not current_user.is_admin:
        query = query.filter(Item.user_id == current_user.id)

    # Поиск по имени клиента, названию товара или имени поручителя
    if search_query:
        query = query.filter(
            or_(
                Item.client_name.ilike(f"%{search_query}%"),
                Item.name.ilike(f"%{search_query}%"),
                Item.guarantor_name.ilike(f"%{search_query}%")
            )
        )

    # Фильтрация по дате оформления
    if created_date_str:
        try:
            created_date = datetime.strptime(created_date_str, "%Y-%m-%d").date()
            query = query.filter(db.func.date(Item.created_at) == created_date)
        except ValueError:
            flash("Неверный формат даты. Используйте ГГГГ-ММ-ДД.", "danger")

    # Сортировка:
    # - Для админа: сначала новые по дате
    # - Для обычного пользователя: по его номеру договора (user_contract_number), убывание

    query = Item.query

    if not current_user.is_admin:
        query = query.filter(Item.user_id == current_user.id)  # Только свои записи

    items = query.order_by(Item.created_at.desc()).all()  # Общая сортировка для всех
    return render_template(
        "contracts.html",
        items=items,
        search_query=search_query,
        current_date=datetime.today().strftime('%Y-%m-%d')
    )








# Просроченные
@app.route("/overdue")
@login_required
def overdue():
    today = datetime.now().date()
    overdue_items = []

    # Берем только оформленные договоры
    query = Item.query.filter_by(status="Оформлен")

    # Для обычного пользователя — только свои договоры
    if not current_user.is_admin:
        query = query.filter(Item.user_id == current_user.id)

    items = query.all()

    overdue_count = 0  # Инициализируем счетчик

    for item in items:
        # Используем installments, а не months
        if not item.created_at or not item.installments:
            continue

        start_date = item.created_at.date()
        months_total = item.installments

        # Ожидаемые даты платежей — начиная со второго месяца!
        expected_dates = [start_date + relativedelta(months=i + 1) for i in range(months_total)]

        # Берем все платежи по этому item
        payments = Payment.query.filter_by(item_id=item.id).all()

        # Какие месяцы уже оплачены — по полю "date"
        paid_months = set((p.date.year, p.date.month) for p in payments if p.date)

        # Какие платежи пропущены
        past_due_dates = [d for d in expected_dates if d < today]

        missed = []
        for d in past_due_dates:
            if (d.year, d.month) not in paid_months:
                missed.append(d)

        # Если есть пропущенные платежи — добавляем item в список
        if missed:
            item.missed_months = missed
            item.total_months = months_total
            item.payments_made = len(paid_months)
            item.overdue_months = len(missed)
            overdue_items.append(item)
            item.monthly_payment = round((item.price - item.down_payment) / item.installments)
            overdue_count += 1  # Увеличиваем счетчик

    return render_template("overdue.html", items=overdue_items, overdue_count=overdue_count)

@app.context_processor
def inject_overdue_count():
    if current_user.is_authenticated:
        today = datetime.now().date()

        query = Item.query.filter_by(status="Оформлен")
        if not current_user.is_admin:
            query = query.filter(Item.user_id == current_user.id)

        items = query.all()

        overdue_count = 0

        for item in items:
            if not item.created_at or not item.installments:
                continue

            start_date = item.created_at.date()
            months_total = item.installments

            expected_dates = [start_date + relativedelta(months=i+1) for i in range(months_total)]
            past_due_dates = [d for d in expected_dates if d < today]

            payments = Payment.query.filter_by(item_id=item.id).all()
            paid_months = set((p.date.year, p.date.month) for p in payments if p.date)

            missed = []
            for d in past_due_dates:
                if (d.year, d.month) not in paid_months:
                    missed.append(d)

            if missed:
                overdue_count += 1

        return dict(overdue_count=overdue_count)
    else:
        # Если пользователь не авторизован — показываем 0
        return dict(overdue_count=0)



# Запуск сервера
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8080)


