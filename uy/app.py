from flask import Flask, render_template, request, redirect, session, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ================= DATABASE CONNECTION =================

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="uy"
)

# ================= HOME ROUTE =================

# serve both root and /login.html for backward compatibility
@app.route("/")
@app.route("/login.html")
def home():
    if "admin" in session:
        return redirect(url_for("admin_dashboard"))
    if "user" in session:
        return redirect(url_for("user_dashboard"))
    # default landing page for unauthenticated visitors is user login
    return redirect(url_for("login"))

# ================= ADMIN REGISTER =================

@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():

    if request.method == "POST":

        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        cursor = db.cursor()

        cursor.execute(
            "INSERT INTO admins(username,password) VALUES(%s,%s)",
            (username, password)
        )

        db.commit()

        return redirect(url_for("admin_login"))

    # admin registration template lives at the project root of the templates directory
    return render_template("admin_register.html")

# ================= ADMIN LOGIN =================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM admins WHERE username=%s",
            (username,)
        )

        admin = cursor.fetchone()

        if admin and check_password_hash(admin["password"], password):
            session["admin"] = admin["username"]
            return redirect(url_for("admin_dashboard"))

        return "Invalid credentials"

    # login template is stored under templates/admin
    return render_template("admin/admin_login.html")

# ================= ADMIN DASHBOARD =================

@app.route("/admin/dashboard")
def admin_dashboard():

    if "admin" not in session:
        return redirect(url_for("admin_login"))

    cursor = db.cursor(dictionary=True)

    # query users as well so the dashboard template can iterate over both
    try:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
    except Exception:
        users = []

    # fetch pending and approved products separately
    cursor.execute("SELECT * FROM products WHERE status='pending'")
    pending = cursor.fetchall()
    cursor.execute("SELECT * FROM products WHERE status='done'")
    done = cursor.fetchall()

    return render_template("admin/admin_dashboard.html", users=users, pending=pending, done=done)

# ================= ADD PRODUCT =================

@app.route("/admin/add_product", methods=["POST"])
def add_product():

    if "admin" not in session:
        return redirect(url_for("admin_login"))

    picture = request.form.get("picture")
    name = request.form.get("name")
    description = request.form.get("description")
    price = request.form.get("price")

    cursor = db.cursor()

    # when admin adds a product it is immediately approved
    cursor.execute(
        "INSERT INTO products(picture,name,description,price,status) VALUES(%s,%s,%s,%s,'done')",
        (picture, name, description, price)
    )

    db.commit()

    return redirect(url_for("admin_dashboard"))

# ================= DELETE PRODUCT =================

@app.route("/admin/delete_product/<int:id>")
def delete_product(id):

    if "admin" not in session:
        return redirect(url_for("admin_login"))

    cursor = db.cursor()

    cursor.execute("DELETE FROM products WHERE id=%s", (id,))
    db.commit()

    return redirect(url_for("admin_dashboard"))

# ================= UPDATE PRODUCT =================

@app.route("/admin/update_product/<int:id>", methods=["GET", "POST"])
def update_product(id):

    if "admin" not in session:
        return redirect(url_for("admin_login"))

    cursor = db.cursor(dictionary=True)

    if request.method == "POST":

        picture = request.form.get("picture")
        name = request.form.get("name")
        description = request.form.get("description")
        price = request.form.get("price")

        cursor.execute(
            "UPDATE products SET picture=%s, name=%s, description=%s, price=%s WHERE id=%s",
            (picture, name, description, price, id)
        )

        db.commit()

        return redirect(url_for("admin_dashboard"))

    cursor.execute("SELECT * FROM products WHERE id=%s", (id,))
    product = cursor.fetchone()

    # the update form lives in the admin subdirectory
    return render_template("admin/update_product.html", product=product)

# ================= ADMIN LOGOUT =================

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

# ================= USER AUTHENTICATION =================

@app.route("/register", methods=["GET", "POST"])
def user_register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))

        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users(name,email,password) VALUES(%s,%s,%s)",
            (name, email, password)
        )
        db.commit()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )
        user = cursor.fetchone()
        if user and check_password_hash(user["password"], password):
            session["user"] = user["id"]
            return redirect(url_for("user_dashboard"))
        return "Invalid credentials"

    return render_template("login.html")


@app.route("/dashboard")
def user_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    cursor = db.cursor(dictionary=True)
    # only show approved products to users
    cursor.execute("SELECT * FROM products WHERE status='done'")
    products = cursor.fetchall()
    return render_template("user_dashboard.html", products=products)


@app.route("/logout")
def user_logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# new user product submission
@app.route("/user/add_product", methods=["POST"])
def user_add_product():
    if "user" not in session:
        return redirect(url_for("login"))

    picture = request.form.get("picture")
    name = request.form.get("name")
    description = request.form.get("description")
    price = request.form.get("price")

    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO products(picture,name,description,price,status) VALUES(%s,%s,%s,%s,'pending')",
        (picture, name, description, price)
    )
    db.commit()
    return redirect(url_for("user_dashboard"))


@app.route("/admin/verify_product/<int:id>")
def verify_product(id):
    if "admin" not in session:
        return redirect(url_for("admin_login"))
    cursor = db.cursor()
    cursor.execute("UPDATE products SET status='done' WHERE id=%s", (id,))
    db.commit()
    return redirect(url_for("admin_dashboard"))

# ================= RUN APP =================

if __name__ == "__main__":
    app.run(debug=True)


