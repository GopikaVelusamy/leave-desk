from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import psycopg2
import psycopg2.extras
import re
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

# -----------------------------------------
# DATABASE CONNECTION STRING
# Set your PostgreSQL URL in environment variable DATABASE_URL
# Format: postgresql://username:password@host:port/dbname
# On Render: set DATABASE_URL in your environment variables
# -----------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/leave_portal")

# Render sometimes gives 'postgres://' URLs — psycopg2 needs 'postgresql://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


# -----------------------------------------
# DATABASE SETUP
# -----------------------------------------
def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            employee_id TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            department TEXT DEFAULT '',
            designation TEXT DEFAULT '',
            role TEXT NOT NULL,
            casual_leave INTEGER DEFAULT 6,
            sick_leave INTEGER DEFAULT 6,
            annual_leave INTEGER DEFAULT 12,
            is_active INTEGER DEFAULT 1,
            must_change_password INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS leave_requests (
            id SERIAL PRIMARY KEY,
            employee_id INTEGER NOT NULL,
            leave_type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            total_days INTEGER DEFAULT 0,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            manager_comment TEXT DEFAULT '',
            decision_date TEXT DEFAULT '',
            submitted_on TEXT NOT NULL,
            approved_by INTEGER,
            approval_level TEXT,
            FOREIGN KEY(employee_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------------------
# DATABASE CONNECTION
# -----------------------------------------
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


# -----------------------------------------
# HOME PAGE
# -----------------------------------------
@app.route("/")
def home():
    return render_template("home.html")


# -----------------------------------------
# SIGNUP
# -----------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        full_name = request.form["full_name"]
        employee_id = (request.form["employee_id"].strip().upper())
        email = request.form["email"].strip()
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):

            flash(
                "Please enter a valid email address.",
                "error"
            )

            return redirect(
                url_for("signup")
            )
        password = request.form["password"]
        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return redirect(url_for("signup"))

        if not re.search(r"[A-Z]", password):
            flash(
                "Password must contain at least one uppercase letter.",
                "error"
            )
            return redirect(url_for("signup"))

        if not re.search(r"[a-z]", password):
            flash(
                "Password must contain at least one lowercase letter.",
                "error"
            )
            return redirect(url_for("signup"))

        if not re.search(r"\d", password):
            flash(
                "Password must contain at least one number.",
                "error"
            )
            return redirect(url_for("signup"))

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash(
                "Password must contain at least one special character.",
                "error"
            )
            return redirect(url_for("signup"))
        role = "employee"
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("signup")
            )
        hashed_password = generate_password_hash(password)

        conn = get_db()
        c = conn.cursor()

        try:
            c.execute(
                """
                INSERT INTO users
                (employee_id, password, full_name, email, role)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (employee_id, hashed_password, full_name, email, role)
            )

            conn.commit()

            flash("Account created successfully!", "success")

            return redirect(url_for("login"))

        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Employee ID already exists!", "error")

        finally:
            conn.close()

    return render_template("signup.html")


# -----------------------------------------
# LOGIN
# -----------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        employee_id = (request.form["employee_id"].strip().upper())
        password = request.form["password"]

        conn = get_db()
        c = conn.cursor()

        c.execute(
            """
            SELECT * FROM users
            WHERE employee_id=%s
            """,
            (employee_id,)
        )
        user = c.fetchone()

        if user and user["is_active"] == 0:
            conn.close()
            flash(
                "Account has been deactivated.",
                "error"
            )
            return redirect(url_for("login"))
        conn.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["employee_id"] = user["employee_id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            if user["must_change_password"]:

                flash(
                    "Please change your password before continuing.",
                    "error"
                )

                return redirect(
                    url_for("change_password")
                )

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            elif user["role"] == "manager":
                return redirect(url_for("manager_dashboard"))

            else:
                return redirect(url_for("employee_dashboard"))

        else:
            flash("Invalid Employee ID or Password!", "error")

    return render_template("login.html")

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (session["user_id"],)
    )
    user = c.fetchone()

    c.execute(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status='Approved' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN status='Pending' THEN 1 ELSE 0 END) as pending
        FROM leave_requests
        WHERE employee_id=%s
        """,
        (session["user_id"],)
    )
    stats = c.fetchone()

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        stats=stats
    )


# -----------------------------------------
# EDIT PROFILE
# -----------------------------------------
@app.route(
    "/edit_profile",
    methods=["GET", "POST"]
)
def edit_profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":

        email = request.form["email"].strip()
        phone = request.form["phone"].strip()

        department = request.form.get(
            "department",
            ""
        ).strip()

        designation = request.form.get(
            "designation",
            ""
        ).strip()

        # -----------------------------------------
        # EMAIL VALIDATION
        # -----------------------------------------
        if not re.match(
            r"^[^@]+@[^@]+\.[^@]+$",
            email
        ):

            flash(
                "Please enter a valid email address.",
                "error"
            )

            conn.close()

            return redirect(
                url_for("edit_profile")
            )

        # -----------------------------------------
        # PHONE VALIDATION (OPTIONAL)
        # -----------------------------------------
        if phone:

            if not re.fullmatch(
                r"\d{10}",
                phone
            ):

                flash(
                    "Phone number must contain exactly 10 digits.",
                    "error"
                )

                conn.close()

                return redirect(
                    url_for("edit_profile")
                )

        # -----------------------------------------
        # UPDATE PROFILE
        # -----------------------------------------
        c.execute(
            """
            UPDATE users
            SET
                email=%s,
                phone=%s
            WHERE id=%s
            """,
            (
                email,
                phone,
                session["user_id"]
            )
        )

        conn.commit()

        flash(
            "Profile updated successfully.",
            "success"
        )

        conn.close()

        return redirect(
            url_for("edit_profile")
        )

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (session["user_id"],)
    )
    user = c.fetchone()

    conn.close()

    return render_template(
        "edit_profile.html",
        user=user
    )


# -----------------------------------------
# CHANGE PASSWORD
# -----------------------------------------
@app.route("/change_password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] not in [
        "employee",
        "manager",
        "admin"
    ]:
        return redirect(url_for("login"))

    if request.method == "POST":

        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        conn = get_db()
        c = conn.cursor()

        c.execute(
            """
            SELECT *
            FROM users
            WHERE id=%s
            """,
            (session["user_id"],)
        )
        user = c.fetchone()

        if not check_password_hash(
            user["password"],
            current_password
        ):

            flash(
                "Current password is incorrect.",
                "error"
            )

            conn.close()

            return redirect(
                url_for("change_password")
            )

        if check_password_hash(
            user["password"],
            new_password
        ):

            flash(
                "New password cannot be the same as the current password.",
                "error"
            )

            conn.close()

            return redirect(
                url_for("change_password")
            )
        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            conn.close()

            return redirect(
                url_for("change_password")
            )

        if len(new_password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            conn.close()
            return redirect(
                url_for("change_password")
            )

        if not re.search(r"[A-Z]", new_password):
            flash(
                "Password must contain one uppercase letter.",
                "error"
            )
            conn.close()
            return redirect(
                url_for("change_password")
            )

        if not re.search(r"[a-z]", new_password):
            flash(
                "Password must contain one lowercase letter.",
                "error"
            )
            conn.close()
            return redirect(
                url_for("change_password")
            )

        if not re.search(r"\d", new_password):
            flash(
                "Password must contain one number.",
                "error"
            )
            conn.close()
            return redirect(
                url_for("change_password")
            )

        if not re.search(
            r"[!@#$%^&*(),.?\":{}|<>]",
            new_password
        ):
            flash(
                "Password must contain one special character.",
                "error"
            )
            conn.close()
            return redirect(
                url_for("change_password")
            )

        c.execute(
            """
            UPDATE users
            SET password=%s,
                must_change_password=0
            WHERE id=%s
            """,
            (
                generate_password_hash(
                    new_password
                ),
                session["user_id"]
            )
        )

        conn.commit()
        conn.close()

        flash(
            "Password changed successfully.",
            "success"
        )

        return redirect(
            url_for("profile")
        )

    return render_template(
        "change_password.html"
    )


# -----------------------------------------
# FORGOT PASSWORD
# -----------------------------------------
@app.route(
    "/forgot_password",
    methods=["GET"]
)
def forgot_password():

    return render_template(
        "forgot_password.html"
    )


@app.route("/reset_user_password/<int:user_id>")
def reset_user_password(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    temp_password = "Temp@123"

    c.execute(
        """
        UPDATE users
        SET
            password=%s,
            must_change_password=1
        WHERE id=%s
        """,
        (
            generate_password_hash(
                temp_password
            ),
            user_id
        )
    )

    conn.commit()
    conn.close()

    flash(
        "Password reset successfully. Temporary password: Temp@123",
        "success"
    )

    return redirect(
        url_for("admin_dashboard")
    )


# -----------------------------------------
# LOGOUT
# -----------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# -----------------------------------------
# EMPLOYEE DASHBOARD
# -----------------------------------------
@app.route("/employee")
def employee_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "employee":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (session["user_id"],)
    )
    user = c.fetchone()

    c.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status='Pending' THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN status='Approved' THEN 1 ELSE 0 END) AS approved,
            SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END) AS rejected
        FROM leave_requests
        WHERE employee_id=%s
        """,
        (session["user_id"],)
    )
    stats = c.fetchone()

    conn.close()

    return render_template(
        "employee_dashboard.html",
        user=user,
        stats=stats
    )


@app.route("/apply_leave")
def apply_leave():

    if "user_id" not in session:
        return redirect(url_for("login"))

    today = date.today()

    max_date = (
        today + timedelta(days=180)
    ).strftime("%Y-%m-%d")

    today = today.strftime("%Y-%m-%d")

    return render_template(
        "apply_leave.html",
        today=today,
        max_date=max_date
    )


@app.route("/my_requests")
def my_requests():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM leave_requests
        WHERE employee_id=%s
        ORDER BY submitted_on DESC
        """,
        (session["user_id"],)
    )
    requests = c.fetchall()

    conn.close()

    return render_template(
        "my_requests.html",
        requests=requests
    )


# -----------------------------------------
# LEAVE STATISTICS
# -----------------------------------------
@app.route("/leave_statistics")
def leave_statistics():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT

            COUNT(*) total,

            SUM(
                CASE
                WHEN status='Approved'
                THEN 1
                ELSE 0
                END
            ) approved,

            SUM(
                CASE
                WHEN status='Rejected'
                THEN 1
                ELSE 0
                END
            ) rejected,

            SUM(
                CASE
                WHEN status='Pending'
                THEN 1
                ELSE 0
                END
            ) pending

        FROM leave_requests

        WHERE employee_id=%s
        """,
        (session["user_id"],)
    )
    stats = c.fetchone()

    conn.close()

    return render_template(
        "leave_statistics.html",
        stats=stats
    )


# -----------------------------------------
# SUBMIT LEAVE
# -----------------------------------------
@app.route("/submit_leave", methods=["POST"])
def submit_leave():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] not in ["employee", "manager"]:
        return redirect(url_for("login"))

    dashboard_route = (
        "manager_leave"
        if session["role"] == "manager"
        else "employee_dashboard"
    )

    leave_type = request.form["leave_type"]
    start_date = request.form["start_date"]
    end_date = request.form["end_date"]
    reason = request.form["reason"]

    today = date.today()

    start_date_obj = datetime.strptime(
        start_date,
        "%Y-%m-%d"
    ).date()

    end_date_obj = datetime.strptime(
        end_date,
        "%Y-%m-%d"
    ).date()

    if start_date_obj < today:

        flash(
            "Start date cannot be in the past.",
            "error"
        )

        return redirect(
            url_for("apply_leave")
        )

    if end_date_obj < start_date_obj:

        flash(
            "End date cannot be earlier than start date.",
            "error"
        )

        return redirect(
            url_for("apply_leave")
        )

    max_future = today + timedelta(days=180)

    if start_date_obj > max_future:

        flash(
            "Leave can only be applied up to 6 months in advance.",
            "error"
        )

        return redirect(
            url_for("apply_leave")
        )

    if end_date_obj > max_future:

        flash(
            "Leave cannot extend beyond 6 months from today.",
            "error"
        )

        return redirect(
            url_for("apply_leave")
        )

    total_days = (
        end_date_obj - start_date_obj
    ).days + 1

    if total_days <= 0:

        flash(
            "Invalid leave duration.",
            "error"
        )

        return redirect(
            url_for("apply_leave")
        )

    if total_days > 30:

        flash(
            "A single leave request cannot exceed 30 days.",
            "error"
        )

        return redirect(
            url_for("apply_leave")
        )

    submitted_on = datetime.now().strftime(
        "%Y-%m-%d %H:%M"
    )

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (session["user_id"],)
    )
    user = c.fetchone()

    if leave_type == "Casual Leave":
        available_leave = user["casual_leave"]

    elif leave_type == "Sick Leave":
        available_leave = user["sick_leave"]

    elif leave_type == "Annual Leave":
        available_leave = user["annual_leave"]

    else:
        available_leave = None

    if available_leave is not None:

        if total_days > available_leave:

            flash(
                f"Only {available_leave} day(s) available for {leave_type}.",
                "error"
            )

            conn.close()

            return redirect(
                url_for("apply_leave")
            )

    c.execute(
        """
        SELECT *
        FROM leave_requests
        WHERE employee_id=%s
        AND (
            start_date <= %s
            AND end_date >= %s
        )
        """,
        (
            session["user_id"],
            end_date,
            start_date
        )
    )
    existing = c.fetchone()

    if existing:

        flash(
            "You already have a leave request during these dates.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("apply_leave")
        )

    approval_level = (
        "admin"
        if session["role"] == "manager"
        else "manager"
    )

    c.execute(
        """
        INSERT INTO leave_requests
        (
            employee_id,
            leave_type,
            start_date,
            end_date,
            total_days,
            reason,
            submitted_on,
            approval_level
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            session["user_id"],
            leave_type,
            start_date,
            end_date,
            total_days,
            reason,
            submitted_on,
            approval_level
        )
    )

    conn.commit()
    conn.close()

    flash(
        f"Leave request submitted successfully! ({total_days} day(s))",
        "success"
    )

    return redirect(
        url_for(dashboard_route)
    )


# -----------------------------------------
# CANCEL LEAVE
# -----------------------------------------
@app.route("/cancel_leave/<int:request_id>")
def cancel_leave(request_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] not in ["employee", "manager"]:
        return redirect(url_for("login"))

    dashboard_route = (
        "manager_leave"
        if session["role"] == "manager"
        else "employee_dashboard"
    )

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM leave_requests
        WHERE id=%s
        AND employee_id=%s
        """,
        (
            request_id,
            session["user_id"]
        )
    )
    leave = c.fetchone()

    if not leave:

        flash(
            "Leave request not found.",
            "error"
        )

        conn.close()

        return redirect(
            url_for(dashboard_route)
        )

    if leave["status"] != "Pending":

        flash(
            "Only pending requests can be cancelled.",
            "error"
        )

        conn.close()

        return redirect(
            url_for(dashboard_route)
        )

    c.execute(
        """
        DELETE FROM leave_requests
        WHERE id=%s
        """,
        (request_id,)
    )

    conn.commit()
    conn.close()

    flash(
        "Leave request cancelled successfully.",
        "success"
    )

    return redirect(
        url_for(dashboard_route)
    )


# -----------------------------------------
# MANAGER DASHBOARD
# -----------------------------------------
@app.route("/manager")
def manager_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "manager":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (session["user_id"],)
    )
    user = c.fetchone()

    c.execute(
        """
        SELECT

            SUM(
                CASE
                    WHEN status='Pending'
                    AND approval_level='manager'
                    THEN 1
                    ELSE 0
                END
            ) AS pending,

            SUM(
                CASE
                    WHEN status='Approved'
                    AND approval_level='manager'
                    THEN 1
                    ELSE 0
                END
            ) AS approved,

            SUM(
                CASE
                    WHEN status='Rejected'
                    AND approval_level='manager'
                    THEN 1
                    ELSE 0
                END
            ) AS rejected

        FROM leave_requests
        """
    )
    stats = c.fetchone()

    c.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE role='employee'
        """
    )
    total_employees = c.fetchone()["count"]

    c.execute(
        """
        SELECT
            lr.leave_type,
            lr.start_date,
            lr.end_date,
            lr.status,
            u.full_name

        FROM leave_requests lr

        JOIN users u
        ON lr.employee_id = u.id

        WHERE lr.approval_level='manager'

        ORDER BY lr.submitted_on DESC

        LIMIT 5
        """
    )
    recent_requests = c.fetchall()

    conn.close()

    return render_template(
        "manager_home.html",
        user=user,
        stats=stats,
        total_employees=total_employees,
        recent_requests=recent_requests
    )


# -----------------------------------------
# EMPLOYEE LEAVE REQUESTS
# -----------------------------------------
@app.route("/manager_requests")
def manager_requests():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "manager":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    search = request.args.get("search", "").strip()

    if search:

        c.execute(
            """
            SELECT
                lr.*,
                u.full_name AS employee_name,
                u.employee_id AS employee_code,
                u.casual_leave,
                u.sick_leave,
                u.annual_leave

            FROM leave_requests lr

            JOIN users u
            ON lr.employee_id = u.id

            WHERE
            (
                u.employee_id ILIKE %s
                OR u.full_name ILIKE %s
            )
            AND u.role='employee'
            AND lr.approval_level='manager'

            ORDER BY
                CASE
                    WHEN lr.status='Pending' THEN 0
                    ELSE 1
                END,
                lr.submitted_on DESC
            """,
            (
                f"%{search}%",
                f"%{search}%"
            )
        )

    else:

        c.execute(
            """
            SELECT
                lr.*,
                u.full_name AS employee_name,
                u.employee_id AS employee_code,
                u.casual_leave,
                u.sick_leave,
                u.annual_leave

            FROM leave_requests lr

            JOIN users u
            ON lr.employee_id = u.id

            WHERE
                u.role='employee'
                AND lr.approval_level='manager'

            ORDER BY
                CASE
                    WHEN lr.status='Pending' THEN 0
                    ELSE 1
                END,
                lr.submitted_on DESC
            """
        )

    all_requests = c.fetchall()

    c.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM users WHERE role='employee') AS total_employees,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE status='Pending'
             AND approval_level='manager') AS pending,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE status='Approved'
             AND approval_level='manager') AS approved,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE status='Rejected'
             AND approval_level='manager') AS rejected
        """
    )
    stats = c.fetchone()

    conn.close()

    return render_template(
        "manager_requests.html",
        all_requests=all_requests,
        stats=stats
    )


# -----------------------------------------
# MANAGER LEAVE DASHBOARD
# -----------------------------------------
@app.route("/manager_leave")
def manager_leave():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "manager":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (session["user_id"],)
    )
    user = c.fetchone()

    c.execute(
        """
        SELECT *
        FROM leave_requests
        WHERE employee_id=%s
        ORDER BY submitted_on DESC
        """,
        (session["user_id"],)
    )
    requests = c.fetchall()

    conn.close()
    today = date.today()

    max_date = (
        today + timedelta(days=180)
    ).strftime("%Y-%m-%d")

    today = today.strftime("%Y-%m-%d")

    return render_template(
        "manager_leave.html",
        requests=requests,
        user=user,
        today=today,
        max_date=max_date
    )


# -----------------------------------------
# ADMIN DASHBOARD
# -----------------------------------------
@app.route("/admin")
def admin_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )
    admin = c.fetchone()

    c.execute(
        """
        SELECT *
        FROM users
        ORDER BY
            CASE role
                WHEN 'admin' THEN 1
                WHEN 'manager' THEN 2
                WHEN 'employee' THEN 3
            END,
            full_name
        """
    )
    users = c.fetchall()

    c.execute(
        """
        SELECT

            (SELECT COUNT(*)
             FROM users
             WHERE role='employee')
             AS total_employees,

            (SELECT COUNT(*)
             FROM users
             WHERE role='manager')
             AS total_managers,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE approval_level='manager'
             AND status='Pending')
             AS employee_pending,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE approval_level='manager'
             AND status='Approved')
             AS employee_approved,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE approval_level='manager'
             AND status='Rejected')
             AS employee_rejected,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE approval_level='admin'
             AND status='Pending')
             AS manager_pending,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE approval_level='admin'
             AND status='Approved')
             AS manager_approved,

            (SELECT COUNT(*)
             FROM leave_requests
             WHERE approval_level='admin'
             AND status='Rejected')
             AS manager_rejected

        """
    )
    stats = c.fetchone()

    c.execute(
        """
        SELECT
            lr.id,
            lr.leave_type,
            lr.start_date,
            lr.end_date,
            lr.status,
            u.full_name

        FROM leave_requests lr

        JOIN users u
        ON lr.employee_id = u.id

        WHERE lr.approval_level='admin'

        ORDER BY lr.submitted_on DESC

        LIMIT 5
        """
    )
    recent_manager_requests = c.fetchall()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        admin=admin,
        users=users,
        stats=stats,
        recent_manager_requests=recent_manager_requests
    )


@app.route(
    "/add_manager",
    methods=["GET", "POST"]
)
def add_manager():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":

        conn = get_db()
        c = conn.cursor()

        try:

            c.execute(
                """
                INSERT INTO users
                (
                    employee_id,
                    password,
                    full_name,
                    email,
                    phone,
                    department,
                    role,
                    must_change_password
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    request.form["employee_id"]
                    .strip()
                    .upper(),

                    generate_password_hash(
                        "Manager@123"
                    ),

                    request.form["full_name"],
                    request.form["email"],
                    request.form["phone"],
                    request.form["department"],

                    "manager",

                    1
                )
            )

            conn.commit()

            flash(
                "Manager created successfully.",
                "success"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        except psycopg2.IntegrityError:
            conn.rollback()
            flash(
                "Employee ID already exists.",
                "error"
            )

            return redirect(
                url_for("add_manager")
            )

        finally:

            conn.close()

    return render_template(
        "add_manager.html"
    )


# -----------------------------------------
# ADMIN - EDIT EMPLOYEE DETAILS
# -----------------------------------------
@app.route("/edit_employee/<int:user_id>", methods=["GET", "POST"])
def edit_employee(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (user_id,)
    )
    user = c.fetchone()

    if not user:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    if user["role"] == "admin":
        conn.close()
        flash("Admin account cannot be edited.", "error")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":

        full_name = request.form["full_name"]
        email = request.form["email"]
        phone = request.form["phone"]
        department = request.form["department"]
        designation = request.form["designation"]

        casual_leave = request.form["casual_leave"]
        sick_leave = request.form["sick_leave"]
        annual_leave = request.form["annual_leave"]

        c.execute(
            """
            UPDATE users
            SET
                full_name=%s,
                email=%s,
                phone=%s,
                department=%s,
                designation=%s,
                casual_leave=%s,
                sick_leave=%s,
                annual_leave=%s
            WHERE id=%s
            """,
            (
                full_name,
                email,
                phone,
                department,
                designation,
                casual_leave,
                sick_leave,
                annual_leave,
                user_id
            )
        )

        conn.commit()
        conn.close()

        flash("User updated successfully.", "success")

        return redirect(url_for("admin_dashboard"))

    conn.close()

    return render_template(
        "admin_edit_user.html",
        user=user,
        admin_edit=True
    )


# -----------------------------------------
# ADMIN - MANAGER LEAVE REQUESTS
# -----------------------------------------
@app.route("/admin_requests")
def admin_requests():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT
            lr.*,
            u.full_name,
            u.employee_id

        FROM leave_requests lr

        JOIN users u
        ON lr.employee_id = u.id

        WHERE
            lr.approval_level='admin'
            AND lr.status='Pending'

        ORDER BY lr.submitted_on DESC
    """)
    pending_requests = c.fetchall()

    c.execute("""
        SELECT
            lr.*,
            u.full_name,
            u.employee_id

        FROM leave_requests lr

        JOIN users u
        ON lr.employee_id = u.id

        WHERE
            lr.approval_level='admin'
            AND lr.status IN ('Approved','Rejected')

        ORDER BY lr.decision_date DESC
        LIMIT 10
    """)
    decision_history = c.fetchall()

    c.execute("""
        SELECT
            COUNT(*) AS pending_manager_requests
        FROM leave_requests
        WHERE
            approval_level='admin'
            AND status='Pending'
    """)
    stats = c.fetchone()

    conn.close()

    return render_template(
        "admin_requests.html",
        pending_requests=pending_requests,
        decision_history=decision_history,
        stats=stats
    )


# -----------------------------------------
# TOGGLE USER STATUS
# -----------------------------------------
@app.route("/toggle_user/<int:user_id>")
def toggle_user(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "admin":
        return redirect(url_for("login"))

    if user_id == session["user_id"]:

        flash(
            "You cannot deactivate your own account.",
            "error"
        )

        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT is_active
        FROM users
        WHERE id=%s
        """,
        (user_id,)
    )
    user = c.fetchone()

    if user:

        new_status = 0 if user["is_active"] else 1

        c.execute(
            """
            UPDATE users
            SET is_active=%s
            WHERE id=%s
            """,
            (new_status, user_id)
        )

        conn.commit()

    conn.close()

    flash(
        "User status updated successfully.",
        "success"
    )

    return redirect(
        url_for("admin_dashboard")
    )


# -----------------------------------------
# APPROVE / REJECT LEAVE
# -----------------------------------------
@app.route("/action/<int:request_id>", methods=["POST"])
def take_action(request_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "manager":
        return redirect(url_for("login"))

    if request.form["action"] not in [
        "Approved",
        "Rejected"
    ]:
        flash(
            "Invalid action.",
            "error"
        )
        return redirect(
            url_for("manager_requests")
        )

    action = request.form["action"]
    comment = request.form.get("comment", "")

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT status, approval_level
        FROM leave_requests
        WHERE id=%s
        """,
        (request_id,)
    )
    current = c.fetchone()

    if not current:

        flash(
            "Leave request not found.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("manager_requests")
        )

    if current["approval_level"] != "manager":

        flash(
            "Invalid approval request.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("manager_requests")
        )

    if current["status"] != "Pending":

        flash(
            "Request already processed.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("manager_requests")
        )

    decision_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M"
    )

    if action == "Approved":

        c.execute(
            """
            SELECT
                employee_id,
                leave_type,
                total_days
            FROM leave_requests
            WHERE id=%s
            """,
            (request_id,)
        )
        leave = c.fetchone()

        if leave:

            leave_map = {
                "Casual Leave": "casual_leave",
                "Sick Leave": "sick_leave",
                "Annual Leave": "annual_leave"
            }

            if leave["leave_type"] in leave_map:

                column = leave_map[
                    leave["leave_type"]
                ]

                c.execute(
                    """
                    SELECT *
                    FROM users
                    WHERE id=%s
                    """,
                    (leave["employee_id"],)
                )
                employee = c.fetchone()

                if employee[column] < leave["total_days"]:

                    flash(
                        "Insufficient leave balance.",
                        "error"
                    )

                    conn.close()

                    return redirect(
                        url_for("manager_requests")
                    )

                c.execute(
                    f"""
                    UPDATE users
                    SET {column} = {column} - %s
                    WHERE id=%s
                    """,
                    (
                        leave["total_days"],
                        leave["employee_id"]
                    )
                )

    c.execute(
        """
        UPDATE leave_requests
        SET status=%s,
            manager_comment=%s,
            decision_date=%s,
            approved_by=%s
        WHERE id=%s
        """,
        (
            action,
            comment,
            decision_date,
            session["user_id"],
            request_id
        )
    )

    conn.commit()
    conn.close()

    flash(
        f"Request {action} successfully!",
        "success"
    )

    return redirect(
        url_for("manager_requests")
    )


# -----------------------------------------
# ADMIN APPROVE / REJECT MANAGER LEAVE
# -----------------------------------------
@app.route(
    "/admin_action/<int:request_id>",
    methods=["POST"]
)
def admin_action(request_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "admin":
        return redirect(url_for("login"))

    if request.form["action"] not in [
        "Approved",
        "Rejected"
    ]:
        flash(
            "Invalid action.",
            "error"
        )
        return redirect(
            url_for("manager_requests")
        )

    action = request.form["action"]
    comment = request.form.get("comment", "")

    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        SELECT status, approval_level
        FROM leave_requests
        WHERE id=%s
        """,
        (request_id,)
    )
    current = c.fetchone()

    if not current:

        flash(
            "Leave request not found.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("admin_requests")
        )

    if current["approval_level"] != "admin":

        flash(
            "Invalid approval request.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("admin_requests")
        )

    if current["status"] != "Pending":

        flash(
            "Request already processed.",
            "error"
        )

        conn.close()

        return redirect(
            url_for("admin_requests")
        )

    decision_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M"
    )

    c.execute(
        """
        UPDATE leave_requests
        SET
            status=%s,
            manager_comment=%s,
            decision_date=%s,
            approved_by=%s
        WHERE id=%s
        """,
        (
            action,
            comment,
            decision_date,
            session["user_id"],
            request_id
        )
    )

    if action == "Approved":

        c.execute(
            """
            SELECT
                employee_id,
                leave_type,
                total_days
            FROM leave_requests
            WHERE id=%s
            """,
            (request_id,)
        )
        leave = c.fetchone()

        leave_map = {
            "Casual Leave": "casual_leave",
            "Sick Leave": "sick_leave",
            "Annual Leave": "annual_leave"
        }

        if leave["leave_type"] in leave_map:

            column = leave_map[
                leave["leave_type"]
            ]

            c.execute(
                f"""
                UPDATE users
                SET {column} =
                    CASE
                        WHEN {column} - %s < 0
                        THEN 0
                        ELSE {column} - %s
                    END
                WHERE id=%s
                """,
                (
                    leave["total_days"],
                    leave["total_days"],
                    leave["employee_id"]
                )
            )

    conn.commit()
    conn.close()

    flash(
        f"Manager leave request {action.lower()} successfully.",
        "success"
    )

    return redirect(
        url_for("admin_requests")
    )


# -----------------------------------------
# EXPORT CSV REPORT
# -----------------------------------------
@app.route("/export_csv")
def export_csv():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "manager":
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT
            u.full_name,
            u.employee_id,
            lr.leave_type,
            lr.start_date,
            lr.end_date,
            lr.total_days,
            lr.status,
            lr.manager_comment,
            lr.decision_date
        FROM leave_requests lr
        JOIN users u
        ON lr.employee_id = u.id
        WHERE u.role='employee'
    """)
    data = c.fetchall()

    conn.close()

    csv_data = "Employee Name,Employee ID,Leave Type,Start Date,End Date,Days,Status,Manager Comment,Decision Date\n"

    for row in data:
        csv_data += (
            f"{row['full_name']},"
            f"{row['employee_id']},"
            f"{row['leave_type']},"
            f"{row['start_date']},"
            f"{row['end_date']},"
            f"{row['total_days']},"
            f"{row['status']},"
            f"{row['manager_comment']},"
            f"{row['decision_date']}\n"
        )

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=leave_report.csv"
        }
    )


# -----------------------------------------
# START APPLICATION
# -----------------------------------------
init_db()
conn = get_db()
c = conn.cursor()

try:

    c.execute(
        """
        INSERT INTO users
        (employee_id, password, full_name, role, must_change_password)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (employee_id) DO NOTHING
        """,
        (
            "MGR001",
            generate_password_hash("Manager@123"),
            "System Manager",
            "manager",
            1
        )
    )

    c.execute(
        """
        INSERT INTO users
        (employee_id, password, full_name, role, must_change_password)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (employee_id) DO NOTHING
        """,
        (
            "ADMIN001",
            generate_password_hash("Admin@123"),
            "System Administrator",
            "admin",
            1
        )
    )

    conn.commit()

except Exception as e:
    print("Error:", e)
    conn.rollback()

finally:
    conn.close()


if __name__ == "__main__":

    print("\n✅ Employee Leave Portal Running")
    print("🌐 http://127.0.0.1:5000\n")

    app.run(host="0.0.0.0", port=5000)