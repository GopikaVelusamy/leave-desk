from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify
import re
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
import json
import warnings

# Suppress Firestore SDK positional argument UserWarnings
warnings.filterwarnings("ignore", category=UserWarning)


app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

# -----------------------------------------
# FIREBASE ADMIN SETUP
# -----------------------------------------
firebase_credentials_json = os.environ.get("FIREBASE_CREDENTIALS")
db_firestore = None
FIREBASE_ENABLED = False

if not firebase_admin._apps:
    # Option 1: Env variable
    if firebase_credentials_json:
        try:
            if firebase_credentials_json.strip().startswith("{"):
                cred_dict = json.loads(firebase_credentials_json)
                cred = credentials.Certificate(cred_dict)
            else:
                cred = credentials.Certificate(firebase_credentials_json)
            firebase_admin.initialize_app(cred)
            db_firestore = firestore.client()
            FIREBASE_ENABLED = True
            print("Firebase Admin initialized using FIREBASE_CREDENTIALS environment variable.")
        except Exception as e:
            print(f"Env credentials init failed: {e}")
            if firebase_admin._apps:
                firebase_admin.delete_app(firebase_admin.get_app())
    
    # Option 2: Local JSON key
    if not FIREBASE_ENABLED:
        local_keys = ["serviceAccountKey.json", "firebase-key.json"]
        key_file = None
        for key_path in local_keys:
            if os.path.exists(key_path):
                key_file = key_path
                break
        if key_file:
            try:
                cred = credentials.Certificate(key_file)
                firebase_admin.initialize_app(cred)
                db_firestore = firestore.client()
                FIREBASE_ENABLED = True
                print(f"Firebase Admin initialized using local key file: {key_file}")
            except Exception as e:
                print(f"Local key file init failed: {e}")
                if firebase_admin._apps:
                    firebase_admin.delete_app(firebase_admin.get_app())
                    
    # Option 3: Application Default Credentials
    if not FIREBASE_ENABLED:
        try:
            cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
            db_firestore = firestore.client()
            FIREBASE_ENABLED = True
            print("Firebase Admin initialized using Application Default Credentials.")
        except Exception as e:
            print(f"Application Default Credentials init failed: {e}")
            if firebase_admin._apps:
                firebase_admin.delete_app(firebase_admin.get_app())
                
    # Option 4: Parameter-less initialization
    if not FIREBASE_ENABLED:
        try:
            firebase_admin.initialize_app()
            db_firestore = firestore.client()
            FIREBASE_ENABLED = True
            print("Firebase Admin initialized with default configuration.")
        except Exception as e:
            print(f"Default parameterless init failed: {e}")
            if firebase_admin._apps:
                firebase_admin.delete_app(firebase_admin.get_app())

if not FIREBASE_ENABLED or db_firestore is None:
    print("\n[WARNING] Firebase is not properly initialized! The application database will not work.\n")


# Helper to convert Firestore document to dict with 'id' key
def to_dict_with_id(doc):
    if not doc.exists:
        return None
    d = doc.to_dict()
    d["id"] = doc.id
    return d


def resolve_deciders(requests_list, users_dict):
    """Resolve processed_by_name and processed_by_role for each request in the list."""
    for r in requests_list:
        decider_id = r.get("approved_by")
        if decider_id:
            decider_data = users_dict.get(decider_id)
            if decider_data:
                r["processed_by_name"] = decider_data.get("full_name", "System")
                r["processed_by_role"] = decider_data.get("role", "")
            else:
                r["processed_by_name"] = "System"
                r["processed_by_role"] = ""
        else:
            r["processed_by_name"] = ""
            r["processed_by_role"] = ""



# -----------------------------------------
# DATABASE SETUP
# -----------------------------------------
def init_db():
    if not FIREBASE_ENABLED or db_firestore is None:
        print("Skipping DB initialization: Firebase is not enabled.")
        return

    try:
        users_ref = db_firestore.collection("users")
        # Check if users collection has any manager or admin
        admin_query = users_ref.where("employee_id", "==", "ADMIN001").limit(1).get()
        mgr_query = users_ref.where("employee_id", "==", "MGR001").limit(1).get()

        if len(admin_query) == 0:
            print("Creating default admin account (ADMIN001)...")
            users_ref.add({
                "employee_id": "ADMIN001",
                "password": generate_password_hash("Admin@123"),
                "full_name": "System Administrator",
                "email": "admin@example.com",
                "phone": "",
                "department": "IT",
                "designation": "Administrator",
                "role": "admin",
                "casual_leave": 6,
                "sick_leave": 6,
                "annual_leave": 12,
                "is_active": 1,
                "must_change_password": 1
            })

        if len(mgr_query) == 0:
            print("Creating default manager account (MGR001)...")
            users_ref.add({
                "employee_id": "MGR001",
                "password": generate_password_hash("Manager@123"),
                "full_name": "System Manager",
                "email": "manager@example.com",
                "phone": "",
                "department": "Management",
                "designation": "Manager",
                "role": "manager",
                "casual_leave": 6,
                "sick_leave": 6,
                "annual_leave": 12,
                "is_active": 1,
                "must_change_password": 1
            })

        print("Database initialization check complete.")
    except Exception as e:
        print(f"Error during init_db: {e}")


# -----------------------------------------
# HOME PAGE
# -----------------------------------------
@app.route("/")
def home():
    return render_template("home.html")


def verify_firebase_password(email, password):
    api_key = "AIzaSyA9i4pJF7daO4ZlVFy64BWsO7TT9zLrfe4"
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    try:
        import requests
        r = requests.post(url, json=payload, timeout=10)
        res = r.json()
        if r.status_code == 200:
            return True, res.get("localId")
        else:
            error_message = res.get("error", {}).get("message", "")
            return False, error_message
    except Exception as e:
        print(f"REST auth error: {e}")
        return False, "CONNECTION_ERROR"


# -----------------------------------------
# SIGNUP
# -----------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form["full_name"]
        email = request.form["email"].strip()

        # Auto-generate a unique Employee ID based on full name
        parts = [p.upper() for p in re.findall(r'[a-zA-Z0-9]+', full_name)]
        if len(parts) >= 2:
            base_id = f"{parts[0]}{parts[1]}"
        elif len(parts) == 1:
            base_id = parts[0]
        else:
            base_id = "EMP"
        base_id = base_id[:16]

        import random
        employee_id = None
        for attempt in range(100):
            rand_num = random.randint(1000, 9999)
            candidate_id = f"{base_id}{rand_num}"
            existing = db_firestore.collection("users").where("employee_id", "==", candidate_id).limit(1).get()
            if len(existing) == 0:
                employee_id = candidate_id
                break

        if not employee_id:
            flash("Could not generate a unique Employee ID. Please try again.", "error")
            return redirect(url_for("signup"))

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("signup"))

        password = request.form["password"]
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("signup"))
        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter.", "error")
            return redirect(url_for("signup"))
        if not re.search(r"[a-z]", password):
            flash("Password must contain at least one lowercase letter.", "error")
            return redirect(url_for("signup"))
        if not re.search(r"\d", password):
            flash("Password must contain at least one number.", "error")
            return redirect(url_for("signup"))
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash("Password must contain at least one special character.", "error")
            return redirect(url_for("signup"))

        role = "employee"
        confirm_password = request.form["confirm_password"]
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        if not FIREBASE_ENABLED or db_firestore is None:
            flash("Database service unavailable.", "error")
            return redirect(url_for("signup"))

        hashed_password = generate_password_hash(password)
        try:
            # Check duplicate employee_id
            existing = db_firestore.collection("users").where("employee_id", "==", employee_id).limit(1).get()
            if len(existing) > 0:
                flash("Employee ID already exists!", "error")
                return redirect(url_for("signup"))

            # Check if user already exists in Firebase Auth
            uid = None
            try:
                fb_user = firebase_auth.get_user_by_email(email)
                uid = fb_user.uid
                print(f"User with email {email} already exists in Firebase Auth. Reusing UID: {uid}")
            except Exception:
                pass

            # If not in Firebase Auth, create them first to get a UID
            if not uid:
                try:
                    fb_user = firebase_auth.create_user(
                        email=email,
                        password=password,
                        display_name=full_name
                    )
                    uid = fb_user.uid
                except Exception as e_auth:
                    print(f"Firebase Auth signup creation failed: {e_auth}")
                    # Fallback: use auto-generated ID
                    uid = db_firestore.collection("users").document().id

            # Create document in Firestore using the aligned UID
            user_ref = db_firestore.collection("users").document(uid)
            user_ref.set({
                "employee_id": employee_id,
                "password": hashed_password,
                "full_name": full_name,
                "email": email,
                "phone": "",
                "department": "",
                "designation": "",
                "role": role,
                "casual_leave": 6,
                "sick_leave": 6,
                "annual_leave": 12,
                "is_active": 1,
                "must_change_password": 0
            })

            flash(f"Account created successfully! Your unique User ID is: {employee_id}. Please use this to log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"Signup error: {e}")
            flash("An error occurred. Please try again.", "error")

    return render_template("signup.html")


# -----------------------------------------
# LOGIN
# -----------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        employee_id = request.form["employee_id"].strip().upper()
        password = request.form["password"]

        if not FIREBASE_ENABLED or db_firestore is None:
            flash("Database service unavailable.", "error")
            return redirect(url_for("login"))

        try:
            user_docs = db_firestore.collection("users").where("employee_id", "==", employee_id).limit(1).get()
            if len(user_docs) == 0:
                flash("Invalid Employee ID or Password!", "error")
                return redirect(url_for("login"))

            user_doc = user_docs[0]
            user = to_dict_with_id(user_doc)

            if user.get("is_active", 1) == 0:
                flash("Account has been deactivated.", "error")
                return redirect(url_for("login"))

            email = user.get("email")
            authenticated = False

            # Check if user exists in Firebase Auth by email first
            in_firebase = False
            if email:
                try:
                    firebase_auth.get_user_by_email(email)
                    in_firebase = True
                except Exception:
                    in_firebase = False

            # 1. Try to authenticate using Firebase Auth REST API (if user has an email and is in Firebase Auth)
            if email and in_firebase:
                success, error_code = verify_firebase_password(email, password)
                if success:
                    authenticated = True
                    # Sync local password hash to match
                    db_firestore.collection("users").document(user["id"]).update({
                        "password": generate_password_hash(password)
                    })
                else:
                    # Strict validation: Since user is in Firebase Auth, Firebase Auth is the source of truth.
                    # We do NOT fall back to local check_password_hash.
                    flash("Invalid Employee ID or Password!", "error")
                    return redirect(url_for("login"))

            # 2. Fall back to local check_password_hash if not authenticated yet (user not in Firebase Auth)
            if not authenticated:
                if check_password_hash(user["password"], password):
                    authenticated = True
                    # If this user has an email, register them in Firebase Auth on the fly so they can use forgot password in the future
                    if email:
                        try:
                            firebase_auth.create_user(
                                uid=user["id"],
                                email=email,
                                password=password,
                                display_name=user["full_name"]
                            )
                        except Exception as e_auth:
                            print(f"Sync-on-demand Firebase Auth creation failed: {e_auth}")
                else:
                    flash("Invalid Employee ID or Password!", "error")
                    return redirect(url_for("login"))

            if authenticated:
                session["user_id"] = user["id"]
                session["employee_id"] = user["employee_id"]
                session["full_name"] = user["full_name"]
                session["role"] = user["role"]

                if user.get("must_change_password", 0) == 1:
                    flash("Please change your password before continuing.", "error")
                    return redirect(url_for("change_password"))

                if user["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                elif user["role"] == "manager":
                    return redirect(url_for("manager_dashboard"))
                else:
                    return redirect(url_for("employee_dashboard"))
        except Exception as e:
            print(f"Login error: {e}")
            flash("Login failed. Please try again.", "error")

    return render_template("login.html")


# -----------------------------------------
# PROFILE
# -----------------------------------------
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        user_doc = db_firestore.collection("users").document(session["user_id"]).get()
        if not user_doc.exists:
            session.clear()
            return redirect(url_for("login"))
        user = to_dict_with_id(user_doc)

        reqs = db_firestore.collection("leave_requests").where("employee_id", "==", session["user_id"]).stream()
        total = 0
        approved = 0
        rejected = 0
        pending = 0
        for doc in reqs:
            d = doc.to_dict()
            total += 1
            status = d.get("status", "Pending")
            if status == "Approved":
                approved += 1
            elif status == "Rejected":
                rejected += 1
            elif status == "Pending":
                pending += 1

        stats = {
            "total": total,
            "approved": approved,
            "rejected": rejected,
            "pending": pending
        }
        return render_template("profile.html", user=user, stats=stats)
    except Exception as e:
        print(f"Profile load error: {e}")
        flash("Could not load profile details.", "error")
        return redirect(url_for("home"))


# -----------------------------------------
# EDIT PROFILE
# -----------------------------------------
@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        user_ref = db_firestore.collection("users").document(session["user_id"])
        if request.method == "POST":
            email = request.form["email"].strip()
            phone = request.form["phone"].strip()

            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                flash("Please enter a valid email address.", "error")
                return redirect(url_for("edit_profile"))

            if phone:
                if not re.fullmatch(r"\d{10}", phone):
                    flash("Phone number must contain exactly 10 digits.", "error")
                    return redirect(url_for("edit_profile"))

            user_ref.update({
                "email": email,
                "phone": phone
            })
            flash("Profile updated successfully.", "success")
            return redirect(url_for("edit_profile"))

        user_doc = user_ref.get()
        user = to_dict_with_id(user_doc)
        return render_template("edit_profile.html", user=user)
    except Exception as e:
        print(f"Edit profile error: {e}")
        flash("An error occurred.", "error")
        return redirect(url_for("profile"))


# -----------------------------------------
# CHANGE PASSWORD
# -----------------------------------------
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] not in ["employee", "manager", "admin"]:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        user_ref = db_firestore.collection("users").document(session["user_id"])
        if request.method == "POST":
            current_password = request.form["current_password"]
            new_password = request.form["new_password"]
            confirm_password = request.form["confirm_password"]

            user_doc = user_ref.get()
            user = to_dict_with_id(user_doc)

            if not check_password_hash(user["password"], current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("change_password"))

            if check_password_hash(user["password"], new_password):
                flash("New password cannot be the same as the current password.", "error")
                return redirect(url_for("change_password"))

            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return redirect(url_for("change_password"))

            if len(new_password) < 8:
                flash("Password must contain at least 8 characters.", "error")
                return redirect(url_for("change_password"))
            if not re.search(r"[A-Z]", new_password):
                flash("Password must contain one uppercase letter.", "error")
                return redirect(url_for("change_password"))
            if not re.search(r"[a-z]", new_password):
                flash("Password must contain one lowercase letter.", "error")
                return redirect(url_for("change_password"))
            if not re.search(r"\d", new_password):
                flash("Password must contain one number.", "error")
                return redirect(url_for("change_password"))
            if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
                flash("Password must contain one special character.", "error")
                return redirect(url_for("change_password"))

            user_ref.update({
                "password": generate_password_hash(new_password),
                "must_change_password": 0
            })
            # Sync password update to Firebase Auth
            try:
                if user.get("email"):
                    fb_user = firebase_auth.get_user_by_email(user["email"])
                    firebase_auth.update_user(
                        fb_user.uid,
                        password=new_password
                    )
                else:
                    firebase_auth.update_user(
                        session["user_id"],
                        password=new_password
                    )
            except Exception as e_auth:
                print(f"Firebase Auth password update failed: {e_auth}")
            flash("Password changed successfully.", "success")
            return redirect(url_for("profile"))

        return render_template("change_password.html")
    except Exception as e:
        print(f"Change password error: {e}")
        flash("An error occurred.", "error")
        return redirect(url_for("profile"))


# -----------------------------------------
# FORGOT PASSWORD
# -----------------------------------------
@app.route("/forgot_password", methods=["GET"])
def forgot_password():
    return render_template("forgot_password.html")

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

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        user_doc = db_firestore.collection("users").document(session["user_id"]).get()
        if not user_doc.exists:
            session.clear()
            return redirect(url_for("login"))
        user = to_dict_with_id(user_doc)

        reqs = db_firestore.collection("leave_requests").where("employee_id", "==", session["user_id"]).stream()
        requests_list = []
        total = 0
        pending = 0
        approved = 0
        rejected = 0
        for doc in reqs:
            d = to_dict_with_id(doc)
            requests_list.append(d)
            total += 1
            status = d.get("status", "Pending")
            if status == "Pending":
                pending += 1
            elif status == "Approved":
                approved += 1
            elif status == "Rejected":
                rejected += 1

        requests_list.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)
        stats = {
            "total": total,
            "pending": pending,
            "approved": approved,
            "rejected": rejected
        }
        return render_template("employee_dashboard.html", user=user, stats=stats, requests=requests_list)
    except Exception as e:
        print(f"Employee dashboard error: {e}")
        flash("Could not load dashboard stats.", "error")
        return redirect(url_for("home"))


@app.route("/apply_leave")
def apply_leave():
    if "user_id" not in session:
        return redirect(url_for("login"))
    today = date.today()
    max_date = (today + timedelta(days=180)).strftime("%Y-%m-%d")
    today = today.strftime("%Y-%m-%d")
    return render_template("apply_leave.html", today=today, max_date=max_date)


@app.route("/my_requests")
def my_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        docs = db_firestore.collection("leave_requests").where("employee_id", "==", session["user_id"]).stream()
        requests = [to_dict_with_id(d) for d in docs]
        
        users_docs = db_firestore.collection("users").get()
        users_dict = {u.id: to_dict_with_id(u) for u in users_docs}
        resolve_deciders(requests, users_dict)

        requests.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)
        return render_template("my_requests.html", requests=requests)
    except Exception as e:
        print(f"My requests load error: {e}")
        flash("Could not load requests list.", "error")
        return redirect(url_for("employee_dashboard"))


# -----------------------------------------
# LEAVE STATISTICS
# -----------------------------------------
@app.route("/leave_statistics")
def leave_statistics():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        docs = db_firestore.collection("leave_requests").where("employee_id", "==", session["user_id"]).stream()
        total = 0
        approved = 0
        rejected = 0
        pending = 0
        for doc in docs:
            d = doc.to_dict()
            total += 1
            status = d.get("status", "Pending")
            if status == "Approved":
                approved += 1
            elif status == "Rejected":
                rejected += 1
            elif status == "Pending":
                pending += 1

        stats = {
            "total": total,
            "approved": approved,
            "rejected": rejected,
            "pending": pending
        }
        return render_template("leave_statistics.html", stats=stats)
    except Exception as e:
        print(f"Leave stats error: {e}")
        flash("An error occurred loading statistics.", "error")
        return redirect(url_for("employee_dashboard"))


# -----------------------------------------
# SUBMIT LEAVE
# -----------------------------------------
@app.route("/submit_leave", methods=["POST"])
def submit_leave():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] not in ["employee", "manager"]:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    dashboard_route = "manager_leave" if session["role"] == "manager" else "employee_dashboard"
    leave_type = request.form["leave_type"]
    start_date = request.form["start_date"]
    end_date = request.form["end_date"]
    reason = request.form["reason"]

    today = date.today()
    try:
        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid date format.", "error")
        return redirect(url_for("apply_leave"))

    if start_date_obj < today:
        flash("Start date cannot be in the past.", "error")
        return redirect(url_for("apply_leave"))
    if end_date_obj < start_date_obj:
        flash("End date cannot be earlier than start date.", "error")
        return redirect(url_for("apply_leave"))

    max_future = today + timedelta(days=180)
    if start_date_obj > max_future:
        flash("Leave can only be applied up to 6 months in advance.", "error")
        return redirect(url_for("apply_leave"))
    if end_date_obj > max_future:
        flash("Leave cannot extend beyond 6 months from today.", "error")
        return redirect(url_for("apply_leave"))

    total_days = (end_date_obj - start_date_obj).days + 1
    if total_days <= 0:
        flash("Invalid leave duration.", "error")
        return redirect(url_for("apply_leave"))
    if total_days > 30:
        flash("A single leave request cannot exceed 30 days.", "error")
        return redirect(url_for("apply_leave"))

    submitted_on = datetime.now().strftime("%Y-%m-%d %H:%M")

    try:
        user_ref = db_firestore.collection("users").document(session["user_id"])
        user_doc = user_ref.get()
        user = to_dict_with_id(user_doc)

        if leave_type == "Casual Leave":
            available_leave = user.get("casual_leave", 0)
        elif leave_type == "Sick Leave":
            available_leave = user.get("sick_leave", 0)
        elif leave_type == "Annual Leave":
            available_leave = user.get("annual_leave", 0)
        else:
            available_leave = None

        if available_leave is not None:
            if total_days > available_leave:
                flash(f"Only {available_leave} day(s) available for {leave_type}.", "error")
                return redirect(url_for("apply_leave"))

        # Overlap check
        existing_reqs = db_firestore.collection("leave_requests").where("employee_id", "==", session["user_id"]).stream()
        overlapping = False
        for doc in existing_reqs:
            d = doc.to_dict()
            # If the request status is cancelled/rejected, maybe overlap is fine?
            # But the original SQL checked all requests. Let's keep that logic but ignore Rejected.
            if d.get("status") == "Rejected":
                continue
            if (d.get("start_date") <= end_date) and (d.get("end_date") >= start_date):
                overlapping = True
                break

        if overlapping:
            flash("You already have a leave request during these dates.", "error")
            return redirect(url_for("apply_leave"))

        approval_level = "admin" if session["role"] == "manager" else "manager"
        db_firestore.collection("leave_requests").add({
            "employee_id": session["user_id"],
            "leave_type": leave_type,
            "start_date": start_date,
            "end_date": end_date,
            "total_days": int(total_days),
            "reason": reason,
            "status": "Pending",
            "manager_comment": "",
            "decision_date": "",
            "submitted_on": submitted_on,
            "approved_by": None,
            "approval_level": approval_level
        })

        # Notify appropriate role (admin for manager leaves, manager/admins for employee leaves)
        try:
            receivers = []
            if session["role"] == "manager":
                # Manager leave requests notify admins
                admins = db_firestore.collection("users").where("role", "==", "admin").get()
                receivers.extend(admins)
            else:
                # Employee leave requests notify managers of the same department
                emp_dept = user.get("department", "")
                if emp_dept:
                    managers = db_firestore.collection("users")\
                        .where("role", "==", "manager")\
                        .where("department", "==", emp_dept)\
                        .get()
                    receivers.extend(managers)
                else:
                    # Fallback if employee has no department: notify all managers
                    managers = db_firestore.collection("users").where("role", "==", "manager").get()
                    receivers.extend(managers)
                
                # Also notify all admins since admin can also review employee leaves
                admins = db_firestore.collection("users").where("role", "==", "admin").get()
                receivers.extend(admins)

            # Deduplicate receivers by user ID
            seen = set()
            dedup_receivers = []
            for r in receivers:
                if r.id not in seen:
                    seen.add(r.id)
                    dedup_receivers.append(r)

            for rec in dedup_receivers:
                send_notification(
                    rec.id,
                    "New Leave Request",
                    f"{session['full_name']} ({session['role'].capitalize()}) has applied for {leave_type} ({total_days} day(s)).",
                    "info"
                )
        except Exception as e:
            print(f"Notification routing error: {e}")

        flash(f"Leave request submitted successfully! ({total_days} day(s))", "success")
    except Exception as e:
        print(f"Submit leave error: {e}")
        flash("Could not submit leave request. Please try again.", "error")

    return redirect(url_for(dashboard_route))


# -----------------------------------------
# CANCEL LEAVE
# -----------------------------------------
@app.route("/cancel_leave/<string:request_id>")
def cancel_leave(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] not in ["employee", "manager"]:
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    dashboard_route = "manager_leave" if session["role"] == "manager" else "employee_dashboard"

    try:
        req_ref = db_firestore.collection("leave_requests").document(request_id)
        req_doc = req_ref.get()
        if not req_doc.exists:
            flash("Leave request not found.", "error")
            return redirect(url_for(dashboard_route))

        leave = to_dict_with_id(req_doc)
        if leave["employee_id"] != session["user_id"]:
            flash("Unauthorized access.", "error")
            return redirect(url_for(dashboard_route))

        if leave["status"] != "Pending":
            flash("Only pending requests can be cancelled.", "error")
            return redirect(url_for(dashboard_route))

        req_ref.delete()
        flash("Leave request cancelled successfully.", "success")
    except Exception as e:
        print(f"Cancel leave error: {e}")
        flash("Could not cancel request.", "error")

    return redirect(url_for(dashboard_route))


# -----------------------------------------
# MANAGER DASHBOARD
# -----------------------------------------
@app.route("/manager")
def manager_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "manager":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        user_doc = db_firestore.collection("users").document(session["user_id"]).get()
        user = to_dict_with_id(user_doc)
        manager_dept = (user.get("department") or "").strip().lower()

        reqs_docs = db_firestore.collection("leave_requests").get()
        pending = 0
        approved = 0
        rejected = 0

        users_docs = db_firestore.collection("users").get()
        users_dict = {u.id: to_dict_with_id(u) for u in users_docs}

        all_manager_requests = []
        for doc in reqs_docs:
            d = to_dict_with_id(doc)
            if d.get("approval_level") == "manager":
                emp_id = d.get("employee_id")
                emp_data = users_dict.get(emp_id, {})
                emp_dept = (emp_data.get("department") or "").strip().lower()

                # Filter by department: allow empty department to be viewed by all managers
                if emp_dept and emp_dept != manager_dept:
                    continue

                status = d.get("status", "Pending")
                if status == "Pending":
                    pending += 1
                elif status == "Approved":
                    approved += 1
                elif status == "Rejected":
                    rejected += 1

                d["full_name"] = emp_data.get("full_name", "Unknown")
                all_manager_requests.append(d)

        # Resolve deciders
        resolve_deciders(all_manager_requests, users_dict)

        # Sort and take 5
        all_manager_requests.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)
        recent_requests = all_manager_requests[:5]

        # Filter total employee count to match manager's department (including unassigned department employees)
        total_employees = sum(
            1 for u in users_dict.values()
            if u.get("role") == "employee" and (not (u.get("department") or "").strip() or (u.get("department") or "").strip().lower() == manager_dept)
        )

        stats = {
            "pending": pending,
            "approved": approved,
            "rejected": rejected
        }

        return render_template(
            "manager_home.html",
            user=user,
            stats=stats,
            total_employees=total_employees,
            recent_requests=recent_requests
        )
    except Exception as e:
        print(f"Manager dashboard error: {e}")
        flash("An error occurred loading manager dashboard.", "error")
        return redirect(url_for("home"))


# -----------------------------------------
# EMPLOYEE LEAVE REQUESTS
# -----------------------------------------
@app.route("/manager_requests")
def manager_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "manager":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        manager_doc = db_firestore.collection("users").document(session["user_id"]).get()
        manager = to_dict_with_id(manager_doc)
        manager_dept = (manager.get("department") or "").strip().lower()

        search = request.args.get("search", "").strip().lower()

        users_docs = db_firestore.collection("users").get()
        users_dict = {u.id: to_dict_with_id(u) for u in users_docs}

        reqs_docs = db_firestore.collection("leave_requests").get()
        all_requests = []

        pending_cnt = 0
        approved_cnt = 0
        rejected_cnt = 0

        for doc in reqs_docs:
            d = to_dict_with_id(doc)
            if d.get("approval_level") == "manager":
                emp_id = d.get("employee_id")
                emp_data = users_dict.get(emp_id, {})
                if emp_data.get("role") != "employee":
                    continue

                emp_dept = (emp_data.get("department") or "").strip().lower()
                # Filter by department: allow empty department to be viewed by all managers
                if emp_dept and emp_dept != manager_dept:
                    continue

                status = d.get("status", "Pending")
                if status == "Pending":
                    pending_cnt += 1
                elif status == "Approved":
                    approved_cnt += 1
                elif status == "Rejected":
                    rejected_cnt += 1

                d["employee_name"] = emp_data.get("full_name", "Unknown")
                d["employee_code"] = emp_data.get("employee_id", "Unknown")
                d["casual_leave"] = emp_data.get("casual_leave", 6)
                d["sick_leave"] = emp_data.get("sick_leave", 6)
                d["annual_leave"] = emp_data.get("annual_leave", 12)

                if search:
                    code_match = search in d["employee_code"].lower()
                    name_match = search in d["employee_name"].lower()
                    if not (code_match or name_match):
                        continue

                all_requests.append(d)

        # Resolve deciders
        resolve_deciders(all_requests, users_dict)

        # Sort: pending first, then submitted_on desc
        # Using stable sort:
        all_requests.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)
        all_requests.sort(key=lambda x: 0 if x.get("status") == "Pending" else 1)

        # Filter total employee count to match manager's department (including unassigned department employees)
        total_employees = sum(
            1 for u in users_dict.values()
            if u.get("role") == "employee" and (not (u.get("department") or "").strip() or (u.get("department") or "").strip().lower() == manager_dept)
        )

        stats = {
            "total_employees": total_employees,
            "pending": pending_cnt,
            "approved": approved_cnt,
            "rejected": rejected_cnt
        }

        return render_template(
            "manager_requests.html",
            all_requests=all_requests,
            stats=stats
        )
    except Exception as e:
        print(f"Manager requests loading error: {e}")
        flash("Could not load employee requests.", "error")
        return redirect(url_for("manager_dashboard"))


# -----------------------------------------
# MANAGER LEAVE DASHBOARD
# -----------------------------------------
@app.route("/manager_leave")
def manager_leave():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "manager":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        user_doc = db_firestore.collection("users").document(session["user_id"]).get()
        user = to_dict_with_id(user_doc)

        docs = db_firestore.collection("leave_requests").where("employee_id", "==", session["user_id"]).stream()
        requests = [to_dict_with_id(d) for d in docs]
        
        users_docs = db_firestore.collection("users").get()
        users_dict = {u.id: to_dict_with_id(u) for u in users_docs}
        resolve_deciders(requests, users_dict)

        requests.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)

        today = date.today()
        max_date = (today + timedelta(days=180)).strftime("%Y-%m-%d")
        today = today.strftime("%Y-%m-%d")

        return render_template(
            "manager_leave.html",
            requests=requests,
            user=user,
            today=today,
            max_date=max_date
        )
    except Exception as e:
        print(f"Manager leave portal error: {e}")
        flash("Could not load dashboard data.", "error")
        return redirect(url_for("manager_dashboard"))


# -----------------------------------------
# ADMIN DASHBOARD
# -----------------------------------------
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        admin_doc = db_firestore.collection("users").document(session["user_id"]).get()
        admin = to_dict_with_id(admin_doc)

        users_docs = db_firestore.collection("users").get()
        users = [to_dict_with_id(u) for u in users_docs]

        role_order = {"admin": 1, "manager": 2, "employee": 3}
        users.sort(key=lambda x: (role_order.get(x.get("role") or "employee", 3), (x.get("full_name") or "").lower()))

        total_employees = sum(1 for u in users if u.get("role") == "employee")
        total_managers = sum(1 for u in users if u.get("role") == "manager")

        reqs_docs = db_firestore.collection("leave_requests").get()
        reqs = [to_dict_with_id(r) for r in reqs_docs]

        employee_pending = sum(1 for r in reqs if r.get("approval_level") == "manager" and r.get("status") == "Pending")
        employee_approved = sum(1 for r in reqs if r.get("approval_level") == "manager" and r.get("status") == "Approved")
        employee_rejected = sum(1 for r in reqs if r.get("approval_level") == "manager" and r.get("status") == "Rejected")

        manager_pending = sum(1 for r in reqs if r.get("approval_level") == "admin" and r.get("status") == "Pending")
        manager_approved = sum(1 for r in reqs if r.get("approval_level") == "admin" and r.get("status") == "Approved")
        manager_rejected = sum(1 for r in reqs if r.get("approval_level") == "admin" and r.get("status") == "Rejected")

        stats = {
            "total_employees": total_employees,
            "total_managers": total_managers,
            "employee_pending": employee_pending,
            "employee_approved": employee_approved,
            "employee_rejected": employee_rejected,
            "manager_pending": manager_pending,
            "manager_approved": manager_approved,
            "manager_rejected": manager_rejected
        }

        # Recent leave requests (both employee and manager requests)
        users_dict = {u["id"]: u for u in users}
        recent_requests = []
        for r in reqs:
            if r.get("approval_level") in ["admin", "manager"]:
                emp_id = r.get("employee_id")
                emp_data = users_dict.get(emp_id, {})
                r["full_name"] = emp_data.get("full_name", "Unknown")
                recent_requests.append(r)

        resolve_deciders(recent_requests, users_dict)

        recent_requests.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)
        recent_requests = recent_requests[:5]

        return render_template(
            "admin_dashboard.html",
            admin=admin,
            users=users,
            stats=stats,
            recent_requests=recent_requests
        )
    except Exception as e:
        print(f"Admin dashboard loading error: {e}")
        flash("Could not load admin dashboard.", "error")
        return redirect(url_for("home"))


# -----------------------------------------
# ADMIN - MANAGE EMPLOYEES & USERS DIRECTORY
# -----------------------------------------
@app.route("/manage_employees")
def manage_employees():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        role_filter = request.args.get("role", "all").strip().lower()
        search_query = request.args.get("search", "").strip().lower()

        users_docs = db_firestore.collection("users").get()
        users = [to_dict_with_id(u) for u in users_docs]

        role_order = {"admin": 1, "manager": 2, "employee": 3}
        users.sort(key=lambda x: (role_order.get(x.get("role") or "employee", 3), (x.get("full_name") or "").lower()))

        # Filter by role
        if role_filter != "all":
            users = [u for u in users if u.get("role") == role_filter]

        # Filter by search query
        if search_query:
            users = [u for u in users if search_query in (u.get("employee_id") or "").lower() or search_query in (u.get("full_name") or "").lower()]

        # Calculate pending leave requests stats for navbar badge
        reqs_docs = db_firestore.collection("leave_requests").get()
        reqs = [to_dict_with_id(r) for r in reqs_docs]
        employee_pending = sum(1 for r in reqs if r.get("approval_level") == "manager" and r.get("status") == "Pending")
        manager_pending = sum(1 for r in reqs if r.get("approval_level") == "admin" and r.get("status") == "Pending")
        stats = {
            "employee_pending": employee_pending,
            "manager_pending": manager_pending
        }

        return render_template("manage_employees.html", users=users, role_filter=role_filter, stats=stats)
    except Exception as e:
        print(f"Manage employees error: {e}")
        flash("Could not load employee management.", "error")
        return redirect(url_for("admin_dashboard"))


# -----------------------------------------
# ADMIN - EDIT EMPLOYEE DETAILS
# -----------------------------------------
@app.route("/edit_employee/<string:user_id>", methods=["GET", "POST"])
def edit_employee(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        user_ref = db_firestore.collection("users").document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            flash("User not found.", "error")
            return redirect(url_for("admin_dashboard"))

        user = to_dict_with_id(user_doc)
        if user["employee_id"] == "ADMIN001":
            flash("System Admin account cannot be edited.", "error")
            return redirect(url_for("admin_dashboard"))

        if request.method == "POST":
            full_name = request.form["full_name"]
            email = request.form["email"]
            phone = request.form["phone"]
            department = request.form["department"]
            designation = request.form["designation"]
            casual_leave = int(request.form["casual_leave"])
            sick_leave = int(request.form["sick_leave"])
            annual_leave = int(request.form["annual_leave"])
            role = request.form["role"].strip().lower()

            if role not in ["employee", "manager", "admin"]:
                flash("Invalid role selection.", "error")
                return redirect(url_for("admin_dashboard"))

            user_ref.update({
                "full_name": full_name,
                "email": email,
                "phone": phone,
                "department": department,
                "designation": designation,
                "casual_leave": casual_leave,
                "sick_leave": sick_leave,
                "annual_leave": annual_leave,
                "role": role
            })
            flash("User updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))

        return render_template("admin_edit_user.html", user=user, admin_edit=True)
    except Exception as e:
        print(f"Edit employee error: {e}")
        flash("An error occurred.", "error")
        return redirect(url_for("admin_dashboard"))


# -----------------------------------------
# ADMIN - MANAGER LEAVE REQUESTS
# -----------------------------------------
@app.route("/admin_requests")
def admin_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("login"))

    try:
        users_docs = db_firestore.collection("users").get()
        users_dict = {u.id: to_dict_with_id(u) for u in users_docs}

        reqs_docs = db_firestore.collection("leave_requests").get()

        pending_requests = []
        decision_history = []
        pending_cnt = 0

        for doc in reqs_docs:
            r = to_dict_with_id(doc)
            if r.get("approval_level") in ["admin", "manager"]:
                emp_id = r.get("employee_id")
                emp_data = users_dict.get(emp_id, {})
                r["full_name"] = emp_data.get("full_name", "Unknown")
                # Set employee_id as the employee string code (e.g. MGR001) for the template display
                r["employee_id"] = emp_data.get("employee_id", "Unknown")
                r["employee_role"] = emp_data.get("role", "employee")

                if r.get("status") == "Pending":
                    pending_cnt += 1
                    pending_requests.append(r)
                else:
                    decision_history.append(r)

        # Sort lists
        resolve_deciders(decision_history, users_dict)
        pending_requests.sort(key=lambda x: x.get("submitted_on") or "", reverse=True)
        decision_history.sort(key=lambda x: x.get("decision_date") or "", reverse=True)
        decision_history = decision_history[:10]

        stats = {
            "pending_manager_requests": pending_cnt
        }

        return render_template(
            "admin_requests.html",
            pending_requests=pending_requests,
            decision_history=decision_history,
            stats=stats
        )
    except Exception as e:
        print(f"Admin requests loading error: {e}")
        flash("Could not load requests.", "error")
        return redirect(url_for("admin_dashboard"))


# -----------------------------------------
# TOGGLE USER STATUS
# -----------------------------------------
@app.route("/toggle_user/<string:user_id>")
def toggle_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "admin":
        return redirect(url_for("login"))

    if user_id == session["user_id"]:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin_dashboard"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        user_ref = db_firestore.collection("users").document(user_id)
        user_doc = user_ref.get()
        if user_doc.exists:
            current_status = user_doc.to_dict().get("is_active", 1)
            new_status = 0 if current_status == 1 else 1
            user_ref.update({"is_active": new_status})
            flash("User status updated successfully.", "success")
        else:
            flash("User not found.", "error")
    except Exception as e:
        print(f"Toggle user error: {e}")
        flash("Could not update user status.", "error")

    return redirect(url_for("admin_dashboard"))


# -----------------------------------------
# APPROVE / REJECT LEAVE (MANAGER ACTION)
# -----------------------------------------
@app.route("/action/<string:request_id>", methods=["POST"])
def take_action(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "manager":
        return redirect(url_for("login"))

    action = request.form.get("action")
    if action not in ["Approved", "Rejected"]:
        flash("Invalid action.", "error")
        return redirect(url_for("manager_requests"))

    comment = request.form.get("comment", "")

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("manager_requests"))

    try:
        req_ref = db_firestore.collection("leave_requests").document(request_id)
        req_doc = req_ref.get()
        if not req_doc.exists:
            flash("Leave request not found.", "error")
            return redirect(url_for("manager_requests"))

        leave = to_dict_with_id(req_doc)

        # Get manager's department
        manager_doc = db_firestore.collection("users").document(session["user_id"]).get()
        manager = to_dict_with_id(manager_doc)
        manager_dept = (manager.get("department") or "").strip().lower()

        # Get employee's department
        emp_id = leave["employee_id"]
        user_ref = db_firestore.collection("users").document(emp_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            flash("Employee user not found.", "error")
            return redirect(url_for("manager_requests"))

        user = to_dict_with_id(user_doc)
        emp_dept = (user.get("department") or "").strip().lower()

        # Enforce department match
        if emp_dept != manager_dept:
            flash("Unauthorized: You do not manage this employee's department.", "error")
            return redirect(url_for("manager_requests"))

        if leave["approval_level"] != "manager":
            flash("Invalid approval request.", "error")
            return redirect(url_for("manager_requests"))

        if leave["status"] != "Pending":
            flash("Request already processed.", "error")
            return redirect(url_for("manager_requests"))

        decision_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        if action == "Approved":
            leave_type = leave["leave_type"]
            total_days = leave["total_days"]
            leave_map = {
                "Casual Leave": "casual_leave",
                "Sick Leave": "sick_leave",
                "Annual Leave": "annual_leave"
            }

            if leave_type in leave_map:
                col = leave_map[leave_type]
                current_balance = user.get(col, 0)

                if current_balance < total_days:
                    flash("Insufficient leave balance for the employee.", "error")
                    return redirect(url_for("manager_requests"))

                # Decrement balance
                user_ref.update({col: current_balance - total_days})

        # Update Request Status
        req_ref.update({
            "status": action,
            "manager_comment": comment,
            "decision_date": decision_date,
            "approved_by": session["user_id"]
        })

        # Send notification to Employee
        try:
            send_notification(
                leave["employee_id"],
                f"Leave {action}",
                f"Your {leave['leave_type']} request has been {action.lower()} by the manager.",
                "success" if action == "Approved" else "error"
            )
        except Exception as e_notif:
            print(f"Employee notification error: {e_notif}")

        flash(f"Request {action} successfully!", "success")
    except Exception as e:
        print(f"Approve/reject error: {e}")
        flash("Could not process leave request.", "error")

    return redirect(url_for("manager_requests"))


# -----------------------------------------
# ADMIN APPROVE / REJECT MANAGER LEAVE
# -----------------------------------------
@app.route("/admin_action/<string:request_id>", methods=["POST"])
def admin_action(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "admin":
        return redirect(url_for("login"))

    action = request.form.get("action")
    if action not in ["Approved", "Rejected"]:
        flash("Invalid action.", "error")
        return redirect(url_for("admin_requests"))

    comment = request.form.get("comment", "")

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("admin_requests"))

    try:
        req_ref = db_firestore.collection("leave_requests").document(request_id)
        req_doc = req_ref.get()
        if not req_doc.exists:
            flash("Leave request not found.", "error")
            return redirect(url_for("admin_requests"))

        leave = to_dict_with_id(req_doc)

        if leave["approval_level"] not in ["admin", "manager"]:
            flash("Invalid approval request.", "error")
            return redirect(url_for("admin_requests"))

        if leave["status"] != "Pending":
            flash("Request already processed.", "error")
            return redirect(url_for("admin_requests"))

        decision_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        if action == "Approved":
            leave_type = leave["leave_type"]
            total_days = leave["total_days"]
            emp_id = leave["employee_id"]

            user_ref = db_firestore.collection("users").document(emp_id)
            user_doc = user_ref.get()
            if not user_doc.exists:
                flash("User not found.", "error")
                return redirect(url_for("admin_requests"))

            user = to_dict_with_id(user_doc)
            leave_map = {
                "Casual Leave": "casual_leave",
                "Sick Leave": "sick_leave",
                "Annual Leave": "annual_leave"
            }

            if leave_type in leave_map:
                col = leave_map[leave_type]
                current_balance = user.get(col, 0)
                if current_balance < total_days:
                    flash("Insufficient leave balance for the user.", "error")
                    return redirect(url_for("admin_requests"))
                user_ref.update({col: current_balance - total_days})

        # Update Request Status
        req_ref.update({
            "status": action,
            "manager_comment": comment,
            "decision_date": decision_date,
            "approved_by": session["user_id"]
        })

        # Send notification to applicant (Manager or Employee)
        try:
            send_notification(
                leave["employee_id"],
                f"Leave {action}",
                f"Your {leave['leave_type']} request has been {action.lower()} by the admin.",
                "success" if action == "Approved" else "error"
            )
        except Exception as e_notif:
            print(f"Applicant notification error: {e_notif}")

        # If the applicant is an employee, notify the department manager too
        try:
            applicant_ref = db_firestore.collection("users").document(leave["employee_id"])
            applicant_doc = applicant_ref.get()
            if applicant_doc.exists:
                applicant = to_dict_with_id(applicant_doc)
                if applicant.get("role") == "employee":
                    emp_dept = applicant.get("department", "")
                    if emp_dept:
                        managers = db_firestore.collection("users")\
                            .where("role", "==", "manager")\
                            .where("department", "==", emp_dept)\
                            .get()
                    else:
                        # Notify all managers if employee has no department assigned
                        managers = db_firestore.collection("users")\
                            .where("role", "==", "manager")\
                            .get()
                        for mgr in managers:
                            send_notification(
                                mgr.id,
                                "Leave Request Processed by Admin",
                                f"Admin has {action.lower()} the leave request for {applicant['full_name']} ({leave['leave_type']}).",
                                "info"
                            )
        except Exception as e_mgr_notif:
            print(f"Manager notification error: {e_mgr_notif}")

        flash(f"Leave request {action.lower()} successfully.", "success")
    except Exception as e:
        print(f"Admin action error: {e}")
        flash("Could not process request.", "error")

    return redirect(url_for("admin_requests"))


# -----------------------------------------
# EXPORT CSV REPORT
# -----------------------------------------
@app.route("/export_csv")
def export_csv():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] != "manager":
        return redirect(url_for("login"))

    if not FIREBASE_ENABLED or db_firestore is None:
        flash("Database service unavailable.", "error")
        return redirect(url_for("manager_dashboard"))

    try:
        manager_doc = db_firestore.collection("users").document(session["user_id"]).get()
        manager = to_dict_with_id(manager_doc)
        manager_dept = (manager.get("department") or "").strip().lower()

        users_docs = db_firestore.collection("users").get()
        users_dict = {u.id: to_dict_with_id(u) for u in users_docs}

        reqs_docs = db_firestore.collection("leave_requests").get()

        csv_data = "Employee Name,Employee ID,Leave Type,Start Date,End Date,Days,Status,Manager Comment,Decision Date\n"
        for doc in reqs_docs:
            lr = to_dict_with_id(doc)
            emp_id = lr.get("employee_id")
            emp_data = users_dict.get(emp_id, {})
            emp_dept = (emp_data.get("department") or "").strip().lower()

            if emp_data.get("role") == "employee" and emp_dept == manager_dept:
                csv_data += (
                    f"{emp_data.get('full_name', 'Unknown')},"
                    f"{emp_data.get('employee_id', 'Unknown')},"
                    f"{lr.get('leave_type', '')},"
                    f"{lr.get('start_date', '')},"
                    f"{lr.get('end_date', '')},"
                    f"{lr.get('total_days', 0)},"
                    f"{lr.get('status', 'Pending')},"
                    f"{lr.get('manager_comment', '')},"
                    f"{lr.get('decision_date', '')}\n"
                )

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=leave_report.csv"
            }
        )
    except Exception as e:
        print(f"CSV export error: {e}")
        flash("Could not export leave data.", "error")
        return redirect(url_for("manager_dashboard"))


# -----------------------------------------
# FIREBASE NOTIFICATIONS AND UTILS
# -----------------------------------------
def send_notification(user_id, title, message, notif_type="info"):
    """Save a notification to Firestore for a specific user."""
    if not FIREBASE_ENABLED or db_firestore is None:
        return
    try:
        db_firestore.collection("notifications").add({
            "user_id": str(user_id),
            "title": title,
            "message": message,
            "type": notif_type,
            "read": False,
            "created_at": firestore.SERVER_TIMESTAMP
        })
    except Exception as e:
        print(f"Notification error: {e}")


# -----------------------------------------
# GOOGLE LOGIN ROUTE
# -----------------------------------------
@app.route("/google_login", methods=["POST"])
def google_login():
    data = request.get_json()
    id_token = data.get("id_token")

    if not id_token:
        return jsonify({"success": False, "message": "No token provided."})

    if not FIREBASE_ENABLED or db_firestore is None:
        return jsonify({"success": False, "message": "Google login is not configured on the server."})

    try:
        # Verify the Firebase ID token
        decoded_token = firebase_auth.verify_id_token(id_token)
        email = decoded_token.get("email")

        if not email:
            return jsonify({"success": False, "message": "Could not get email from Google account."})

        # Check if user exists in Firestore
        user_docs = db_firestore.collection("users").where("email", "==", email).limit(1).get()
        if len(user_docs) == 0:
            return jsonify({
                "success": False,
                "message": f"No account found with email '{email}'. Please sign up first or use a different Google account."
            })

        user = to_dict_with_id(user_docs[0])

        if user.get("is_active", 1) == 0:
            return jsonify({"success": False, "message": "Your account has been deactivated."})

        # Log the user in via Flask session
        session["user_id"] = user["id"]
        session["employee_id"] = user["employee_id"]
        session["full_name"] = user["full_name"]
        session["role"] = user["role"]

        # Redirect based on role
        if user["role"] == "admin":
            redirect_url = url_for("admin_dashboard")
        elif user["role"] == "manager":
            redirect_url = url_for("manager_dashboard")
        else:
            redirect_url = url_for("employee_dashboard")

        return jsonify({"success": True, "redirect": redirect_url})

    except firebase_auth.InvalidIdTokenError:
        return jsonify({"success": False, "message": "Invalid Google token. Please try again."})
    except Exception as e:
        print(f"Google login error: {e}")
        return jsonify({"success": False, "message": "Google login failed. Please try again."})


# -----------------------------------------
# GET NOTIFICATIONS (for bell icon)
# -----------------------------------------
@app.route("/get_notifications")
def get_notifications():
    if "user_id" not in session:
        return jsonify([])

    if not FIREBASE_ENABLED or db_firestore is None:
        return jsonify([])

    try:
        # Avoid composite indices by filtering and then sorting in python
        notifs_ref = db_firestore.collection("notifications")\
            .where("user_id", "==", str(session["user_id"]))\
            .where("read", "==", False)\
            .limit(100)

        docs = notifs_ref.stream()
        notifications = []
        for doc in docs:
            d = doc.to_dict()
            notifications.append({
                "id": doc.id,
                "title": d.get("title", ""),
                "message": d.get("message", ""),
                "type": d.get("type", "info"),
                # Store created_at for sorting; handle cases where ServerTimestamp is still pending local resolution
                "created_at": d.get("created_at") or datetime.now()
            })

        # Sort in python
        notifications.sort(key=lambda x: x.get("created_at") or datetime.now(), reverse=True)
        # Limit to 10
        notifications = notifications[:10]

        # Strip internal timestamps before json output
        for n in notifications:
            if "created_at" in n:
                del n["created_at"]

        return jsonify(notifications)
    except Exception as e:
        print(f"Get notifications error: {e}")
        return jsonify([])


# -----------------------------------------
# MARK NOTIFICATIONS AS READ
# -----------------------------------------
@app.route("/mark_notifications_read", methods=["POST"])
def mark_notifications_read():
    if "user_id" not in session:
        return jsonify({"success": False})

    if not FIREBASE_ENABLED or db_firestore is None:
        return jsonify({"success": False})

    try:
        notifs_ref = db_firestore.collection("notifications")\
            .where("user_id", "==", str(session["user_id"]))\
            .where("read", "==", False)

        docs = notifs_ref.stream()
        batch = db_firestore.batch()
        count = 0
        for doc in docs:
            batch.update(doc.reference, {"read": True})
            count += 1
            if count >= 500:  # Firestore batch limits updates to 500
                break
        if count > 0:
            batch.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(f"Mark read error: {e}")
        return jsonify({"success": False})


# START APPLICATION
# -----------------------------------------
_db_initialized = False

@app.before_request
def initialize_database_lazy():
    global _db_initialized
    if not _db_initialized:
        init_db()
        _db_initialized = True


if __name__ == "__main__":
    print("\n Employee Leave Portal Running (Firebase Mode)")
    print("http://127.0.0.1:5000\n")
    app.run(host="0.0.0.0", port=5000)