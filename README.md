# 📋 LeaveDesk – Employee Leave Portal

A simple leave request portal built with **Flask + SQLite**.
Perfect for you since you already know Flask!

---

## 🗂️ Project Structure

```
leave-portal/
│
├── app.py                  ← Main Flask app (all routes + DB logic)
├── requirements.txt        ← Just one dependency: Flask
├── leave_portal.db         ← Auto-created SQLite database (after first run)
│
└── templates/
    ├── login.html               ← Login page
    ├── employee_dashboard.html  ← Employee: submit & view requests
    └── manager_dashboard.html   ← Manager: approve/reject requests
```

---

## ▶️ How to Run (in 3 steps)

**Step 1 — Install Flask** (one time only)
```bash
pip install flask
```

**Step 2 — Go into the project folder**
```bash
cd leave-portal
```

**Step 3 — Run the app**
```bash
python app.py
```

Then open your browser: **http://127.0.0.1:5000**

---

## 🧪 Test Accounts (pre-loaded)

| Role     | Username   | Password     |
|----------|------------|--------------|
| Employee | emp1       | pass123      |
| Employee | emp2       | pass123      |
| Manager  | manager1   | manager123   |

---

## 🔄 How the Workflow Works

1. **Employee logs in** → sees a form to apply for leave + table of past requests
2. **Employee submits** leave type, dates, and reason
3. **Manager logs in** → sees all requests with Pending/Approved/Rejected tabs
4. **Manager clicks Approve or Reject** → optionally adds a comment
5. **Employee refreshes** their dashboard → sees the updated status + manager's comment

---

## 🧠 Understanding app.py (Flask basics you know)

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    # GET  = show the login page
    # POST = process the submitted form
```

- `session` = stores who is logged in (like a cookie)
- `flash()` = shows success/error messages on the page
- `sqlite3` = simple file-based database, no server needed
- `render_template()` = send HTML file to the browser (same as Flask always)

---

## 🔧 How to Add a New Employee

Open `app.py`, find the `sample_users` list in `init_db()`, and add:
```python
("newuser", "theirpassword", "Full Name", "employee"),
```
Then restart the app. ✅

Or add via Python shell:
```python
import sqlite3
conn = sqlite3.connect("leave_portal.db")
conn.execute("INSERT INTO users (username, password, full_name, role) VALUES (?,?,?,?)",
             ("alice", "pass456", "Alice Johnson", "employee"))
conn.commit()
```
