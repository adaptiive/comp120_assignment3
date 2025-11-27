# 📡 WiFi Speed Test Web App# WiFi Tester Web App



A beautiful and modern web application to test your WiFi connection speed using Python Flask and the speedtest-cli library.A simple web application built with Python Flask to test WiFi connectivity and network performance.



![WiFi Speed Test](https://img.shields.io/badge/WiFi-Speed%20Test-blue?style=for-the-badge)## Features

![Python](https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge&logo=python)

![Flask](https://img.shields.io/badge/Flask-2.3+-red?style=for-the-badge&logo=flask)🌐 **Internet Connectivity Test**

- Tests basic internet connection to Google

## ✨ Features- Shows response time and status



# � WiFi Speed Test Web App

A Flask-based web app that runs internet speed tests (download, upload, ping) using the speedtest-cli library and provides role-based dashboards for Home Users, IT Administrators, and ISP Support.

Features
--------
- Role-based UI and API endpoints (Home User, IT Admin, ISP Support)
- Background speed testing (non-blocking)
- In-memory history of the last 50 tests (replaceable with a database)
- Diagnostics, export, and shareable report endpoints

Getting started
---------------
1. Create and activate a Python virtual environment (recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the app (development):

```powershell
python app.py
```

4. Open http://127.0.0.1:5000 in your browser.

Notes
-----
- History is stored in memory for simplicity. Use a database (SQLite, Postgres) for persistence in production.
- The speed test runs in a background thread and receives the selected user role when started (avoids accessing Flask session from background threads).

User roles
----------
- Home User: simplified UI, one-click tests.
- IT Administrator: access to history, diagnostics, export, and clear history.
- ISP Support: can generate shareable reports for customers.

Next steps
----------
- Add persistence (SQLite) and authentication.
- Add unit tests and CI pipeline.

License
-------
MIT

Made with ❤️ using Python and Flask.