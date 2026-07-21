# 🛡️ LogLens

**A Flask-based Security Log Analysis Dashboard for Detecting Suspicious Web Server Activities**

---

## 📖 Overview

LogLens is a web-based cybersecurity dashboard built with **Python** and **Flask** that analyzes Apache and Nginx access logs to detect common web attacks and visualize security events.

The application enables users to upload server log files, automatically identify suspicious activities, explore attack statistics through interactive charts, search and filter alerts, and export analysis reports in CSV and PDF formats.

This project was developed as a portfolio project to demonstrate practical skills in **Python**, **Flask**, **Cybersecurity**, and **Web Development**.

---

## ✨ Features

### 🛡️ Attack Detection

* Failed Login Detection
* Brute Force Detection
* SQL Injection Detection
* Cross-Site Scripting (XSS) Detection
* Directory Traversal Detection

### 📊 Interactive Dashboard

* Dashboard statistics cards
* HTTP Status Code Distribution (Bar Chart)
* Attack Summary (Pie Chart)
* Recent Security Alerts
* Top Attacking IP Addresses
* Most Targeted URLs

### 🔎 Search & Filtering

* Live alert search
* Filter by Severity
* Filter by Attack Type

### 📄 Report Generation

* Export analysis as CSV
* Export analysis as PDF

---

## 🖥️ Dashboard

![Dashboard](https://raw.githubusercontent.com/sourav2442/LogLens/main/Screenshots/dashboard.png)

---

## 📊 Charts

![Charts](https://raw.githubusercontent.com/sourav2442/LogLens/main/Screenshots/charts.png)

---

## 🔍 Search & Filters

![Search](https://raw.githubusercontent.com/sourav2442/LogLens/main/Screenshots/search.png)

![Filters](https://raw.githubusercontent.com/sourav2442/LogLens/main/Screenshots/filters.png)

---

## 📈 Analytics

![Analytics](https://raw.githubusercontent.com/sourav2442/LogLens/main/Screenshots/analytics.png)

---

## 📄 Reports

![Reports](https://raw.githubusercontent.com/sourav2442/LogLens/main/Screenshots/reports.png)

## 🏗️ Project Structure

```text
LogLens/
│
├── app/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   │
│   │   └── js/
│   │       ├── charts.js
│   │       └── search.js
│   │
│   ├── templates/
│   │   └── index.html
│   │
│   ├── sample_logs/
│   │   └── access.log
│   │
│   ├── uploads/
│   │   └── .gitkeep
│   │
│   ├── reports/
│   │   └── .gitkeep
│   │
│   └── exports/
│       └── security_report.pdf   (generated automatically)
│
├── detector/
│   ├── __init__.py
│   └── detector.py
│
├── parser/
│   ├── __init__.py
│   └── parser.py
│
├── Screenshots/
│   ├── dashboard.png
│   ├── analytics.png
│   ├── charts.png
│   ├── filters.png
│   ├── reports.png
│   └── search.png
│
├── tests/
│
├── .gitignore
├── app.py
├── README.md
├── requirements.txt
```

---

## 🛠️ Technologies Used

| Category        | Technologies                     |
| --------------- | -------------------------------- |
| Backend         | Python, Flask                    |
| Frontend        | HTML, CSS, Bootstrap, JavaScript |
| Charts          | Chart.js                         |
| Reports         | ReportLab, CSV                   |
| Version Control | Git, GitHub                      |

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/LogLens.git
```

Move into the project:

```bash
cd LogLens
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the environment:

### Windows

```bash
venv\Scripts\activate
```

### Linux/macOS

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5001
```

---

## 📋 Usage

1. Launch the Flask application.
2. Upload an Apache or Nginx access log.
3. Review the detected attacks and dashboard statistics.
4. Use the search box and filters to analyze alerts.
5. Export the results as CSV or PDF reports.

---

## 🔮 Future Improvements

* User authentication
* Database integration
* Real-time log monitoring
* Email notifications
* Threat intelligence feeds
* Machine learning-based anomaly detection
* Docker support
* REST API

---

## 🎓 Learning Outcomes

Through this project, I gained experience with:

* Flask application development
* Python log parsing
* Basic web attack detection
* Data visualization
* File uploads
* Report generation
* Git version control
* Frontend development using Bootstrap and JavaScript

---

## 📜 License

This project is intended for educational and portfolio purposes.

---

## 👨‍💻 Author

**Sourav Chauuhan**

B.Tech Computer Science & Engineering Student

Aspiring Cybersecurity Engineer
