import os
import csv

from flask import Flask, render_template, request, send_file

from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors

from parser.parser import parse_logs

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(
    __name__,
    template_folder="app/templates",
    static_folder="app/static"
)

@app.route("/")
def home():
    # Parse logs and analyze them
    results = parse_logs()

    # Send data to the HTML template
    return render_template(
        "index.html",
        total_logs=results["total_logs"],
        failed_logins=results["failed_logins"],
        brute_force_ips=results["brute_force_ips"],
        alerts=results["alerts"],
        status_counts=results["status_counts"],
        attack_summary=results["attack_summary"],
        dashboard_stats=results["dashboard_stats"],
    )
@app.route("/upload", methods=["POST"])
def upload():

    uploaded_file = request.files["logfile"]

    # Validate the uploaded file
    if uploaded_file.filename == "":
        return "No file selected."

    if not uploaded_file.filename.lower().endswith(".log"):
        return "Please upload a .log file."

    upload_folder = "app/uploads"

    os.makedirs(upload_folder, exist_ok=True)

    file_path = os.path.join(upload_folder, uploaded_file.filename)

    uploaded_file.save(file_path)

    results = parse_logs(file_path)

    return render_template(
    "index.html",
    total_logs=results["total_logs"],
    failed_logins=results["failed_logins"],
    brute_force_ips=results["brute_force_ips"],
    alerts=results["alerts"],
    status_counts=results["status_counts"],
    attack_summary=results["attack_summary"],
    dashboard_stats=results.get("dashboard_stats", {})
    )
@app.route("/export/csv")
def export_csv():

    results = parse_logs()

    export_folder = "app/exports"
    os.makedirs(export_folder, exist_ok=True)

    file_path = os.path.join(export_folder, "security_report.csv")

    with open(file_path, "w", newline="") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "Severity",
            "Attack Type",
            "IP Address",
            "URL"
        ])

        for alert in results["alerts"]:

            writer.writerow([
                alert["severity"],
                alert["type"],
                alert["ip"],
                alert["url"]
            ])

    return send_file(file_path, as_attachment=True)

@app.route("/export/pdf")
def export_pdf():

    results = parse_logs()

    export_folder = "app/exports"
    os.makedirs(export_folder, exist_ok=True)

    file_path = os.path.join(export_folder, "security_report.pdf")

    doc = SimpleDocTemplate(file_path)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph("<b>LogLens Security Report</b>", styles["Title"])
    )

    elements.append(
        Paragraph(
            f"Total Logs: {results['total_logs']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Total Alerts: {len(results['alerts'])}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph("<br/>", styles["Normal"])
    )

    data = [
        ["Severity", "Attack Type", "IP Address", "URL"]
    ]

    for alert in results["alerts"]:

        data.append([
            alert["severity"],
            alert["type"],
            alert["ip"],
            alert["url"]
        ])

    table = Table(data)

    table.setStyle(TableStyle([

        ("BACKGROUND", (0,0), (-1,0), colors.darkblue),

        ("TEXTCOLOR", (0,0), (-1,0), colors.white),

        ("GRID", (0,0), (-1,-1), 1, colors.black),

        ("BACKGROUND", (0,1), (-1,-1), colors.beige),

        ("ALIGN", (0,0), (-1,-1), "CENTER"),

        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

        ("BOTTOMPADDING", (0,0), (-1,0), 10),

    ]))

    elements.append(table)

    doc.build(elements)

    return send_file(file_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)