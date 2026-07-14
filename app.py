from flask import Flask, render_template
from parser.parser import parse_logs

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
        alerts=results["alerts"]
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)