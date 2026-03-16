from flask import Flask, render_template, request
from analyzer import analyze_target
import sqlite3

app = Flask(__name__)

conn = sqlite3.connect("threats.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
id INTEGER PRIMARY KEY AUTOINCREMENT,
ip TEXT,
score INTEGER,
level TEXT,
country TEXT
)
""")

conn.commit()


@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        ip = request.form["ip"]

        result = analyze_target(ip)

        cursor.execute(
            "INSERT INTO scans (ip, score, level, country) VALUES (?, ?, ?, ?)",
            (result["ip"], result["score"], result["threat_level"], result["country"])
        )

        conn.commit()


    cursor.execute("SELECT ip, score, level, country FROM scans")

    rows = cursor.fetchall()

    history = []

    for r in rows:

        history.append({
            "ip": r[0],
            "score": r[1],
            "threat_level": r[2],
            "country": r[3]
            })


    high = len([h for h in history if h["threat_level"] == "HIGH"])
    medium = len([h for h in history if h["threat_level"] == "MEDIUM"])
    low = len([h for h in history if h["threat_level"] == "LOW"])


    return render_template(
        "index.html",
        result=result,
        history=history,
        high=high,
        medium=medium,
        low=low
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
