# ATTENZIONE: applicazione volutamente vulnerabile, solo per collaudare scanner di sicurezza.
import os, sqlite3, pickle, hashlib, random, subprocess, base64, yaml, requests
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, render_template_string, send_file, make_response
import jwt

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key-123"          # VULN-P01 secret hardcoded
DB = "shop.db"
AWS_ACCESS_KEY_ID = "AKIAQ7RTXM4PLB2KNZ6V"                  # VULN-P02 chiave AWS finta
AWS_SECRET_ACCESS_KEY = "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"  # VULN-P03
GITHUB_TOKEN = "ghp_9fK2mQxL7vR4tYbN8cZ1wDpS6aHjE3uGoXiT"   # VULN-P04

def db():
    return sqlite3.connect(DB)

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["user"], request.form["pass"]
    q = "SELECT * FROM users WHERE name='%s' AND pw='%s'" % (u, hashlib.md5(p.encode()).hexdigest())  # VULN-P05 SQLi, VULN-P06 MD5
    row = db().execute(q).fetchone()
    if row:
        return jwt.encode({"user": u}, app.config["SECRET_KEY"], algorithm="HS256")
    return "KO", 401

@app.route("/search")
def search():
    term = request.args.get("q", "")
    return render_template_string("<h1>Risultati per " + term + "</h1>")  # VULN-P07 SSTI/XSS

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)  # VULN-P08 command injection

@app.route("/file")
def read_file():
    return send_file("/srv/files/" + request.args["name"])  # VULN-P09 path traversal

@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text  # VULN-P10 SSRF, VULN-P11 TLS off

@app.route("/import", methods=["POST"])
def import_data():
    obj = pickle.loads(base64.b64decode(request.data))   # VULN-P12 deserializzazione
    cfg = yaml.load(request.args.get("cfg", "a: 1"), Loader=yaml.Loader)  # VULN-P13 yaml.load unsafe
    return str(obj) + str(cfg)

@app.route("/xml", methods=["POST"])
def xml():
    return ET.fromstring(request.data).tag   # VULN-P14 XML non protetto

@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))   # VULN-P15 eval

@app.route("/go")
def go():
    return redirect(request.args["next"])    # VULN-P16 open redirect

@app.route("/token")
def token():
    return str(random.randint(100000, 999999))  # VULN-P17 PRNG non sicuro

@app.route("/safe-search")
def safe_search():   # NON vulnerabile: controllo falsi positivi
    rows = db().execute("SELECT * FROM items WHERE name=?", (request.args.get("q", ""),)).fetchall()
    return {"rows": rows}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)   # VULN-P18 debug + bind 0.0.0.0
