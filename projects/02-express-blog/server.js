// ATTENZIONE: applicazione volutamente vulnerabile, solo per collaudare scanner di sicurezza.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const mysql = require("mysql");
const serialize = require("node-serialize");
const cors = require("cors");

const app = express();
app.use(cors({ origin: "*", credentials: true }));            // VULN-N01 CORS permissivo
app.use(express.json());

const JWT_SECRET = "changeme";                                 // VULN-N02
const SLACK_WEBHOOK = "https://hooks.slack.com/services/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"; // VULN-N03
const db = mysql.createConnection({ host: "db", user: "root", password: "rootpw123" });  // VULN-N04

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (e, r) => res.json(r));  // VULN-N05 SQLi
});

app.get("/hello", (req, res) => {
  res.send("<h1>Ciao " + req.query.name + "</h1>");            // VULN-N06 XSS riflesso
});

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (e, out) => res.send(out));      // VULN-N07 command injection
});

app.get("/download", (req, res) => {
  res.send(fs.readFileSync("./uploads/" + req.query.f));       // VULN-N08 path traversal
});

app.post("/merge", (req, res) => {
  res.json(_.merge({}, req.body));                             // VULN-N09 prototype pollution
});

app.post("/restore", (req, res) => {
  res.json(serialize.unserialize(req.body.data));              // VULN-N10 deserializzazione
});

app.get("/eval", (req, res) => res.send(String(eval(req.query.code))));  // VULN-N11

app.post("/token", (req, res) => {
  res.send(jwt.sign({ user: req.body.user, admin: true }, JWT_SECRET, { algorithm: "none" }));  // VULN-N12
});

app.get("/hash", (req, res) => {
  res.send(crypto.createHash("sha1").update(req.query.p).digest("hex"));   // VULN-N13 hash debole
});

app.get("/regex", (req, res) => {
  res.send(String(new RegExp(req.query.re).test(req.query.s)));            // VULN-N14 ReDoS
});

app.get("/safe", (req, res) => {   // NON vulnerabile: controllo falsi positivi
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (e, r) => res.json(r));
});

app.listen(3000, "0.0.0.0");
