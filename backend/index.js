const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(
  cors({
    origin: "http://localhost:3000", // Replace with your frontend URL
    methods: ["GET", "POST", "PUT", "DELETE"], // Allowed HTTP methods
    allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
  })
);
app.use(bodyParser.json());

const db = new sqlite3.Database("./recipes.db");

// Create tables
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)`
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS recipes (id INTEGER PRIMARY KEY, mood TEXT, recipe TEXT)`
  );
});

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(403);

  jwt.verify(token.split(" ")[1], "secret_key", (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
    [username, hashedPassword, role],
    (err) => {
      if (err) return res.status(500).send(err.message);
      res.sendStatus(201);
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(403).send("Invalid credentials");
      }
      const token = jwt.sign(
        { username: user.username, role: user.role },
        "secret_key"
      );
      res.json({ token });
    }
  );
});

app.get("/recipes", authenticateToken, (req, res) => {
  db.all(`SELECT * FROM recipes`, [], (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

app.post("/recipes", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  const { mood, recipe } = req.body;
  db.run(
    `INSERT INTO recipes (mood, recipe) VALUES (?, ?)`,
    [mood, recipe],
    (err) => {
      if (err) return res.status(500).send(err.message);
      res.sendStatus(201);
    }
  );
});

app.put("/recipes/:id", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);

  const { id } = req.params; // Get recipe ID from URL
  const { recipe } = req.body; // Get updated recipe content from body

  if (!id || !recipe) {
    return res.status(400).send("Missing recipe ID or content.");
  }

  db.run(`UPDATE recipes SET recipe = ? WHERE id = ?`, [recipe, id], (err) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Database error");
    }
    res.sendStatus(200);
  });
});

app.listen(5010, () => console.log("Backend running on http://localhost:5010"));
