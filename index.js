const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { verifyToken, isAdmin } = require("./authMiddleware");

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log("✅ Connected to DB");
});

// 🟢 REGISTER
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send("Missing required fields");
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
      [username, email, hashed],
      (err, result) => {
        if (err) {
          console.error("❌ SQL Error:", err);
          return res.status(500).send(err.sqlMessage || "Registration error");
        }
        res.status(201).send("User registered");
      }
    );
  } catch (error) {
    console.error("❌ Hashing error:", error);
    res.status(500).send("Server error");
  }
});

// 🟢 LOGIN (με debug)
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Missing email or password");
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, users) => {
    if (err) {
      console.error("❌ SQL Error:", err);
      return res.status(500).send("Login error");
    }

    if (users.length === 0) {
      console.log("❌ Email not found in DB:", email);
      return res.status(400).send("Invalid email");
    }

    const user = users[0];
    console.log("✅ User found. Email:", user.email);
    console.log("🔑 Entered password:", password);
    console.log("🔐 Stored hashed password:", user.password);

    const match = await bcrypt.compare(password, user.password);
    console.log("🧪 Password match result:", match);

    if (!match) return res.status(401).send("Wrong password");

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({ token, username: user.username, role: user.role });
  });
});

// 🟢 GET MATCHES
app.get("/matches", (req, res) => {
  db.query("SELECT * FROM matches", (err, results) => {
    if (err) {
      console.error("❌ Error fetching matches:", err);
      return res.status(500).send("Server error");
    }
    res.json(results);
  });
});

// 🟢 POST MATCH (μόνο admin)
app.post("/matches", verifyToken, isAdmin, (req, res) => {
  const { opponent, date, time, location, total_tickets } = req.body;
  const available_tickets = total_tickets;

  if (!opponent || !date || !time || !total_tickets) {
    return res.status(400).send("Missing match details");
  }

  db.query(
    "INSERT INTO matches (opponent, date, time, location, total_tickets, available_tickets) VALUES (?, ?, ?, ?, ?, ?)",
    [opponent, date, time, location, total_tickets, available_tickets],
    (err, result) => {
      if (err) {
        console.error("❌ Error inserting match:", err);
        return res.status(500).send("Error adding match");
      }
      res.status(201).send("Match added");
    }
  );
});

// 🟢 RESERVATION (προστατευμένο)
app.post("/reservations", verifyToken, (req, res) => {
  const { match_id, tickets_reserved } = req.body;
  const user_id = req.user.id;

  if (!match_id || !tickets_reserved) {
    return res.status(400).send("Missing reservation data");
  }

  db.query(
    "SELECT available_tickets FROM matches WHERE id = ?",
    [match_id],
    (err, results) => {
      if (err) return res.status(500).send("Server error");
      if (results.length === 0) return res.status(404).send("Match not found");

      const available = results[0].available_tickets;
      if (available < tickets_reserved) {
        return res.status(400).send("Not enough tickets available");
      }

      db.query(
        "INSERT INTO reservations (user_id, match_id, tickets_reserved) VALUES (?, ?, ?)",
        [user_id, match_id, tickets_reserved],
        (err) => {
          if (err) return res.status(500).send("Reservation error");

          db.query(
            "UPDATE matches SET available_tickets = available_tickets - ? WHERE id = ?",
            [tickets_reserved, match_id],
            (err) => {
              if (err) return res.status(500).send("Ticket update error");
              res.status(201).send("Reservation successful");
            }
          );
        }
      );
    }
  );
});

// 🟢 MY RESERVATIONS
app.get("/my-reservations", verifyToken, (req, res) => {
  const user_id = req.user.id;

  db.query(
    `
    SELECT r.id AS reservation_id, r.tickets_reserved,
           m.opponent, m.date, m.time, m.location
    FROM reservations r
    JOIN matches m ON r.match_id = m.id
    WHERE r.user_id = ?
    ORDER BY m.date, m.time
    `,
    [user_id],
    (err, results) => {
      if (err) return res.status(500).send("Server error");
      res.json(results);
    }
  );
});

// 🟢 DELETE RESERVATION
app.delete("/reservations/:reservation_id", verifyToken, (req, res) => {
  const reservation_id = req.params.reservation_id;

  db.query(
    "SELECT match_id, tickets_reserved, user_id FROM reservations WHERE id = ?",
    [reservation_id],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).send("Reservation not found");
      }

      const { match_id, tickets_reserved, user_id } = results[0];

      if (user_id !== req.user.id) {
        return res.status(403).send("Not allowed to delete this reservation");
      }

      db.query(
        "DELETE FROM reservations WHERE id = ?",
        [reservation_id],
        (err) => {
          if (err) return res.status(500).send("Delete error");

          db.query(
            "UPDATE matches SET available_tickets = available_tickets + ? WHERE id = ?",
            [tickets_reserved, match_id],
            (err) => {
              if (err) return res.status(500).send("Ticket restore error");
              res.send("Reservation cancelled");
            }
          );
        }
      );
    }
  );
});

app.listen(3001, () => console.log("🚀 Server running on port 3001"));
