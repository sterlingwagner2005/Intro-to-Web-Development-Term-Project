const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./mytunes.db');

// First, ensure the 'users' table exists
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  // Now insert the admin user
  const username = 'admin';
  const password = 'admin';
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
    [username, hashedPassword, 'admin'],
    function (err) {
      if (err) {
        console.error("Error inserting admin:", err);
      } else {
        console.log("✅ Admin user created (or already exists).");
      }
      db.close();
    });
});