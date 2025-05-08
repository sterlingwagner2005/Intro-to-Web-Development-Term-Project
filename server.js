const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./mytunes.db');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Create DB tables if they don't exist
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS playlists (id INTEGER PRIMARY KEY, userId INTEGER, name TEXT, songs TEXT)");
});

// Middleware to check if user is logged in
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).send("Admins only.");
  next();
}

// Routes
app.get('/', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'mytunes.html'));
});

app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user) return res.redirect('/login');
    bcrypt.compare(password, user.password, (err, same) => {
      if (same) {
        req.session.userId = user.id;
        req.session.role = user.role;
        res.redirect('/');
      } else {
        res.redirect('/login');
      }
    });
  });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashed, 'guest'], (err) => {
    if (err) return res.redirect('/register');
    res.redirect('/login');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Playlist API (requires login)
app.get('/api/playlists', requireLogin, (req, res) => {
  if (req.session.role === 'admin') {
    // Admin sees all playlists
    db.all("SELECT playlists.id, playlists.name, users.username FROM playlists JOIN users ON playlists.userId = users.id", [], (err, rows) => {
      if (err) return res.status(500).send("Error fetching playlists");
      res.json(rows);
    });
  } else {
    // Guests see only their playlists
    db.all("SELECT id, name FROM playlists WHERE userId = ?", [req.session.userId], (err, rows) => {
      if (err) return res.status(500).send("Error fetching playlists");
      res.json(rows);
    });
  }
});

app.post('/api/playlists', requireLogin, (req, res) => {
  if (req.session.role === 'admin') {
    return res.status(403).send("Admins cannot create playlists.");
  }
  const { name, songs } = req.body;
  db.run("INSERT INTO playlists (userId, name, songs) VALUES (?, ?, ?)",
    [req.session.userId, name, JSON.stringify(songs)], function (err) {
      if (err) return res.status(500).send("Error saving playlist");
      res.json({ id: this.lastID });
    });
});

app.get('/admin/users', requireLogin, requireAdmin, (req, res) => {
  db.all("SELECT id, username, role FROM users", [], (err, users) => {
    if (err) return res.status(500).send("Error retrieving users");
    res.json(users);
  });
});


// Delete a playlist
app.delete('/api/playlist/:id', requireLogin, (req, res) => {
  const playlistId = req.params.id;
  const userId = req.session.userId;
  const isAdmin = req.session.role === 'admin';

  db.get("SELECT * FROM playlists WHERE id = ?", [playlistId], (err, playlist) => {
    if (err || !playlist) {
      return res.status(404).send({ error: "Playlist not found" });
    }

    if (!isAdmin && playlist.userId !== userId) {
      return res.status(403).send({ error: "Not authorized to delete this playlist" });
    }

    db.run("DELETE FROM playlists WHERE id = ?", [playlistId], (err2) => {
      if (err2) {
        return res.status(500).send({ error: "Failed to delete playlist" });
      }
      res.send({ success: true });
    });
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

const https = require('https');

// Route to search iTunes API
app.get('/search', (req, res) => {
  const term = req.query.term;
  if (!term) return res.status(400).send({ error: "Missing search term" });

  const url = `https://itunes.apple.com/search?term=${encodeURIComponent(term)}&entity=song&limit=20`;

  https.get(url, (apiRes) => {
    let data = '';
    apiRes.on('data', chunk => data += chunk);
    apiRes.on('end', () => {
      try {
        const parsed = JSON.parse(data);
        res.send(parsed);
      } catch (e) {
        res.status(500).send({ error: "Error parsing iTunes response" });
      }
    });
  }).on('error', err => {
    console.error("iTunes API error:", err);
    res.status(500).send({ error: "iTunes API request failed" });
  });
});


app.get('/api/playlist/:id', requireLogin, (req, res) => {
  const playlistId = req.params.id;
  db.get("SELECT * FROM playlists WHERE id = ? AND userId = ?", [playlistId, req.session.userId], (err, row) => {
    if (err || !row) return res.status(404).send({ error: "Playlist not found" });
    res.json(row);
  });
});
