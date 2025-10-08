const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const db = require('../database');

// Register new user
router.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Input validation
  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  if (password.length < 6) {
    return res.status(400).send('Password must be at least 6 characters');
  }

  // Hash password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Insert into database
  db.run(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
    [username, hashedPassword, 'regular'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).send('Username already exists');
        }
        return res.status(500).send('Error creating user');
      }
      res.redirect('/login?registered=true');
    }
  );
});

// Login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  // Find user
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).send('Database error');
    }

    if (!user) {
      return res.status(401).send('Invalid username or password');
    }

    // Check password
    const validPassword = bcrypt.compareSync(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).send('Invalid username or password');
    }

    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;

    res.redirect('/notes');
  });
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/login');
  });
});

module.exports = router;