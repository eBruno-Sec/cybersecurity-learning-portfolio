const express = require('express');
const router = express.Router();
const db = require('../database');

// Middleware to check if user is admin
function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).send('You must be logged in');
  }
  if (req.session.role !== 'admin') {
    return res.status(403).send('Access denied: Admin only');
  }
  next();
}

// View all users (admin only)
router.get('/users', requireAdmin, (req, res) => {
  db.all('SELECT id, username, role FROM users', [], (err, users) => {
    if (err) {
      return res.status(500).send('Error fetching users');
    }
    res.render('admin-users', {
      username: req.session.username,
      role: req.session.role,
      users: users
    });
  });
});

// View all notes (admin only)
router.get('/notes', requireAdmin, (req, res) => {
  db.all(
    `SELECT interview_notes.*, users.username 
     FROM interview_notes 
     JOIN users ON interview_notes.user_id = users.id 
     ORDER BY created_at DESC`,
    [],
    (err, notes) => {
      if (err) {
        return res.status(500).send('Error fetching notes');
      }
      res.render('admin-notes', {
        username: req.session.username,
        role: req.session.role,
        notes: notes
      });
    }
  );
});

module.exports = router;