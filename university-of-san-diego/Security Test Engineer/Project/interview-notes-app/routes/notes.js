const express = require('express');
const router = express.Router();
const db = require('../database');

// Middleware to check if user is logged in
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/auth/login');
    }
    next();
}

// GET notes page - view user's own notes
router.get('/', requireLogin, (req, res) => {
    const userId = req.session.userId;
    
    db.all(
        'SELECT * FROM interview_notes WHERE user_id = ? ORDER BY created_at DESC',
        [userId],
        (err, notes) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            res.render('notes', { 
                notes, 
                username: req.session.username,
                role: req.session.role 
            });
        }
    );
});

// GET create note form
router.get('/create', requireLogin, (req, res) => {
    res.render('create-note');
});

// POST create new note
router.post('/create', requireLogin, (req, res) => {
    const { candidate_name, position, interview_date, notes } = req.body;
    const userId = req.session.userId;

    db.run(
        'INSERT INTO interview_notes (candidate_name, position, interview_date, notes, user_id) VALUES (?, ?, ?, ?, ?)',
        [candidate_name, position, interview_date, notes, userId],
        (err) => {
            if (err) {
                return res.status(500).send('Error creating note');
            }
            res.redirect('/notes');
        }
    );
});

// POST delete note
router.post('/delete/:id', requireLogin, (req, res) => {
    const noteId = req.params.id;
    const userId = req.session.userId;
    const userRole = req.session.role;

    // Check if user owns this note OR is admin
    db.get(
        'SELECT * FROM interview_notes WHERE id = ?',
        [noteId],
        (err, note) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            if (!note) {
                return res.status(404).send('Note not found');
            }

            // Allow deletion if user owns the note OR user is admin
            if (note.user_id === userId || userRole === 'admin') {
                db.run('DELETE FROM interview_notes WHERE id = ?', [noteId], (err) => {
                    if (err) {
                        return res.status(500).send('Error deleting note');
                    }
                    res.redirect('/notes');
                });
            } else {
                res.status(403).send('You can only delete your own notes');
            }
        }
    );
});

// GET edit note form
router.get('/edit/:id', requireLogin, (req, res) => {
    const noteId = req.params.id;
    const userId = req.session.userId;
    const userRole = req.session.role;

    // Get the note
    db.get(
        'SELECT * FROM interview_notes WHERE id = ?',
        [noteId],
        (err, note) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            if (!note) {
                return res.status(404).send('Note not found');
            }

            // Check if user owns this note OR is admin
            if (note.user_id !== userId && userRole !== 'admin') {
                return res.status(403).send('You can only edit your own notes');
            }

            res.render('edit-note', { note });
        }
    );
});

// POST update note
router.post('/edit/:id', requireLogin, (req, res) => {
    const noteId = req.params.id;
    const userId = req.session.userId;
    const userRole = req.session.role;
    const { candidate_name, position, interview_date, notes } = req.body;

    // First check if user owns this note OR is admin
    db.get(
        'SELECT * FROM interview_notes WHERE id = ?',
        [noteId],
        (err, note) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            if (!note) {
                return res.status(404).send('Note not found');
            }
            if (note.user_id !== userId && userRole !== 'admin') {
                return res.status(403).send('You can only edit your own notes');
            }

            // Update the note
            db.run(
                'UPDATE interview_notes SET candidate_name = ?, position = ?, interview_date = ?, notes = ? WHERE id = ?',
                [candidate_name, position, interview_date, notes, noteId],
                (err) => {
                    if (err) {
                        return res.status(500).send('Error updating note');
                    }
                    res.redirect('/notes');
                }
            );
        }
    );
});

module.exports = router;