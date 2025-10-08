const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// Create/connect to database
const db = new sqlite3.Database('./interview_notes.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('✅ Connected to SQLite database');
    initializeDatabase();
  }
});

// Create tables and default admin user
function initializeDatabase() {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'regular'
    )
  `, (err) => {
    if (err) {
      console.error('Error creating users table:', err);
    } else {
      console.log('✅ Users table ready');
      createDefaultAdmin();
    }
  });

  // Interview notes table
  db.run(`
    CREATE TABLE IF NOT EXISTS interview_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_name TEXT NOT NULL,
      position TEXT NOT NULL,
      interview_date TEXT NOT NULL,
      notes TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `, (err) => {
    if (err) {
      console.error('Error creating notes table:', err);
    } else {
      console.log('✅ Interview notes table ready');
    }
  });
}

// Create default admin account (username: admin, password: admin123)
function createDefaultAdmin() {
  const adminUsername = 'admin';
  const adminPassword = 'admin123';
  
  db.get('SELECT * FROM users WHERE username = ?', [adminUsername], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync(adminPassword, 10);
      db.run(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        [adminUsername, hashedPassword, 'admin'],
        (err) => {
          if (err) {
            console.error('Error creating admin:', err);
          } else {
            console.log('✅ Default admin created (username: admin, password: admin123)');
          }
        }
      );
    }
  });
}

module.exports = db;