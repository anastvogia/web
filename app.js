const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const app = express();
const PORT = 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

// MySQL configuration
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'web'
};

// Serve static files (HTML, CSS, JS) from "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve login page as default landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle login POST request
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query(
      'SELECT * FROM users WHERE username = ? AND password = ?',
      [username, password]
    );
    await connection.end();

    if (rows.length === 1) {
      const user = rows[0];
      res.json({ success: true, role: user.role });
    } else {
      res.json({ success: false, message: 'Invalid username or password' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// API to get all theses, sorted by assigned_date (newest first)
app.get('/api/thesis', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query('SELECT * FROM thesis ORDER BY assigned_date DESC');
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// API to get a specific thesis by ID
app.get('/api/thesis/:id', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query('SELECT * FROM thesis WHERE id = ?', [thesisId]);
    await connection.end();

    if (rows.length > 0) {
      res.json(rows[0]); // Return the single entry
    } else {
      res.status(404).json({ error: 'Thesis not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
