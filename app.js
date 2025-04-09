// app.js
const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const app = express();
const PORT = 3000;

// MySQL config
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'web'
};

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// API to get theses
app.get('/api/thesis', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query('SELECT * FROM thesis');
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

