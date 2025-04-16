const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
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

// (async () => {
//   const connection = await mysql.createConnection(dbConfig);
//   const [users] = await connection.query('SELECT id, password FROM users');

//   for (const user of users) {
//     const hashedPassword = await bcrypt.hash(user.password, 10);
//     await connection.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);
//     console.log(`Updated password for user ID ${user.id}`);
//   }

//   await connection.end();
// })();


// Session configuration
const sessionConfig = {
  secret: 'your-secret-key', // Use a strong secret key
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 } // 1 day
};

// Session middleware
app.use(session(sessionConfig));

// Serve static files (HTML, CSS, JS) from "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve login page as default landing page
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Serve login page if not logged in
app.get('/login.html', (req, res) => {
  if (req.session.user) {
    return res.redirect(`/login.html`); // Redirect logged-in users to the appropriate page
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query('SELECT * FROM users WHERE username = ?', [username]);
    await connection.end();

    if (rows.length === 1) {
      const user = rows[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        req.session.user = {
          id: user.id,
          username: user.username,
          role: user.role
        };
        res.json({ success: true, role: user.role });
      } else {
        res.json({ success: false, message: 'Invalid username or password' });
      }
    } else {
      res.json({ success: false, message: 'Invalid username or password' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Could not log out.');
    }
    res.redirect('/login.html'); // Redirect to login after logout
  });
});

// Middleware to check if user is authenticated and has the correct role
function isAuthenticated(requiredRole) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login.html'); // Redirect to login if not logged in
    }

    if (requiredRole && req.session.user.role !== requiredRole) {
      return res.redirect('/login.html'); // Redirect if user doesn't have the required role
    }

    next(); // Allow access if authenticated and authorized
  };
}

// Serve student-home.html only if the user is logged in and has 'student' role
app.get('/student-home.html', isAuthenticated('student'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'student-home.html'));
});

// Serve secretariat-home.html only if the user is logged in and has 'secretariat' role
app.get('/secretariat-home.html', isAuthenticated('secretariat'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'secretariat-home.html'));
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
// API to check if user is logged in and return their role
// Check current session (used by navbar)
app.get('/api/check-session', (req, res) => {
  if (req.session && req.session.user) {
    res.json({
      loggedIn: true,
      username: req.session.user.username,
      role: req.session.user.role
    });
  } else {
    res.json({ loggedIn: false });
  }
});

app.get('/api/student-thesis', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const studentId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig); // Ensure connection is established
    const [rows] = await connection.query(
      'SELECT * FROM thesis WHERE student_id = ?',
      [studentId]
    );
    await connection.end();

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No thesis found for this student' });
    }

    res.json(rows[0]); // Return the first thesis found for the student
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch thesis' });
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
