const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const app = express();
const dbConfig = require('./dbconfig'); 
const PORT = 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

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

// Serve static files from the "thesis" directory
app.use('/thesis', express.static(path.join(__dirname, 'thesis')));

// Serve static files from the "upload" directory
app.use('/upload', express.static(path.join(__dirname, 'upload')));


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

const draftStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'upload', 'drafts'));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, req.session.user.username + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const uploadDraft = multer({ storage: draftStorage });

app.post('/api/upload-draft', uploadDraft.single('draft'), async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const filePath = `/upload/drafts/${req.file.filename}`;
  const studentId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    await connection.query(
      'UPDATE thesis SET draft_file_path = ? WHERE student_id = ?',
      [filePath, studentId]
    );

    await connection.end();
    res.json({ success: true, filePath });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to upload draft' });
  }
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

// Serve professor-home.html only if the user is logged in and has 'professor' role
app.get('/professor-home.html', isAuthenticated('professor'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'professor-home.html'));
});

app.get('/login.html', (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === 'student') {
      return res.redirect('/student-home.html');
    } else if (req.session.user.role === 'professor') {
      return res.redirect('/professor-home.html');
    }
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

const importUpload = multer({ dest: 'uploads/' });

app.post('/api/import-users', importUpload.single('file'), async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'secretariat') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const fs = require('fs');
  const filePath = req.file.path;

  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

    if (!Array.isArray(data)) {
      return res.status(400).json({ success: false, message: 'Invalid JSON structure.' });
    }

    const connection = await mysql.createConnection(dbConfig);

    let inserted = 0;
    for (const user of data) {
      const {
      username, password, role,
      full_address = null, email = null, mobile_phone = null, landline = null
      } = user;

      // Skip if role is not valid
      if (!['student', 'professor'].includes(role)) continue;

      // Hash the password before inserting
      const hashedPassword = await bcrypt.hash(password, 10);

      await connection.query(`
      INSERT INTO users (username, password, role, full_address, email, mobile_phone, landline)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      `, [username, hashedPassword, role, full_address, email, mobile_phone, landline]);

      inserted++;
    }

    await connection.end();
    fs.unlinkSync(filePath); // cleanup
    res.json({ success: true, count: inserted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Import failed.' });
  }
});

// API to get all theses, sorted by assigned_date (newest first)
// Fetch ONLY active or under_review theses
app.get('/api/thesis', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query(`
      SELECT id, title, status, assigned_date
      FROM thesis
      WHERE status IN ('active', 'under_review')
      ORDER BY assigned_date DESC
    `);
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error('[Fetch Theses Error]', err);
    res.status(500).json({ error: 'Database error' });
  }
});


// Fetch full data for one thesis by ID
app.get('/api/thesis/:id', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Get thesis basic info
    const [thesisRows] = await connection.query(`
      SELECT id, title, description, status, assigned_date, additional_links, exam_date, exam_location, exam_link, nemertis_link, draft_file_path
      FROM thesis
      WHERE id = ?
    `, [thesisId]);

    if (thesisRows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Thesis not found' });
    }

    const thesis = thesisRows[0];

    // Now get committee (accepted professors)
    const [committeeRows] = await connection.query(`
      SELECT u.username
      FROM committee_invites ci
      JOIN users u ON ci.professor_id = u.id
      WHERE ci.thesis_id = ? AND ci.status = 'accepted'
    `, [thesisId]);

    await connection.end();

    // Prepare committee names
    const committeeList = committeeRows.map(row => row.username).join(', ');

    // Add committee list to thesis
    thesis.committee_names = committeeList || 'Pending';

    res.json(thesis);
  } catch (err) {
    console.error('Error fetching thesis:', err);
    res.status(500).json({ error: 'Failed to fetch thesis' });
  }
});




app.get('/api/exam-report', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).send('Unauthorized');
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Get thesis
    const [thesisRows] = await connection.query(`
      SELECT id, title, exam_date, exam_location, nemertis_link
      FROM thesis
      WHERE student_id = ?
    `, [req.session.user.id]);

    if (thesisRows.length === 0) {
      await connection.end();
      return res.status(404).send('No report found');
    }

    const thesis = thesisRows[0];

    // Get real committee members (accepted only)
    const [committeeRows] = await connection.query(`
      SELECT u.username
      FROM committee_invites ci
      JOIN users u ON ci.professor_id = u.id
      WHERE ci.thesis_id = ? AND ci.status = 'accepted'
    `, [thesis.id]);

    const committeeList = committeeRows.map(member => member.username).join(', ') || 'Pending';

    await connection.end();

    const html = `
      <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Exam Report</title>
    <!-- Bootstrap CSS -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body class="bg-light">
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-12 col-md-10 col-lg-8">
          <div class="card shadow-sm">
            <div class="card-header bg-success text-white">
              <h2 class="h4 mb-0">Exam Report</h2>
            </div>
            <div class="card-body">
              <h4 class="card-title mb-3">Title: ${thesis.title}</h4>
              <p class="mb-2">
                <strong>Committee:</strong> ${committeeList}
              </p>
              <p class="mb-2">
                <strong>Exam Date:</strong> ${new Date(thesis.exam_date).toLocaleString()}
              </p>
              <p class="mb-2">
                <strong>Location:</strong> ${thesis.exam_location}
              </p>
              <p class="mb-0">
                <strong>Nemertis Link:</strong>
                <a href="${thesis.nemertis_link}" target="_blank">${thesis.nemertis_link}</a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Bootstrap JS (optional) -->
    <script
      src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
    ></script>
  </body>
</html>
    `;

    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


app.get('/api/completed-thesis', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).send('Unauthorized');
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Get thesis
    const [thesisRows] = await connection.query(`
      SELECT id, title, description, assigned_date, days_since_assignment, protocol_number
      FROM thesis
      WHERE student_id = ?
    `, [req.session.user.id]);

    if (thesisRows.length === 0) {
      await connection.end();
      return res.status(404).send('No report found');
    }

    const thesis = thesisRows[0];

    const [committeeRows] = await connection.query(`
      SELECT u.username
      FROM committee_invites ci
      JOIN users u ON ci.professor_id = u.id
      WHERE ci.thesis_id = ? AND ci.status = 'accepted'
    `, [thesis.id]);

    const committeeList = committeeRows.map(member => member.username).join(', ') || 'Pending';

    const [historyRows] = await connection.query(`
      SELECT old_status, new_status, DATE_FORMAT(changed_at, '%Y-%m-%d %H:%i') AS changed_at
      FROM thesis_status_history
      WHERE thesis_id = ?
      ORDER BY changed_at ASC
    `, [thesis.id]);

    await connection.end();

    const html = `
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Thesis Details</title>
    <!-- Bootstrap CSS -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body class="bg-light">
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-12 col-md-10 col-lg-8">
          <!-- Thesis Details Card -->
          <div class="card shadow-sm mb-4">
            <div class="card-header bg-primary text-white">
              <h2 class="h4 mb-0">Thesis Details</h2>
            </div>
            <div class="card-body">
              <h4 class="card-title mb-3">Title: ${thesis.title}</h4>
              <p class="mb-2">
                <strong>Committee:</strong> ${committeeList}
              </p>
              <p class="mb-2">
                <strong>Description:</strong> ${thesis.description}
              </p>
              <p class="mb-2">
                <strong>Assigned Date:</strong> ${thesis.assigned_date}
              </p>
              <p class="mb-2">
                <strong>Days Since Assignment:</strong> ${thesis.days_since_assignment} 
              </p>
              <p class="mb-0">
                <strong>Protocol Number:</strong> ${thesis.protocol_number}
              </p>
            </div>
          </div>

          <!-- Status History Card -->
          <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
              <h2 class="h5 mb-0">Status Change History</h2>
            </div>
            <div class="card-body p-0">
              <div class="table-responsive">
                <table class="table table-striped table-bordered mb-0">
                  <thead class="table-secondary">
                    <tr>
                      <th>From</th>
                      <th>To</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${historyRows.map(row => `
                      <tr>
                        <td>${row.old_status}</td>
                        <td>${row.new_status}</td>
                        <td>${row.changed_at}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <!-- Bootstrap JS -->
    <script
      src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
    ></script>
  </body>
</html>
    `;

    res.send(html);

  } catch (err) {
    console.error('[Completed Thesis Error]', err);
    res.status(500).send('Server error');
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
    const connection = await mysql.createConnection(dbConfig);

    // Get thesis for student
    const [thesisRows] = await connection.query(
      'SELECT * FROM thesis WHERE student_id = ?',
      [studentId]
    );

    if (thesisRows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'No thesis found for this student' });
    }

    const thesis = thesisRows[0];

    // Get accepted professors for this thesis
    const [committee] = await connection.query(
      `SELECT u.username 
       FROM committee_invites ci
       JOIN users u ON ci.professor_id = u.id
       WHERE ci.thesis_id = ? AND ci.status = 'accepted'`,
      [thesis.id]
    );

    // Create a string of professor usernames like: "prof1, prof2, prof3"
    thesis.committee_names = committee.map(c => c.username).join(', ') || null;

    await connection.end();
    res.json(thesis);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch thesis' });
  }
});

// API to get current user's profile info
app.get('/api/get-profile', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query(
      'SELECT full_address, email, mobile_phone, landline FROM users WHERE id = ?',
      [req.session.user.id]
    );
    await connection.end();

    if (rows.length === 1) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// API to update current user's profile
app.post('/api/update-profile', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const { full_address, email, mobile_phone, landline } = req.body;
  const userId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);
    await connection.query(
      'UPDATE users SET full_address = ?, email = ?, mobile_phone = ?, landline = ? WHERE id = ?',
      [full_address, email, mobile_phone, landline, userId]
    );
    await connection.end();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});
app.post('/api/invite-professor', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { professorId } = req.body;
  const studentId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Get the student's thesis ID
    const [thesisRows] = await connection.query('SELECT id FROM thesis WHERE student_id = ?', [studentId]);
    if (thesisRows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Thesis not found' });
    }
    const thesisId = thesisRows[0].id;

    // Check if already invited
    const [existing] = await connection.query(
      'SELECT * FROM committee_invites WHERE thesis_id = ? AND professor_id = ?',
      [thesisId, professorId]
    );
    if (existing.length > 0) {
      await connection.end();
      return res.status(400).json({ error: 'Professor already invited' });
    }

    // Insert invite
    await connection.query(
      'INSERT INTO committee_invites (thesis_id, professor_id) VALUES (?, ?)',
      [thesisId, professorId]
    );

    await connection.end();
    res.json({ success: true, message: 'Invitation sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to invite professor' });
  }
});

app.post('/api/respond-invite', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const professorId = req.session.user.id;
  const { inviteId, response } = req.body; // response = 'accepted' or 'declined'

  if (!['accepted', 'declined'].includes(response)) {
    return res.status(400).json({ error: 'Invalid response' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Check if invite exists and belongs to professor
    const [inviteRows] = await connection.query(
      'SELECT * FROM committee_invites WHERE id = ? AND professor_id = ?',
      [inviteId, professorId]
    );

    if (inviteRows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Invite not found or unauthorized' });
    }

    const thesisId = inviteRows[0].thesis_id;

    // Update invite status and responded_at timestamp
    await connection.query(
      'UPDATE committee_invites SET status = ?, responded_at = NOW() WHERE id = ?',
      [response, inviteId]
    );

    // Check how many professors accepted
    const [accepted] = await connection.query(
      'SELECT COUNT(*) AS count FROM committee_invites WHERE thesis_id = ? AND status = "accepted"',
      [thesisId]
    );

    if (accepted[0].count >= 2) {
      // Enough professors accepted → move thesis to "active"
      await connection.query(
        'UPDATE thesis SET status = "active" WHERE id = ?',
        [thesisId]
      );

      // Decline all other pending invitations
      await connection.query(
        'UPDATE committee_invites SET status = "declined", responded_at = NOW() WHERE thesis_id = ? AND status = "pending"',
        [thesisId]
      );
    }

    await connection.end();
    res.json({ success: true, message: `Invite ${response}` });

  } catch (err) {
    console.error('[Respond Invite Error]', err);
    res.status(500).json({ error: 'Failed to respond to invite' });
  }
});


app.get('/api/professors', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query(
      `SELECT id, username
      FROM users
      WHERE role = 'professor'
        AND id NOT IN (
          SELECT professor_id
          FROM thesis
          WHERE student_id = ?
        )`
    , [req.session.user.id]); // Use req.session.user.id for the logged-in student's ID
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch professors' });
  }
});
app.get('/api/my-invites', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [thesisRows] = await connection.query(
      'SELECT id FROM thesis WHERE student_id = ?',
      [req.session.user.id]
    );
    if (thesisRows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Thesis not found' });
    }

    const thesisId = thesisRows[0].id;

    const [invites] = await connection.query(
      `SELECT ci.id, u.username AS professor, ci.status
       FROM committee_invites ci
       JOIN users u ON ci.professor_id = u.id
       WHERE ci.thesis_id = ?`,
      [thesisId]
    );

    await connection.end();
    res.json(invites);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load invites' });
  }
});
app.get('/api/invites-for-me', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const professorId = req.session.user.id;

    const [invites] = await connection.query(`
      SELECT ci.id AS inviteId, ci.status, t.title AS thesis_title, s.username AS student
      FROM committee_invites ci
      JOIN thesis t ON ci.thesis_id = t.id
      JOIN users s ON t.student_id = s.id
      WHERE ci.professor_id = ?
    `, [professorId]);

    await connection.end();
    res.json(invites);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load invitations' });
  }
});
// API to set exam details (date, location, link) for a thesis
// Only accessible by students
app.post('/api/set-exam-details', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { exam_date, exam_mode, exam_location } = req.body;
  const studentId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);
    await connection.query(
      `UPDATE thesis 
       SET exam_date = ?, exam_mode = ?, exam_location = ? 
       WHERE student_id = ?`,
      [exam_date, exam_mode, exam_location, studentId]
    );
    await connection.end();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update exam details' });
  }
});

app.post('/api/set-nemertis-link', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { nemertis_link } = req.body;
  const studentId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);
    await connection.query(
      'UPDATE thesis SET nemertis_link = ? WHERE student_id = ?',
      [nemertis_link, studentId]
    );
    await connection.end();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save link' });
  }
});

async function updateThesisStatus(thesisId, newStatus) {
  const connection = await mysql.createConnection(dbConfig);

  // Get old status
  const [[row]] = await connection.query(
    'SELECT status FROM thesis WHERE id = ?', [thesisId]
  );
  const oldStatus = row.status;

  // Update thesis status
  await connection.query(
    'UPDATE thesis SET status = ? WHERE id = ?',
    [newStatus, thesisId]
  );

  // Insert status change history
  await connection.query(
    'INSERT INTO thesis_status_history (thesis_id, old_status, new_status) VALUES (?, ?, ?)',
    [thesisId, oldStatus, newStatus]
  );

  await connection.end();
}

app.get('/api/thesis/:id/history', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.query(`
      SELECT old_status, new_status, DATE_FORMAT(changed_at, '%Y-%m-%d %H:%i') as changed_at
      FROM thesis_status_history
      WHERE thesis_id = ?
      ORDER BY changed_at ASC
    `, [thesisId]);

    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.post('/api/register-protocol', async (req, res) => {
  const { thesisId, protocolNumber, assemblyDate } = req.body;

  if (!thesisId || !protocolNumber || !assemblyDate) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    const query = `
      UPDATE thesis
      SET protocol_number = ?, assembly_date = ?
      WHERE id = ?
    `;
    const [result] = await connection.execute(query, [protocolNumber, assemblyDate, thesisId]);

    await connection.end();

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Thesis not found.' });
    }

    res.status(200).json({ success: true, message: 'Protocol registered successfully.' });
  } catch (error) {
    console.error('Error registering protocol:', error);
    res.status(500).json({ success: false, message: 'Failed to register protocol.' });
  }
});

app.get('/api/secretariat-current-thesis', async (req, res) => {
  const connection = await mysql.createConnection(dbConfig);
  const [rows] = await connection.query('SELECT * FROM thesis WHERE status = "under_review" LIMIT 1');
  await connection.end();

  if (rows.length === 0) {
    return res.status(404).json({ error: 'No under review thesis' });
  }

  res.json(rows[0]);
});

app.post('/api/mark-completed', async (req, res) => {
  const { thesisId } = req.body;
  const connection = await mysql.createConnection(dbConfig);
  await connection.query('UPDATE thesis SET status = ? WHERE id = ?', ['completed', thesisId]);
  await connection.end();
  res.json({ success: true });
});

app.get('/api/students', async (req, res) => {
  const { search } = req.query;

  if (!search) {
    return res.status(400).json({ error: 'Search term required' });
  }

  const connection = await mysql.createConnection(dbConfig);

  const [students] = await connection.query(`
    SELECT id, username
    FROM users
    WHERE role = 'student'
      AND (username LIKE ? OR id LIKE ?)
  `, [`%${search}%`, `%${search}%`]);

  await connection.end();

  res.json(students);
});

app.post('/api/assign-thesis', async (req, res) => {
  const { studentId, title, description } = req.body;

  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const professorId = req.session.user.id;

  const connection = await mysql.createConnection(dbConfig);

  await connection.query(`
    INSERT INTO thesis (title, description, student_id, assigned_professor_id, status)
    VALUES (?, ?, ?, ?, 'under_assignment')
  `, [title, description, studentId, professorId]);

  await connection.end();

  res.json({ success: true, message: 'Thesis assigned temporarily.' });
});
app.post('/api/cancel-assignment', async (req, res) => {
  const { thesisId } = req.body;

  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const professorId = req.session.user.id;

  const connection = await mysql.createConnection(dbConfig);

  const [rows] = await connection.query(`
    SELECT * FROM thesis
    WHERE id = ? AND assigned_professor_id = ? AND status = 'under_assignment'
  `, [thesisId, professorId]);

  if (rows.length === 0) {
    await connection.end();
    return res.status(400).json({ error: 'Cannot cancel this thesis' });
  }

  await connection.query(`DELETE FROM thesis WHERE id = ?`, [thesisId]);

  await connection.end();

  res.json({ success: true, message: 'Assignment canceled.' });
});

app.get('/api/available-theses', async (req, res) => {
  const connection = await mysql.createConnection(dbConfig);

  const professorId = req.session.user.id;
  // console.log('Professor ID:', professorId);
  const [rows] = await connection.query(`
    SELECT id, title
    FROM thesis
    WHERE status IS NULL and professor_id = ?
  `, [professorId]);

  await connection.end();
  res.json(rows);
});

app.get('/api/students-without-thesis', async (req, res) => {
  const connection = await mysql.createConnection(dbConfig);

  const [rows] = await connection.query(`
    SELECT id, username
    FROM users
    WHERE role = 'student'
      AND id NOT IN (SELECT student_id FROM thesis WHERE student_id IS NOT NULL)
  `);

  await connection.end();
  res.json(rows);
});

app.post('/api/assign-thesis-to-student', async (req, res) => {
  const { thesisId, studentId } = req.body;

  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [result] = await connection.query(`
      UPDATE thesis
      SET student_id = ?, status = 'under_assignment', professor_id = ?
      WHERE id = ? AND status IS NULL
    `, [studentId, req.session.user.id, thesisId]);

    await connection.end();

    if (result.affectedRows === 0) {
      return res.json({ success: false, message: 'Thesis already assigned or not available.' });
    }

    res.json({ success: true, message: 'Thesis successfully assigned.' });

  } catch (error) {
    console.error('[Assign Thesis Error]', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/professor-under-assignment', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.query(`
      SELECT t.id AS thesis_id, t.title, u.username AS student_username
      FROM thesis t
      JOIN users u ON t.student_id = u.id
      WHERE t.professor_id = ? AND t.status = 'under_assignment'
    `, [req.session.user.id]);

    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error('[Professor Assignments Error]', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// Only show theses the professor assigned
app.get('/api/professor-assigned-theses', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.query(`
      SELECT t.id AS thesis_id, t.title, t.status, u.username AS student_username
      FROM thesis t
      JOIN users u ON t.student_id = u.id
      WHERE t.professor_id = ? 
        AND t.status IN ('under_assignment', 'active')
    `, [req.session.user.id]);

    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error('[Professor Assigned Theses Error]', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.post('/api/professor-cancel-assignment', async (req, res) => {
  const { thesisId, reason } = req.body; // reason and cancelNumber may be provided conditionally

  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    // Check if the thesis belongs to this professor and is under_assignment
    const [rows] = await connection.query(`
    SELECT * FROM thesis
    WHERE id = ? AND professor_id = ? AND (status = 'under_assignment' OR status = 'active')
    `, [thesisId, req.session.user.id]);

    if (rows.length === 0) {
      await connection.end();
      return res.json({ success: false, message: 'Cannot cancel: not found or unauthorized.' });
    }

    // Update thesis: only set the cancellation_reason if provided; otherwise, it will remain NULL
    await connection.query(`
      UPDATE thesis
      SET student_id = NULL,
          status = NULL,
          cancellation_reason = ?
      WHERE id = ?
    `, [reason || null, thesisId]);

    await connection.end();
    res.json({ success: true, message: 'Assignment cancelled successfully.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});




const upload = multer({
  dest: 'uploads/', // Directory to store uploaded files
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
});


app.post('/api/submit-thesis', upload.single('file'), async (req, res) => {
  const { title, description } = req.body;

  if (!title || !description) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);


    const query = `
      INSERT INTO thesis (title, description, description_file, professor_id)
      VALUES (?, ?, ?, ?)
    `;
    if (req.file){
      const filePath = path.join('uploads', req.file.filename);
      await connection.execute(query, [title, description, filePath, req.session.user.id]);

    }
    else {
      await connection.execute(query, [title, description, null, req.session.user.id]);
    } 
    await connection.end();

    res.status(200).json({ success: true, message: 'Thesis submitted successfully.' });
  } catch (error) {
    console.error('Error submitting thesis:', error);
    res.status(500).json({ success: false, message: 'Failed to submit thesis.' });
  }
});
app.get('/api/professor-theses', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Fetch theses created by the logged-in professor
    const [rows] = await connection.query(`
      SELECT id, title, description, status, assigned_date
      FROM thesis
      WHERE professor_id = ?
    `, [req.session.user.id]);

    await connection.end();

    res.status(200).json({ success: true, theses: rows });
  } catch (error) {
    console.error('Error fetching professor theses:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch theses.' });
  }
});
app.put('/api/thesis/:id', async (req, res) => {
  const thesisId = req.params.id;
  const { title, description } = req.body;

  if (!title || !description) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.query(
      'UPDATE thesis SET title = ?, description = ? WHERE id = ?',
      [title, description, thesisId]
    );
    await connection.end();

    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Thesis updated successfully.' });
    } else {
      res.status(404).json({ success: false, message: 'Thesis not found.' });
    }
  } catch (err) {
    console.error('Error updating thesis:', err);
    res.status(500).json({ success: false, message: 'Failed to update thesis.' });
  }
});


// Professor responds to an invitation (accept or decline)
app.post('/api/respond-invite', async (req, res) => {
  const { inviteId, response } = req.body;

  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  if (!['accepted', 'declined'].includes(response)) {
    return res.status(400).json({ success: false, message: 'Invalid response' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Update status and responded_at
    const [result] = await connection.query(`
      UPDATE committee_invites
      SET status = ?, responded_at = NOW()
      WHERE id = ? AND professor_id = ?
    `, [response, inviteId, req.session.user.id]);

    await connection.end();

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Invite not found or not yours' });
    }

    res.json({ success: true, message: `Invite ${response} successfully.` });

  } catch (err) {
    console.error('Error responding to invite:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.get('/api/professor-my-thesis-invites', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [invites] = await connection.query(`
      SELECT 
        t.id AS thesis_id,
        t.title AS thesis_title,
        u.username AS invited_professor,
        ci.status,
        ci.invited_at,
        ci.responded_at
      FROM thesis t
      JOIN committee_invites ci ON t.id = ci.thesis_id
      JOIN users u ON ci.professor_id = u.id
      WHERE t.professor_id = ?
      ORDER BY t.id DESC, ci.invited_at ASC
    `, [req.session.user.id]);

    await connection.end();
    res.json(invites);

  } catch (err) {
    console.error('Error fetching professor thesis invites:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/professor-theses-filtered', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const { status, role } = req.query; // Get filters from query string
  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    let query = `
      SELECT DISTINCT t.id, t.title, t.description, t.status, t.assigned_date,t.grading_open,
             CASE 
               WHEN t.professor_id = ? THEN 'Supervisor'
               WHEN ci.professor_id = ? THEN 'Committee Member'
               ELSE 'Unknown'
             END AS role
      FROM thesis t
      LEFT JOIN committee_invites ci ON t.id = ci.thesis_id
      WHERE (t.professor_id = ? OR ci.professor_id = ?)
    `;
    const params = [professorId, professorId, professorId, professorId];

    // Add status filter if provided
    if (status) {
      query += ' AND t.status = ?';
      params.push(status);
    }

    // Add role filter if provided
    if (role) {
      query += ' HAVING role = ?';
      params.push(role);
    }

    query += ' ORDER BY t.assigned_date DESC';

    const [rows] = await connection.query(query, params);
    await connection.end();

    res.json({ success: true, theses: rows });
  } catch (error) {
    console.error('Error fetching filtered theses:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch theses.' });
  }
});

app.post('/api/thesis/:id/add-comment', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id: thesisId } = req.params;
  const { comment } = req.body;
  const professorId = req.session.user.id;

  if (!comment || comment.length > 300) {
    return res.status(400).json({ error: 'Comment is required and must be up to 300 characters.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Check if the professor is associated with the thesis
    const [rows] = await connection.query(`
      SELECT * FROM thesis
      WHERE id = ? AND (professor_id = ? OR id IN (
        SELECT thesis_id FROM committee_invites WHERE professor_id = ? AND status = 'accepted'
      ))
    `, [thesisId, professorId, professorId]);

    if (rows.length === 0) {
      await connection.end();
      return res.status(403).json({ error: 'You are not authorized to comment on this thesis.' });
    }

    // Insert the comment
    await connection.query(`
      INSERT INTO professor_comments (thesis_id, professor_id, comment)
      VALUES (?, ?, ?)
    `, [thesisId, professorId, comment]);

    await connection.end();
    res.json({ success: true, message: 'Comment added successfully.' });
  } catch (err) {
    console.error('Error adding comment:', err);
    res.status(500).json({ error: 'Failed to add comment.' });
  }
});

app.get('/api/thesis/:id/comments', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id: thesisId } = req.params;
  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Check if the professor is associated with the thesis
    const [rows] = await connection.query(`
      SELECT * FROM thesis
      WHERE id = ? AND (professor_id = ? OR id IN (
        SELECT thesis_id FROM committee_invites WHERE professor_id = ? AND status = 'accepted'
      ))
    `, [thesisId, professorId, professorId]);

    if (rows.length === 0) {
      await connection.end();
      return res.status(403).json({ error: 'You are not authorized to view comments for this thesis.' });
    }

    // Fetch comments
    const [comments] = await connection.query(`
      SELECT comment, created_at
      FROM professor_comments
      WHERE thesis_id = ? AND professor_id = ?
      ORDER BY created_at DESC
    `, [thesisId, professorId]);

    await connection.end();
    res.json({ success: true, comments });
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ error: 'Failed to fetch comments.' });
  }
});

app.get('/api/thesis/:id/announcement', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.query(`
      SELECT 
        t.title, 
        t.exam_date, 
        t.exam_mode, 
        t.exam_location, 
        t.exam_link,
        t.committee,
        t.announcement
      FROM thesis t
      WHERE t.id = ?
    `, [thesisId]);

    await connection.end();

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Thesis not found' });
    }

    const thesis = rows[0];

    // If a custom announcement exists, return it
    if (thesis.announcement) {
      return res.json({ success: true, announcement: thesis.announcement });
    }

    // Otherwise, generate one automatically
    if (!thesis.exam_date || (!thesis.exam_location && !thesis.exam_link)) {
      return res.status(400).json({ success: false, message: 'Presentation details are missing' });
    }

    const examPlace = thesis.exam_mode === 'online'
      ? `Online link: ${thesis.exam_link}`
      : `Location: ${thesis.exam_location}`;

    const autoAnnouncement = `
ANNOUNCEMENT

Thesis Presentation:
"${thesis.title}"

Date and Time: ${new Date(thesis.exam_date).toLocaleString('en-GB')}

${examPlace}

Committee Members:
${thesis.committee || 'Pending'}

You are invited to attend the presentation.
    `;

    res.json({ success: true, announcement: autoAnnouncement });

  } catch (error) {
    console.error('Error generating announcement:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


app.get('/api/professor-theses-filtered', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const professorId = req.session.user.id;

    const [theses] = await connection.query(`
      SELECT 
        t.id,
        t.title,
        t.description,
        t.status,
        t.exam_date,
        t.exam_mode,
        t.exam_location,
        t.exam_link,
        CASE 
          WHEN t.professor_id = ? THEN 'Supervisor'
          ELSE 'Committee Member'
        END AS role
      FROM thesis t
      LEFT JOIN committee_invites ci ON t.id = ci.thesis_id
      WHERE t.professor_id = ? OR ci.professor_id = ?
      GROUP BY t.id
    `, [professorId, professorId, professorId]);

    await connection.end();

    res.json({ success: true, theses });

  } catch (err) {
    console.error('Error fetching filtered theses:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/professor-announcements', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.query(`
      SELECT 
        t.id,
        t.title,
        t.exam_date,
        t.exam_mode,
        t.exam_location,
        t.exam_link,
        t.committee,
        t.announcement_text
      FROM thesis t
      WHERE 
        t.professor_id = ? 
        AND t.status = 'under_review'
        AND t.exam_date IS NOT NULL 
        AND (t.exam_location IS NOT NULL OR t.exam_link IS NOT NULL)
    `, [professorId]);

    await connection.end();

    res.json({ success: true, theses: rows });
  } catch (err) {
    console.error('Error fetching announcements:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



// Save custom announcement
app.post('/api/save-announcement/:id', async (req, res) => {
  const thesisId = req.params.id;
  const { announcement } = req.body;

  try {
    const connection = await mysql.createConnection(dbConfig);

    await connection.query(`
      UPDATE thesis
      SET announcement_text = ?
      WHERE id = ?
    `, [announcement, thesisId]);

    await connection.end();
    res.json({ success: true, message: 'Announcement saved.' });
  } catch (err) {
    console.error('Error saving announcement:', err);
    res.status(500).json({ success: false, message: 'Failed to save announcement.' });
  }
});


app.post('/api/thesis/:id/announcement', async (req, res) => {
  const thesisId = req.params.id;
  const { announcement } = req.body;

  try {
    const connection = await mysql.createConnection(dbConfig);

    await connection.query(`
      UPDATE thesis
      SET announcement_text = ?
      WHERE id = ?
    `, [announcement, thesisId]);

    await connection.end();
    res.json({ success: true, message: 'Announcement saved successfully' });

  } catch (error) {
    console.error('Error saving announcement:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/thesis/:id/draft', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Fetch the draft file path for the thesis
    const [rows] = await connection.query(`
      SELECT draft_file_path
      FROM thesis
      WHERE id = ?
    `, [thesisId]);

    await connection.end();

    if (rows.length === 0 || !rows[0].draft_file_path) {
      return res.status(404).json({ error: 'Draft not found or thesis is not under review.' });
    }

    res.json({ success: true, draftFilePath: rows[0].draft_file_path });
  } catch (err) {
    console.error('Error fetching draft:', err);
    res.status(500).json({ error: 'Failed to fetch draft.' });
  }
});

app.get('/api/thesis/:id/status-history', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.query(`
      SELECT thesis_id, new_status, changed_at
      FROM thesis_status_history
      WHERE thesis_id = ?
      ORDER BY id DESC
      LIMIT 1;
    `, [thesisId]);

    await connection.end();

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'No status history found for this thesis.' });
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('Error fetching thesis status history:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/thesis/:id/mark-under-review', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [result] = await connection.query(`
      UPDATE thesis
      SET status = 'under_review'
      WHERE id = ? AND status = 'active'
    `, [thesisId]);

    await connection.end();

    if (result.affectedRows === 0) {
      return res.status(400).json({ success: false, message: 'Thesis not found or not active.' });
    }

    res.json({ success: true, message: 'Thesis marked as under review.' });
  } catch (error) {
    console.error('Error marking thesis as under review:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/professor-thesis-stats', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Count theses where professor is the supervisor
    const [supervisedRows] = await connection.query(`
      SELECT COUNT(*) AS supervised_count
      FROM thesis
      WHERE professor_id = ?
    `, [professorId]);

    const supervisedCount = supervisedRows[0].supervised_count;

    // Count theses where professor is a committee member (excluding supervised ones)
    const [committeeOnlyRows] = await connection.query(`
      SELECT COUNT(*) AS committee_only_count
      FROM committee_invites ci
      JOIN thesis t ON ci.thesis_id = t.id
      WHERE ci.professor_id = ? AND ci.status = 'accepted' AND (t.professor_id IS NULL OR t.professor_id != ?)
    `, [professorId, professorId]);

    const committeeCount = supervisedCount + committeeOnlyRows[0].committee_only_count;

    await connection.end();

    res.json({
      success: true,
      supervised: supervisedCount,
      committee: committeeCount
    });
  } catch (error) {
    console.error('Error fetching thesis stats:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/professor-avg-completion', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const professorId = req.session.user.id;
  try {
    const connection = await mysql.createConnection(dbConfig);

    //Average completion time as supervisor
    const [[supervised]] = await connection.query(`
      SELECT AVG(DATEDIFF(t.exam_date, t.assigned_date)) AS avg_days_supervised
      FROM thesis t
      WHERE t.professor_id = ? AND t.status = 'completed'
    `, [professorId]);

    //Average as committee member (excluding duplicates where also supervisor)
    const [[committee]] = await connection.query(`
      SELECT AVG(DATEDIFF(t.exam_date, t.assigned_date)) AS avg_days_committee
      FROM thesis t
      JOIN committee_invites ci ON t.id = ci.thesis_id
      WHERE ci.professor_id = ? 
        AND t.status = 'completed'
        AND (t.professor_id IS NULL OR t.professor_id != ?)
    `, [professorId, professorId]);

    await connection.end();

    res.json({
      success: true,
      avg_supervised: supervised.avg_days_supervised || 0,
      avg_committee: committee.avg_days_committee || 0
    });

  } catch (err) {
    console.error('Error calculating averages:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/thesis/:id/grade', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id: thesisId } = req.params;
  const { qualityGrade, durationGrade, textQualityGrade, presentationGrade, comments } = req.body;
  const professorId = req.session.user.id;

  // Validate grades
  if (
    !Number.isInteger(qualityGrade) || qualityGrade < 0 || qualityGrade > 10 ||
    !Number.isInteger(durationGrade) || durationGrade < 0 || durationGrade > 10 ||
    !Number.isInteger(textQualityGrade) || textQualityGrade < 0 || textQualityGrade > 10 ||
    !Number.isInteger(presentationGrade) || presentationGrade < 0 || presentationGrade > 10
  ) {
    return res.status(400).json({ error: 'Grades must be integers between 0 and 10.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Check if the professor is part of the committee for this thesis
    const [rows] = await connection.query(`
      SELECT 1
      FROM thesis t
      LEFT JOIN committee_invites ci ON t.id = ci.thesis_id
      WHERE t.id = ?
      AND (t.professor_id = ? OR ci.professor_id = ?)
      AND t.grading_open = TRUE;
    `, [thesisId, professorId , professorId]);

    if (rows.length === 0) {
      await connection.end();
      return res.status(403).json({ error: 'You are not authorized to grade this thesis.' });
    }

    // Insert or update the grades
    await connection.query(`
      INSERT INTO committee_grades (thesis_id, professor_id, quality_grade, duration_grade, text_quality_grade, presentation_grade, comments)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        quality_grade = VALUES(quality_grade),
        duration_grade = VALUES(duration_grade),
        text_quality_grade = VALUES(text_quality_grade),
        presentation_grade = VALUES(presentation_grade),
        comments = VALUES(comments)
    `, [thesisId, professorId, qualityGrade, durationGrade, textQualityGrade, presentationGrade, comments]);

    await connection.end();
    res.json({ success: true, message: 'Grades submitted successfully.' });
  } catch (err) {
    console.error('Error submitting grades:', err);
    res.status(500).json({ error: 'Failed to submit grades.' });
  }
});

app.get('/api/thesis/:id/committee-grades', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id: thesisId } = req.params;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Fetch grades from the committee_grades table
    const [rows] = await connection.query(`
      SELECT u.username AS professor, cg.quality_grade, cg.duration_grade, cg.text_quality_grade, cg.presentation_grade, cg.final_grade, cg.comments
      FROM committee_grades cg
      JOIN users u ON cg.professor_id = u.id
      WHERE cg.thesis_id = ?
    `, [thesisId]);

    await connection.end();
    res.json({ success: true, grades: rows });
  } catch (err) {
    console.error('Error fetching committee grades:', err);
    res.status(500).json({ error: 'Failed to fetch committee grades.' });
  }
});

app.post('/api/thesis/:id/open-grading', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const thesisId = req.params.id;
  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Ensure the user is the supervisor of the thesis
    const [[row]] = await connection.query(
      'SELECT id FROM thesis WHERE id = ? AND professor_id = ?',
      [thesisId, professorId]
    );

    if (!row) {
      await connection.end();
      return res.status(403).json({ error: 'Only the supervisor can open grading.' });
    }

    await connection.query(
      'UPDATE thesis SET grading_open = TRUE WHERE id = ?',
      [thesisId]
    );

    await connection.end();
    res.json({ success: true });
  } catch (err) {
    console.error('Error opening grading:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/professor-avg-grades', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // As Supervisor
    const [[supervised]] = await connection.query(`
      SELECT AVG((quality_grade + duration_grade + text_quality_grade + presentation_grade) / 4) AS avg_supervised
      FROM committee_grades
      WHERE thesis_id IN (
        SELECT id FROM thesis WHERE professor_id = ?
      ) AND professor_id = ?
    `, [professorId, professorId]);

    // As Committee Member (excluding if supervisor)
    const [[committee]] = await connection.query(`
      SELECT AVG((quality_grade + duration_grade + text_quality_grade + presentation_grade) / 4) AS avg_committee
      FROM committee_grades
      WHERE professor_id = ?
        AND thesis_id NOT IN (
          SELECT id FROM thesis WHERE professor_id = ?
        )
    `, [professorId, professorId]);

    await connection.end();

    res.json({
      success: true,
      avg_supervised: supervised.avg_supervised || 0,
      avg_committee: committee.avg_committee || 0
    });
  } catch (err) {
    console.error('Error calculating average grades:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/thesis/:id/details', async (req, res) => {
  const thesisId = req.params.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Fetch thesis core details and student info
    const [[thesis]] = await connection.query(`
      SELECT 
        t.id,
        t.title,
        t.description,
        t.status,
        t.committee,
        u.username AS student_name
      FROM thesis t
      LEFT JOIN users u ON t.student_id = u.id
      WHERE t.id = ?
    `, [thesisId]);

    if (!thesis) {
      await connection.end();
      return res.status(404).json({ success: false, message: 'Thesis not found' });
    }

    // Fetch status history (timeline)
    const [timeline] = await connection.query(`
      SELECT old_status, new_status, changed_at
      FROM thesis_status_history
      WHERE thesis_id = ?
      ORDER BY changed_at ASC
    `, [thesisId]);

    // Fetch average final grade
    const [[gradeData]] = await connection.query(`
      SELECT 
        ROUND(AVG((quality_grade + duration_grade + text_quality_grade + presentation_grade) / 4), 2) AS final_grade
      FROM committee_grades
      WHERE thesis_id = ?
    `, [thesisId]);

    // Attach final_grade to the thesis object
    thesis.final_grade = gradeData.final_grade || null;

    await connection.end();

    res.json({
      success: true,
      thesis,
      timeline,
      final_grade: gradeData.final_grade || null
    });

  } catch (err) {
    console.error('Error loading thesis details:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



app.get('/api/professor-theses-details', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Fetch all theses for the professor
    const [theses] = await connection.query(`
      SELECT 
        t.id,
        t.title,
        t.description,
        t.status,
        t.committee,
        u.username AS student_name
      FROM thesis t
      LEFT JOIN users u ON t.student_id = u.id
      WHERE t.professor_id = ?
    `, [professorId]);

    // Fetch additional details for each thesis
    for (const thesis of theses) {
      // Fetch status history (timeline)
      const [timeline] = await connection.query(`
        SELECT old_status, new_status, changed_at
        FROM thesis_status_history
        WHERE thesis_id = ?
        ORDER BY changed_at ASC
      `, [thesis.id]);

      // Fetch average final grade
      const [[gradeData]] = await connection.query(`
        SELECT 
          ROUND(AVG((quality_grade + duration_grade + text_quality_grade + presentation_grade) / 4), 2) AS final_grade
        FROM committee_grades
        WHERE thesis_id = ?
      `, [thesis.id]);

      // Attach additional data to the thesis object
      thesis.timeline = timeline;
      thesis.final_grade = gradeData ? gradeData.final_grade : null;
    }

    await connection.end();

    res.json({ success: true, theses });
  } catch (error) {
    console.error('Error fetching professor theses details:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/export-theses/:format', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'professor') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  // const format = req.params.format; // Get format from the endpoint parameter
  // if (!['csv', 'json'].includes(format)) {
  //   return res.status(400).json({ success: false, message: 'Invalid format. Use "csv" or "json".' });
  // }
  const format = req.params.format === 'csv' ? 'csv' : 'json'; // Default to JSON if not CSV
  const professorId = req.session.user.id;

  try {
    const connection = await mysql.createConnection(dbConfig);

    // Fetch all theses for the professor
    const [theses] = await connection.query(`
      SELECT 
        t.id,
        t.title,
        t.description,
        t.status,
        t.committee,
        u.username AS student_name
      FROM thesis t
      LEFT JOIN users u ON t.student_id = u.id
      WHERE t.professor_id = ?
    `, [professorId]);

    // Fetch additional details for each thesis
    for (const thesis of theses) {
      const [timeline] = await connection.query(`
        SELECT old_status, new_status, changed_at
        FROM thesis_status_history
        WHERE thesis_id = ?
        ORDER BY changed_at ASC
      `, [thesis.id]);

      const [[gradeData]] = await connection.query(`
        SELECT 
          ROUND(AVG((quality_grade + duration_grade + text_quality_grade + presentation_grade) / 4), 2) AS final_grade
        FROM committee_grades
        WHERE thesis_id = ?
      `, [thesis.id]);

      thesis.timeline = timeline;
      thesis.final_grade = gradeData ? gradeData.final_grade : null;
    }

    await connection.end();

    if (format === 'csv') {
      // Convert data to CSV
      const csvHeaders = ['ID', 'Title', 'Description', 'Status', 'Committee', 'Student Name', 'Final Grade'];
      const csvRows = theses.map(thesis => [
        thesis.id,
        thesis.title,
        thesis.description,
        thesis.status,
        thesis.committee || 'N/A',
        thesis.student_name || 'N/A',
        thesis.final_grade || 'N/A'
      ]);

      const csvContent = [
        csvHeaders.join(','),
        ...csvRows.map(row => row.map(value => `"${value}"`).join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="theses.csv"');
      res.send(csvContent);
    } else {
      // Return data as JSON
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="theses.json"');
      res.send(theses.map(thesis => JSON.stringify(thesis, null, 2)).join('\n\n'));
    }
  } catch (error) {
    console.error('Error exporting theses:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/announcements', async (req, res) => {
    const { startDate, endDate } = req.query;

    try {
        const connection = await mysql.createConnection(dbConfig);
        let query = `
            SELECT announcement_text AS text, exam_date
            FROM thesis
            WHERE announcement_text IS NOT NULL AND announcement_text != ''
        `;
        const params = [];

        if (startDate) {
            query += " AND exam_date >= ?";
            params.push(startDate);
        }
        if (endDate) {
            query += " AND exam_date <= ?";
            params.push(endDate);
        }

        const [rows] = await connection.query(query, params);
        await connection.end();
        res.json(rows);
    } catch (error) {
        console.error("Error fetching announcements:", error);
        res.status(500).json({ error: "Failed to fetch announcements" });
    }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
