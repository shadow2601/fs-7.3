const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET = 'your_jwt_secret'; // Use a secure secret key in production

app.use(express.json());

// Dummy users for demo
const users = [
  { username: 'adminUser', password: 'admin123', role: 'Admin' },
  { username: 'modUser', password: 'mod123', role: 'Moderator' },
  { username: 'normalUser', password: 'user123', role: 'User' }
];

// Auth: Login endpoint, returns JWT
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    u => u.username === username && u.password === password
  );
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const payload = {
    username: user.username,
    role: user.role
  };
  const token = jwt.sign(payload, SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// JWT + Role middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token missing' });
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token invalid' });
    req.user = user;
    next();
  });
}

function requireRole(role) {
  // Middleware to check user role
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      return next();
    } else {
      return res.status(403).json({ message: 'Access denied: insufficient role' });
    }
  };
}

// Admin dashboard: only for Admin
app.get('/admin-dashboard', authenticateToken, requireRole('Admin'), (req, res) => {
  res.json({
    message: 'Welcome to the Admin dashboard!',
    user: {
      username: req.user.username,
      role: req.user.role,
      iat: req.user.iat,
      exp: req.user.exp
    }
  });
});

// Moderator panel: only for Moderator
app.get('/moderator-panel', authenticateToken, requireRole('Moderator'), (req, res) => {
  res.json({
    message: 'Welcome to the Moderator panel!',
    user: {
      username: req.user.username,
      role: req.user.role,
      iat: req.user.iat,
      exp: req.user.exp
    }
  });
});

// User profile: accessible by any authenticated user (Admin, Moderator, or User)
app.get('/user-profile', authenticateToken, (req, res) => {
  res.json({
    message: `Welcome to your profile, ${req.user.username}.`,
    user: {
      username: req.user.username,
      role: req.user.role,
      iat: req.user.iat,
      exp: req.user.exp
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
