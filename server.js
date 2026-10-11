const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secretkey123';

app.use(cors());
app.use(express.json());

// In-memory data store
const users = [];
const movies = [];

// Middleware Authenticate Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'Family Movie Watchlist API is running' });
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
    role: role || 'member'
  };

  users.push(newUser);
  res.status(201).json({ message: 'User registered successfully' });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

// Get Watchlist
app.get('/api/movies', authenticateToken, (req, res) => {
  res.json(movies);
});

// Add Movie
app.post('/api/movies', authenticateToken, (req, res) => {
  const { title, genre, year } = req.body;
  if (!title) {
    return res.status(400).json({ error: 'Movie title is required' });
  }

  const newMovie = {
    id: movies.length + 1,
    title,
    genre: genre || 'General',
    year: year || new Date().getFullYear(),
    addedBy: req.user.username,
    watched: false
  };

  movies.push(newMovie);
  res.status(201).json(newMovie);
});

// Delete Movie (Admin only)
app.delete('/api/movies/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const movieId = parseInt(req.params.id);
  const index = movies.findIndex(m => m.id === movieId);

  if (index === -1) {
    return res.status(404).json({ error: 'Movie not found' });
  }

  movies.splice(index, 1);
  res.json({ message: 'Movie removed from watchlist' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
