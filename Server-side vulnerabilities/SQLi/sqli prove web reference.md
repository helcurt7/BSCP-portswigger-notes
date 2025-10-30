Here's the PostgreSQL version with detailed explanations of each security segment:

## **1. Package.json**
```json
{
  "name": "sql-injection-proof-postgres",
  "version": "1.0.0",
  "description": "Express app with PostgreSQL SQL injection protection",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.0",
    "express-rate-limit": "^6.0.0",
    "helmet": "^6.0.0",
    "pg": "^8.8.0",
    "pg-format": "^1.0.4",
    "express-validator": "^6.0.0",
    "bcryptjs": "^2.4.3"
  }
}
```

## **2. Main Application (app.js)**
```javascript
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const format = require('pg-format');

const app = express();
const PORT = 3000;

// ==================== SECURITY SEGMENT 1: HELMET & RATE LIMITING ====================
// WHY: Prevents common attacks like XSS, clickjacking, and brute force
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"]
    }
  }
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use(limiter);
// ====================================================================================

// ==================== SECURITY SEGMENT 2: INPUT SIZE LIMITS ====================
// WHY: Prevents buffer overflow and large payload attacks
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
// ===============================================================================

// PostgreSQL Connection Pool
const pool = new Pool({
  user: 'your_username',
  host: 'localhost',
  database: 'secure_app',
  password: 'your_password',
  port: 5432,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Initialize Database (run once)
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Insert sample user with hashed password
    const hashedPassword = await bcrypt.hash('securepassword123', 12);
    await pool.query(
      'INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING',
      ['admin', hashedPassword, 'admin@example.com']
    );
    
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// ==================== SECURITY SEGMENT 3: INPUT VALIDATION ====================
// WHY: Whitelist approach - only allow known good characters, reject everything else
const validateUserInput = [
  body('username')
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be 3-20 characters')
    .matches(/^[a-zA-Z0-9_]+$/) // ONLY letters, numbers, underscore
    .withMessage('Username can only contain letters, numbers, and underscores')
    .trim(),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase and number'),
  
  body('email')
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail(), // Sanitizes email
  
  body('search')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Search query too long')
    .matches(/^[a-zA-Z0-9@.\s-_]+$/) // Limited character set
    .withMessage('Invalid search characters')
    .trim()
];
// ==============================================================================

// ==================== SECURITY SEGMENT 4: PARAMETERIZED QUERIES ====================
// WHY: This is the PRIMARY defense - separates SQL code from data
class SafePostgres {
  // SAFE: Uses parameterized queries - user input is NEVER in SQL string
  static async authenticateUser(username, password) {
    const sql = 'SELECT * FROM users WHERE username = $1';
    const result = await pool.query(sql, [username]); // $1 is replaced safely
    
    if (result.rows.length === 0) return null;
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    return isValid ? user : null;
  }

  // SAFE: Even LIKE queries use parameters
  static async searchUsers(searchTerm) {
    const sql = 'SELECT id, username, email FROM users WHERE username LIKE $1 OR email LIKE $1 LIMIT 10';
    const likeTerm = `%${searchTerm}%`; // Constructed in JavaScript, not SQL
    const result = await pool.query(sql, [likeTerm]);
    return result.rows;
  }

  // SAFE: User input goes into parameterized positions $1, $2, $3
  static async createUser(username, password, email) {
    const passwordHash = await bcrypt.hash(password, 12);
    const sql = 'INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id';
    const result = await pool.query(sql, [username, passwordHash, email]);
    return result.rows[0];
  }

  // SAFE: Numeric parameters are also parameterized
  static async getUserById(userId) {
    const sql = 'SELECT id, username, email FROM users WHERE id = $1';
    const result = await pool.query(sql, [userId]);
    return result.rows[0] || null;
  }

  // ==================== SECURITY SEGMENT 5: SAFE DYNAMIC SQL ====================
  // WHY: When dynamic SQL is needed, use pg-format for safe construction
  static async safeOrderedUsers(orderBy = 'username', direction = 'ASC') {
    // Whitelist allowed column names and directions
    const allowedColumns = ['username', 'email', 'created_at'];
    const allowedDirections = ['ASC', 'DESC'];
    
    if (!allowedColumns.includes(orderBy) || !allowedDirections.includes(direction.toUpperCase())) {
      throw new Error('Invalid order parameters');
    }
    
    // SAFE: pg-format properly escapes identifiers
    const sql = format('SELECT * FROM users ORDER BY %I %s', orderBy, direction);
    const result = await pool.query(sql);
    return result.rows;
  }
  // ==============================================================================
}
// ====================================================================================

// Routes
app.get('/', (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>PostgreSQL SQL Injection Proof App</h1>
        <p>Try SQL injection attacks - they won't work!</p>
        <form action="/login" method="post">
          <input name="username" placeholder="Username">
          <input name="password" type="password" placeholder="Password">
          <button>Login</button>
        </form>
      </body>
    </html>
  `);
});

// ==================== SECURITY SEGMENT 6: VALIDATION + PARAMETERIZED EXECUTION ====================
app.post('/login', validateUserInput, async (req, res) => {
  // Input validation first
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      errors: errors.array(),
      message: 'Input validation failed' 
    });
  }

  const { username, password } = req.body;

  try {
    // THEN: Parameterized query execution
    const user = await SafePostgres.authenticateUser(username, password);
    
    if (user) {
      res.json({ 
        success: true, 
        message: 'Login successful',
        user: { id: user.id, username: user.username }
      });
    } else {
      // Generic error message - don't reveal which was wrong
      res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
  } catch (error) {
    // ==================== SECURITY SEGMENT 7: PROPER ERROR HANDLING ====================
    // WHY: Never expose database errors to users
    console.error('Database error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Authentication service unavailable' 
    });
    // ===================================================================================
  }
});

app.post('/search', [
  body('search')
    .isLength({ min: 1, max: 50 })
    .withMessage('Search must be 1-50 characters')
    .matches(/^[a-zA-Z0-9@.\s-_]+$/)
    .withMessage('Invalid search characters')
    .trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { search } = req.body;

  try {
    const users = await SafePostgres.searchUsers(search);
    res.json({ success: true, users });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ success: false, message: 'Search service unavailable' });
  }
});

app.post('/register', validateUserInput, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, email } = req.body;

  try {
    const result = await SafePostgres.createUser(username, password, email);
    res.json({ 
      success: true, 
      message: 'User created successfully',
      userId: result.id 
    });
  } catch (error) {
    if (error.code === '23505') { // PostgreSQL unique violation
      res.status(400).json({ 
        success: false, 
        message: 'Username or email already exists' 
      });
    } else {
      console.error('Registration error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Registration service unavailable' 
      });
    }
  }
});

// ==================== SECURITY SEGMENT 8: TYPE VALIDATION ====================
app.get('/user/:id', async (req, res) => {
  const userId = parseInt(req.params.id);
  
  // WHY: Validate type and range before database query
  if (isNaN(userId) || userId <= 0 || userId > 2147483647) { // PostgreSQL INTEGER max
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid user ID format' 
    });
  }

  try {
    const user = await SafePostgres.getUserById(userId);
    if (user) {
      res.json({ success: true, user });
    } else {
      res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    console.error('User fetch error:', error);
    res.status(500).json({ success: false, message: 'Service unavailable' });
  }
});
// =============================================================================

// Test endpoint to demonstrate security
app.post('/test-injection', async (req, res) => {
  const { input } = req.body;
  
  try {
    // This demonstrates that even direct user input in parameterized queries is safe
    const result = await pool.query('SELECT $1 as test_input', [input]);
    res.json({ 
      success: true, 
      input: result.rows[0].test_input,
      message: 'Input was safely handled as data, not SQL code'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error processing input' });
  }
});

// Start Server
async function startServer() {
  await initializeDatabase();
  
  app.listen(PORT, () => {
    console.log(`PostgreSQL Secure server running on http://localhost:${PORT}`);
    console.log('\n=== SQL Injection Protection Features ===');
    console.log('✅ 1. Parameterized Queries (Primary Defense)');
    console.log('✅ 2. Input Validation & Whitelisting');
    console.log('✅ 3. Input Size Limits');
    console.log('✅ 4. Rate Limiting');
    console.log('✅ 5. Security Headers (Helmet)');
    console.log('✅ 6. Proper Error Handling');
    console.log('✅ 7. Type & Range Validation');
    console.log('✅ 8. Password Hashing (bcrypt)');
    console.log('✅ 9. Connection Pooling with Limits');
    console.log('\nTry SQL injection attacks - they will be blocked!');
  });
}

startServer().catch(console.error);

module.exports = app;
```

## **3. Database Setup (database.sql)**
```sql
-- Create database and user
CREATE DATABASE secure_app;
CREATE USER secure_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE secure_app TO secure_user;

-- Connect to secure_app and create tables
\c secure_app;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- The application will initialize sample data
```

## **4. Test SQL Injection Attacks That Will FAIL**

```bash
# These will all be blocked:

# 1. Basic SQL injection
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1","password":"x"}'

# 2. UNION-based attack  
curl -X POST http://localhost:3000/search \
  -H "Content-Type: application/json" \
  -d '{"search":"test'\'' UNION SELECT * FROM users--"}'

# 3. Error-based attack
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' AND 1=CAST((SELECT version()) AS int)--","password":"x"}'

# 4. Time-based blind attack
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' AND (SELECT pg_sleep(10))--","password":"x"}'
```

## **Key Security Explanations:**

### **1. Parameterized Queries (MAIN DEFENSE)**
```javascript
// UNSAFE - SQL injection possible
const sql = `SELECT * FROM users WHERE username = '${username}'`;

// SAFE - PostgreSQL parameterized query
const sql = 'SELECT * FROM users WHERE username = $1';
const result = await pool.query(sql, [username]);
```
**Why it works:** PostgreSQL treats `$1` as a data placeholder. User input can NEVER become executable SQL code.

### **2. Input Validation (DEFENSE IN DEPTH)**
```javascript
.matches(/^[a-zA-Z0-9_]+$/) // Only allow these characters
```
**Why it works:** Whitelist approach - even if parameterization fails, malicious characters like `'`, `;`, `--` are blocked.

### **3. Error Handling (INFORMATION LEAK PREVENTION)**
```javascript
} catch (error) {
  console.error('Database error:', error); // Log internally
  res.status(500).json({ message: 'Service unavailable' }); // Generic user message
}
```
**Why it works:** Attackers can't learn about database structure from error messages.

### **4. Type Validation**
```javascript
const userId = parseInt(req.params.id);
if (isNaN(userId) || userId <= 0) {
  return res.status(400).json({ message: 'Invalid user ID format' });
}
```
**Why it works:** Prevents type-based attacks and ensures data integrity.

This implementation provides **defense in depth** with multiple layers of protection, making SQL injection practically impossible.
