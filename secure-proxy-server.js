const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const submitLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5, // limit each IP to 5 form submissions per minute
    message: 'Too many form submissions, please wait a moment.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to false for Vercel deployment
        httpOnly: true,
        maxAge: 2 * 60 * 60 * 1000, // 2 hours
        sameSite: 'lax' // Add sameSite for better compatibility
    }
}));

// Enable CORS for specific origins only
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // Allow localhost and Vercel domains
        const allowedOrigins = [
            'http://localhost:3000',
            'https://localhost:3000',
            /^https:\/\/.*\.vercel\.app$/,
            /^https:\/\/.*\.vercel\.dev$/
        ];
        
        const isAllowed = allowedOrigins.some(allowedOrigin => {
            if (typeof allowedOrigin === 'string') {
                return origin === allowedOrigin;
            } else {
                return allowedOrigin.test(origin);
            }
        });
        
        if (isAllowed) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Parse JSON bodies with size limit
app.use(express.json({ limit: '10mb' }));

// Do NOT broadly serve the entire directory as static to avoid bypassing auth
// If you add assets (images/css/js), mount a specific public dir like:
// app.use('/assets', express.static(path.join(__dirname, 'assets')));

// Simple authentication credentials (in production, use environment variables)
const AUTH_CREDENTIALS = {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'pawnshop123' // Change this!
};

// Users store (file-based for simplicity)
const USERS_FILE = path.join(__dirname, 'users.json');
const INVITE_CODE = process.env.INVITE_CODE || 'INVITE-ONLY-FOR-DAD';

function loadUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            return [];
        }
        const raw = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load users.json:', e);
        return [];
    }
}

function saveUsers(users) {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (e) {
        console.error('Failed to save users.json:', e);
    }
}

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.authenticated) {
        return next();
    }

    // For browser navigations (HTML), redirect to login instead of JSON
    if (req.method === 'GET' && req.accepts('html')) {
        return res.redirect('/login');
    }

    return res.status(401).json({
        success: false,
        message: 'Authentication required'
    });
}

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // 1) Try environment admin credentials
        if (username === AUTH_CREDENTIALS.username && password === AUTH_CREDENTIALS.password) {
            req.session.authenticated = true;
            req.session.username = username;
            return res.json({ success: true, message: 'Login successful' });
        }

        // 2) Try users.json
        const users = loadUsers();
        const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (user) {
            const ok = await bcrypt.compare(password, user.passwordHash);
            if (ok) {
                req.session.authenticated = true;
                req.session.username = user.username;
                return res.json({ success: true, message: 'Login successful' });
            }
        }

        res.status(401).json({ success: false, message: 'Invalid credentials' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Signup endpoint (invite-code protected)
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password, inviteCode } = req.body;

        if (!inviteCode || inviteCode !== INVITE_CODE) {
            return res.status(403).json({ success: false, message: 'Invalid invite code' });
        }

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username and password are required' });
        }

        const users = loadUsers();
        if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
            return res.status(409).json({ success: false, message: 'Username already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const newUser = { username, passwordHash, createdAt: new Date().toISOString() };
        users.push(newUser);
        saveUsers(users);

        res.json({ success: true, message: 'Signup successful. You can now log in.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ success: false, message: 'Signup failed' });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: 'Logout failed'
            });
        }
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    });
});

// Check authentication status
app.get('/api/auth-status', (req, res) => {
    res.json({
        authenticated: !!req.session.authenticated,
        username: req.session.username || null
    });
});

// Input validation function
function validateFormData(data) {
    const errors = [];
    
    // Required fields
    const requiredFields = ['pawnNumber', 'customerName', 'fatherHusbandName', 'address', 'dateOfPawn', 'amount', 'weight', 'articleDescription'];
    
    for (const field of requiredFields) {
        if (!data[field] || data[field].toString().trim() === '') {
            errors.push(`${field} is required`);
        }
    }
    
    // Validate pawn number format
    if (data.pawnNumber && !/^[A-Za-z0-9\s\-_]+$/.test(data.pawnNumber)) {
        errors.push('Pawn number contains invalid characters');
    }
    
    // Validate amount
    if (data.amount && (isNaN(data.amount) || data.amount < 0)) {
        errors.push('Amount must be a positive number');
    }
    
    // Validate weight
    if (data.weight && (isNaN(data.weight) || data.weight < 0)) {
        errors.push('Weight must be a positive number');
    }
    
    // Validate date
    if (data.dateOfPawn && isNaN(Date.parse(data.dateOfPawn))) {
        errors.push('Invalid date format');
    }
    
    // Sanitize string inputs
    const stringFields = ['pawnNumber', 'customerName', 'fatherHusbandName', 'address', 'articleDescription'];
    for (const field of stringFields) {
        if (data[field]) {
            data[field] = data[field].toString().trim().substring(0, 500); // Limit length
        }
    }
    
    return { isValid: errors.length === 0, errors, sanitizedData: data };
}

// Serve the secure form (requires authentication)
app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'pawn-shop-secure.html'));
});

// Explicitly protect direct access to the secure HTML file
app.get('/pawn-shop-secure.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'pawn-shop-secure.html'));
});

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

// Secure proxy endpoint to Google Apps Script
app.post('/api/submit', submitLimiter, requireAuth, async (req, res) => {
    try {
        // Validate input data
        const validation = validateFormData(req.body);
        if (!validation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validation.errors
            });
        }

        const googleScriptUrl = process.env.GOOGLE_SCRIPT_URL;
        
        if (!googleScriptUrl) {
            return res.status(500).json({ 
                success: false, 
                message: 'Google Apps Script URL not configured' 
            });
        }

        // Log the submission for audit
        console.log(`Form submission by ${req.session.username} at ${new Date().toISOString()}`);

        // Forward the request to Google Apps Script with sanitized data
        const response = await fetch(googleScriptUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(validation.sanitizedData)
        });

        let result;
        try {
            const responseText = await response.text();
            result = JSON.parse(responseText);
        } catch (parseError) {
            console.error('Failed to parse Google Apps Script response:', parseError);
            console.error('Response was:', await response.text());
            return res.status(500).json({
                success: false,
                message: 'Google Apps Script returned invalid response'
            });
        }
        
        if (response.ok) {
            res.json({
                success: true,
                message: 'Article submitted successfully!',
                pawnNumber: result.pawnNumber || validation.sanitizedData.pawnNumber
            });
        } else {
            res.status(400).json({
                success: false,
                message: result.message || 'Google Apps Script error'
            });
        }

    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit to Google Sheets'
        });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Secure proxy server running',
        authenticated: !!req.session.authenticated
    });
});

app.listen(PORT, () => {
    console.log(`🔒 Secure Proxy Server Started on port ${PORT}`);
    console.log(`📡 Google Apps Script: ${process.env.GOOGLE_SCRIPT_URL ? '✅ Configured' : '❌ Not configured'}`);
    console.log(`🔐 Authentication: ${AUTH_CREDENTIALS.username} / ${AUTH_CREDENTIALS.password}`);
    console.log(`🌐 Access: http://localhost:${PORT}/login`);
    console.log(`✉️  Invite code (set INVITE_CODE env): ${INVITE_CODE}`);
});
