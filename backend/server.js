const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const hpp = require("hpp");
const path = require("path");
const passport = require("passport");
const session = require("express-session");
const axios = require("axios");
require("dotenv").config();

// Import rate limiters
const { apiLimiter } = require("./middleware/rateLimiter");

// Initialize Google OAuth
require("./config/googleAuth");

// Import JSON storage
const {
  collegesStorage,
  usersStorage,
  mentorsStorage,
} = require("./utils/jsonStorage");

// Try to use file store, fallback to memory store if not available
let sessionStore;
try {
  const FileStore = require("session-file-store")(session);
  sessionStore = new FileStore({
    path: "./sessions",
    ttl: 3600, // 1 hour
    retries: 0,
    logFn: () => {}, // Disable logging to reduce memory usage
  });
  console.log("✅ Using file-based session store");
} catch (err) {
  console.warn(
    "⚠️ File store not available, using memory store (not recommended for production)",
  );
  sessionStore = null; // Will use default memory store
}

// Initialize Express app
const app = express();

app.use("/api/", apiLimiter);
console.log("✅ Using basic rate limiting for API protection");

// Trust proxy (for accurate IP addresses behind reverse proxy)
app.set("trust proxy", 1);

// Add session middleware
const sessionConfig = {
  secret:
    process.env.SESSION_SECRET ||
    "medscore_session_secret_key_2025_production_v1",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", // HTTPS in production
    maxAge: 1 * 60 * 60 * 1000, // 1 hour
  },
  rolling: true,
};

// Add store only if available
if (sessionStore) {
  sessionConfig.store = sessionStore;
}

app.use(session(sessionConfig));

// ===== SECURITY MIDDLEWARE =====

// Helmet - Set security headers
// CSP temporarily disabled for testing
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);

// HSTS - Force HTTPS
app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  }),
);

// CORS - Cross-Origin Resource Sharing
const corsOptions = {
  origin: [
    "https://medscore.xyz",
    "https://www.medscore.xyz",
    "https://api.medscore.xyz",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    process.env.FRONTEND_URL,
    ...(process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",")
      : []),
  ].filter(Boolean),
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-API-Key",
    "X-Requested-With",
  ],
  exposedHeaders: ["Authorization"],
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options("*", cors(corsOptions));

// Body parser middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Passport middleware (this should come AFTER session middleware)
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect to frontend with user data
    const user = req.user;

    // Generate JWT token for the user
    const jwt = require("jsonwebtoken");
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || "30d" },
    );

    // Redirect to frontend with token
    res.redirect(
      `${process.env.FRONTEND_URL || "https://www.medscore.xyz"}?token=${token}&user=${encodeURIComponent(JSON.stringify(user))}`,
    );
  },
);

// Data sanitization - MySQL injection protection handled by mysql2
// XSS protection handled by Helmet

// Prevent parameter pollution
app.use(hpp());

// ===== BOT PROTECTION =====
// Bot protection handled by Arcjet (if available) or basic rate limiting
// Arcjet middleware already applied above if configured

// HTTP request logger
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
} else {
  app.use(morgan("combined"));
}

// Initialize logger
const logger = require("./utils/logger");

// ===== API ROUTES =====

// Serve static files from uploads directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Import routes
console.log("Loading routes...");
const authRoutes = require("./routes/auth");
console.log("Auth routes loaded");
const adminRoutes = require("./routes/admin");
console.log("Admin routes loaded");
const adminRolesRoutes = require("./routes/adminRoles");
console.log("Admin roles routes loaded");
const collegeRoutes = require("./routes/colleges");
console.log("College routes loaded");
const cutoffRoutes = require("./routes/cutoffs");
console.log("Cutoff routes loaded");
const mentorRoutes = require("./routes/mentors");
console.log("Mentor routes loaded");
const bookingRoutes = require("./routes/bookings");
console.log("Booking routes loaded");
const materialRoutes = require("./routes/materials");
console.log("Material routes loaded");
const purchaseRoutes = require("./routes/purchases");
console.log("Purchase routes loaded");
const paymentRoutes = require("./routes/payments");
console.log("Payment routes loaded");
const plannerRoutes = require("./routes/planner");
console.log("Planner routes loaded");
const mentorApplicationRoutes = require("./routes/mentorApplications");
console.log("Mentor application routes loaded");
const googleAuthRoutes = require("./routes/googleAuth");
console.log("Google auth routes loaded");
const uploadRoutes = require("./routes/uploads");
console.log("Upload routes loaded");

// Import rate limiters for protection
const {
  loginLimiter,
  signupLimiter,
  uploadLimiter,
  otpLimiter,
} = require("./middleware/rateLimiter");

// API routes with basic rate limiting protection
// Fallback to basic rate limiting
// Scope login rate limiting at the route level inside auth routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/admin/roles", adminRolesRoutes);
app.use("/api/bookings", bookingRoutes);
app.use("/api/purchases", purchaseRoutes);
app.use("/api/payments", paymentRoutes);
app.use("/api/planner", plannerRoutes);
app.use("/api/mentor-applications", mentorApplicationRoutes);
app.use("/api/auth/google", googleAuthRoutes);
app.use("/api/uploads", uploadLimiter, uploadRoutes);

// Public routes
app.use("/api/colleges", collegeRoutes);
app.use("/api/cutoffs", cutoffRoutes);
app.use("/api/mentors", mentorRoutes);
app.use("/api/materials", materialRoutes);

// Health check endpoints - Fixed for api.medscore.xyz deployment
app.get("/health", (req, res) => {
  // Simple health check without database dependency (prevents Render timeout)
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Additional health endpoint for compatibility
app.get("/api/health", async (req, res) => {
  // Detailed health check with database status
  let dbStatus = "unknown";
  try {
    const connection = await pool.getConnection();
    await connection.query("SELECT 1");
    connection.release();
    dbStatus = "connected";
  } catch (error) {
    dbStatus = "disconnected";
  }

  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "production",
    database: dbStatus,
    uptime: process.uptime(),
    version: "1.0.0",
  });
});

// App status endpoint
app.get("/app-status", (req, res) => {
  res.json({
    status: "OK",
    message: "MedScore Backend is running",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "production",
    server: "CloudLinux/cPanel",
    node_version: process.version,
    uptime: process.uptime(),
    version: "1.0.0",
  });
});

// CloudLinux specific startup status endpoint
app.get("/startup-status", (req, res) => {
  res.json({
    status: "OK",
    environment: "CloudLinux Production",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    cloudlinux: true,
    nodeVersion: process.version,
  });
});

// Render keep-alive endpoint - Prevents free tier from sleeping
app.get("/keep-alive", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Keep-alive ping successful",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Internal keep-alive mechanism - Ping self every 10 minutes to prevent Render sleep
const startKeepAlive = () => {
  const keepAliveInterval = 10 * 60 * 1000; // 10 minutes
  const baseURL = process.env.BACKEND_URL || "https://medscore-backend.onrender.com";
  
  setInterval(async () => {
    try {
      const response = await axios.get(`${baseURL}/keep-alive`, { timeout: 5000 });
      if (response.status === 200) {
        console.log("✅ Keep-alive ping successful - Render will not sleep");
      } else {
        console.warn("⚠️ Keep-alive ping failed:", response.status);
      }
    } catch (error) {
      console.warn("⚠️ Keep-alive ping error:", error.message);
    }
  }, keepAliveInterval);
  
  console.log("✅ Render keep-alive mechanism started (pings every 10 minutes)");
};

// Start keep-alive only in production (Render)
if (process.env.NODE_ENV === "production" || process.env.RENDER) {
  startKeepAlive();
}

// ===== STATIC FILES =====

// Serve static files from public directory (if exists)
app.use(express.static(path.join(__dirname, "public")));

// Serve frontend static files (CSS, JS, images, etc.)
app.use(express.static(path.join(__dirname, "../frontend")));

// ===== ERROR HANDLING MIDDLEWARE =====

// 404 handler - Show "Page doesn't exist" for invalid routes
// This catches all routes that don't match API routes or static files
app.use((req, res, next) => {
  // List of valid frontend routes that should be served
  const validRoutes = [
    '/', '/login', '/signup', '/forgot-password',
    '/dashboard', '/mentor-dashboard',
    '/colleges', '/mentors', '/materials', '/planner', '/bookings', '/settings', '/apply-mentor',
    '/admin', '/admin/login', '/admin/dashboard', '/admin/uploads',
    '/admin/colleges', '/admin/mentors', '/admin/materials', '/admin/users', '/admin/settings'
  ];
  
  // Check if it's a valid route or a static asset
  const isApiRoute = req.path.startsWith("/api/");
  const isStaticAsset = req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|html)$/i);
  const isValidRoute = validRoutes.includes(req.path) || req.path.startsWith('/frontend/') || req.path.startsWith('/assets/');
  
  // If it's an API route, return JSON error
  if (isApiRoute) {
    return res.status(404).json({
      error: "API endpoint not found",
      path: req.originalUrl,
      method: req.method,
      server: "api.medscore.xyz",
      documentation: "https://api.medscore.xyz/api/health",
    });
  }
  
  // If it's a static asset or valid route, it should have been served already
  // If we reach here, it's an invalid route
  // For all invalid routes (like /backend, /cursormkc, etc.), show HTML error page
  res.status(404).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Page Not Found - MedScore</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }
        .error-container {
          text-align: center;
          padding: 40px;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 20px;
          backdrop-filter: blur(10px);
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        h1 {
          font-size: 72px;
          margin: 0;
          font-weight: 700;
        }
        h2 {
          font-size: 24px;
          margin: 20px 0;
          font-weight: 400;
        }
        p {
          font-size: 16px;
          margin: 20px 0;
          opacity: 0.9;
        }
        a {
          color: white;
          text-decoration: underline;
        }
        a:hover {
          opacity: 0.8;
        }
      </style>
    </head>
    <body>
      <div class="error-container">
        <h1>404</h1>
        <h2>Page Doesn't Exist</h2>
        <p>The page you're looking for doesn't exist or has been moved.</p>
        <p><a href="/">Go to Homepage</a></p>
      </div>
    </body>
    </html>
  `);
});

// Global error handler
app.use((error, req, res, next) => {
  console.error("Global error handler:", error);

  // Mongoose validation error
  if (error.name === "ValidationError") {
    const errors = Object.values(error.errors).map((err) => err.message);
    return res.status(400).json({
      error: "Validation Error",
      details: errors,
    });
  }

  // Mongoose duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json({
      error: `${field} already exists`,
    });
  }

  // JWT errors
  if (error.name === "JsonWebTokenError") {
    return res.status(401).json({
      error: "Invalid token",
    });
  }

  if (error.name === "TokenExpiredError") {
    return res.status(401).json({
      error: "Token expired",
    });
  }

  // Default error
  res.status(error.status || 500).json({
    error:
      process.env.NODE_ENV === "development"
        ? error.message
        : "Internal server error",
  });
});

// Export app for use in start.js
module.exports = app;