const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const hpp = require("hpp");
const path = require("path");
const passport = require("passport");
const session = require("express-session");
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
app.use("/api/auth", loginLimiter, authRoutes);
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

// ===== STATIC FILES =====

// Serve static files from public directory (if exists)
app.use(express.static(path.join(__dirname, "public")));

// Serve frontend static files - This should be after API routes
app.use(express.static(path.join(__dirname, "../frontend")));

// ===== ERROR HANDLING MIDDLEWARE =====

// 404 handler - Fixed for api.medscore.xyz deployment
app.use((req, res, next) => {
  // For API routes, return JSON error
  if (req.path.startsWith("/api/") || req.path === "/") {
    return res.status(404).json({
      error: "API endpoint not found",
      path: req.originalUrl,
      method: req.method,
      server: "api.medscore.xyz",
      documentation: "https://api.medscore.xyz/api/health",
    });
  }
  // For non-API routes, continue to next middleware
  next();
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
