#!/usr/bin/env node

// ===== MedScore Backend Startup =====
// Compatible with Render, Railway, and cPanel hosting

const path = require("path");
const fs = require("fs");

// Set production environment
process.env.NODE_ENV = process.env.NODE_ENV || "production";

// Memory optimization
if (!process.env.NODE_OPTIONS) {
  process.env.NODE_OPTIONS = "--max-old-space-size=512";
}

// Error handling - prevent app crashes
process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught Exception:", err.message);
  console.error(err.stack);
});

process.on("unhandledRejection", (err) => {
  console.error("❌ Unhandled Rejection:", err.message);
  console.error(err.stack);
});

// Application root path
const appRoot = __dirname;
process.chdir(appRoot);

const platform = process.env.RENDER
  ? "Render"
  : process.env.RAILWAY_ENVIRONMENT
    ? "Railway"
    : "cPanel";

console.log("🌐 Starting MedScore Backend...");
console.log("📁 Application Root:", appRoot);
console.log("🔧 Node.js Version:", process.version);
console.log("🏷️  Environment:", process.env.NODE_ENV);
console.log("🚀 Platform:", platform);

// Check if required files exist
const requiredFiles = ["server.js", "package.json"];

for (const file of requiredFiles) {
  const filePath = path.join(appRoot, file);
  if (!fs.existsSync(filePath)) {
    console.error(`❌ Required file missing: ${file}`);
    process.exit(1);
  }
}

// Load environment variables
try {
  require("dotenv").config();
  console.log("✅ Environment variables loaded");
} catch (err) {
  console.warn("⚠️ .env file not found, using system environment variables");
}

// Database initialization
const initializeDatabase = async () => {
  try {
    const { connectDB } = require("./config/mysql-db");
    const logger = require("./utils/logger");

    console.log("🔌 Initializing database connection...");

    // Try to connect to database
    const dbConnected = await connectDB();
    if (dbConnected) {
      console.log("✅ MySQL Database connected successfully");
      if (logger) logger.info("✅ MySQL Database connected successfully");
    } else {
      console.log("⚠️ Database connection failed, using JSON storage fallback");
      if (logger)
        logger.warn(
          "⚠️ Database connection failed, using JSON storage fallback",
        );
    }

    return dbConnected;
  } catch (err) {
    console.error("❌ Database initialization error:", err.message);
    console.log("📝 Continuing with JSON storage fallback");
    return false;
  }
};

// Load and start the server
const startServer = async () => {
  try {
    console.log("🚀 Loading server application...");

    // Initialize database first
    const dbConnected = await initializeDatabase();

    // Log database status
    if (dbConnected) {
      console.log("📊 Database auto-reconnect enabled");
    } else {
      console.log("⚠️ Database auto-reconnect disabled - using JSON storage");
    }

    // Load the main server
    const app = require("./server");

    // Add platform-specific health check
    app.get("/startup-status", (req, res) => {
      res.json({
        status: "OK",
        environment: process.env.NODE_ENV || "production",
        platform: platform,
        timestamp: new Date().toISOString(),
        version: "1.0.0",
        appRoot: appRoot,
        nodeVersion: process.version,
      });
    });

    console.log("✅ Server application loaded successfully");
    console.log("🌍 Environment:", process.env.NODE_ENV || "production");
    console.log("🔒 Security middleware active");
    console.log("✅ MedScore Backend ready for requests");

    // Export the app for cPanel
    module.exports = app;

    // For direct execution, start the server
    if (require.main === module) {
      const PORT = process.env.PORT || 5000;
      const HOST = process.env.HOST || "0.0.0.0";

      const server = app.listen(PORT, HOST, () => {
        console.log(`🚀 Server running on ${HOST}:${PORT}`);
        console.log(`📊 API: http://localhost:${PORT}/api`);
        console.log(`✅ Health: http://localhost:${PORT}/health`);
        console.log(`🔍 Status: http://localhost:${PORT}/startup-status`);
      });

      // Handle graceful shutdown
      const gracefulShutdown = (signal) => {
        console.log(`\n📡 Received ${signal}. Gracefully shutting down...`);
        server.close(() => {
          console.log("✅ Server closed successfully");
          process.exit(0);
        });
      };

      process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
      process.on("SIGINT", () => gracefulShutdown("SIGINT"));
    }

    return app;
  } catch (error) {
    console.error("❌ Failed to start server:", error.message);
    console.error("Stack trace:", error.stack);
    process.exit(1);
  }
};

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`\n📡 Received ${signal}. Gracefully shutting down...`);

  // Give time for requests to complete
  setTimeout(() => {
    console.log("✅ Graceful shutdown completed");
    process.exit(0);
  }, 2000);
};

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

// Start the application
if (require.main === module) {
  startServer().catch((err) => {
    console.error("❌ Critical error starting application:", err);
    process.exit(1);
  });
} else {
  // Export for cPanel when required as module
  module.exports = startServer;
}

console.log("🎯 Startup script initialized");
