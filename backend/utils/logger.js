const winston = require("winston");
const path = require("path");

// Create logs directory if it doesn't exist
const fs = require("fs");
const logsDir = path.join(__dirname, "../logs");
try {
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }
} catch (error) {
  console.warn("⚠️ Could not create logs directory:", error.message);
  console.warn("⚠️ Logs will only appear in console");
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

// Define log format for console
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: "HH:mm:ss" }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  }),
);

// Create logger instance with safe transports
const transports = [];

// Try to add file transports (may fail on restricted environments)
try {
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, "error.log"),
      level: "error",
      maxsize: parseInt(process.env.MAX_LOG_SIZE) || 10485760, // 10MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, "combined.log"),
      maxsize: parseInt(process.env.MAX_LOG_SIZE) || 10485760, // 10MB
      maxFiles: 5,
    }),
  );
} catch (error) {
  console.warn("⚠️ Could not create file transports:", error.message);
}

// Always add console transport as fallback
transports.push(
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: "HH:mm:ss" }),
      winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let msg = `${timestamp} [${level}]: ${message}`;
        if (Object.keys(meta).length > 0) {
          msg += ` ${JSON.stringify(meta)}`;
        }
        return msg;
      }),
    ),
  }),
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: logFormat,
  defaultMeta: { service: "medscore-backend" },
  transports,
});

// Try to add exception and rejection handlers (may fail in restricted environments)
try {
  logger.exceptions.handle(
    new winston.transports.File({
      filename: path.join(logsDir, "exceptions.log"),
    }),
  );
  logger.rejections.handle(
    new winston.transports.File({
      filename: path.join(logsDir, "rejections.log"),
    }),
  );
} catch (error) {
  console.warn(
    "⚠️ Could not create exception/rejection handlers:",
    error.message,
  );
}

// Custom log methods
logger.adminAction = (adminId, action, details) => {
  logger.info("Admin Action", {
    type: "admin_action",
    adminId,
    action,
    details,
    timestamp: new Date().toISOString(),
  });
};

logger.userAction = (userId, action, details) => {
  logger.info("User Action", {
    type: "user_action",
    userId,
    action,
    details,
    timestamp: new Date().toISOString(),
  });
};

logger.securityEvent = (event, details) => {
  logger.warn("Security Event", {
    type: "security_event",
    event,
    details,
    timestamp: new Date().toISOString(),
  });
};

logger.paymentEvent = (event, details) => {
  logger.info("Payment Event", {
    type: "payment_event",
    event,
    details,
    timestamp: new Date().toISOString(),
  });
};

logger.systemEvent = (event, details) => {
  logger.info("System Event", {
    type: "system_event",
    event,
    details,
    timestamp: new Date().toISOString(),
  });
};

logger.performance = (operation, duration, details) => {
  logger.info("Performance", {
    type: "performance",
    operation,
    duration,
    details,
    timestamp: new Date().toISOString(),
  });
};

// Error logging with context
logger.errorWithContext = (error, context) => {
  logger.error("Error with Context", {
    type: "error",
    error: {
      message: error.message,
      stack: error.stack,
      name: error.name,
    },
    context,
    timestamp: new Date().toISOString(),
  });
};

// API request logging
logger.apiRequest = (req, res, duration) => {
  logger.info("API Request", {
    type: "api_request",
    method: req.method,
    url: req.originalUrl,
    statusCode: res.statusCode,
    duration,
    ip: req.ip,
    userAgent: req.get("User-Agent"),
    userId: req.user ? req.user._id : null,
    timestamp: new Date().toISOString(),
  });
};

// Database operation logging
logger.dbOperation = (operation, collection, duration, details) => {
  logger.info("Database Operation", {
    type: "db_operation",
    operation,
    collection,
    duration,
    details,
    timestamp: new Date().toISOString(),
  });
};

// Rate limit logging
logger.rateLimit = (ip, endpoint, limit) => {
  logger.warn("Rate Limit Exceeded", {
    type: "rate_limit",
    ip,
    endpoint,
    limit,
    timestamp: new Date().toISOString(),
  });
};

// Authentication logging
logger.auth = (event, details) => {
  logger.info("Authentication Event", {
    type: "auth",
    event,
    details,
    timestamp: new Date().toISOString(),
  });
};

// File upload logging
logger.fileUpload = (userId, filename, size, type) => {
  logger.info("File Upload", {
    type: "file_upload",
    userId,
    filename,
    size,
    fileType: type,
    timestamp: new Date().toISOString(),
  });
};

// Email logging
logger.email = (event, details) => {
  logger.info("Email Event", {
    type: "email",
    event,
    details,
    timestamp: new Date().toISOString(),
  });
};

// Cleanup old logs (run daily)
logger.cleanup = () => {
  const retentionDays = parseInt(process.env.LOG_RETENTION_DAYS) || 30;
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

  // This would be implemented with a cron job
  logger.info("Log cleanup scheduled", {
    type: "system_event",
    event: "log_cleanup",
    cutoffDate: cutoffDate.toISOString(),
    retentionDays,
  });
};

module.exports = logger;
