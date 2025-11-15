const mysql = require("mysql2/promise");

// Create MySQL connection pool with cPanel configuration
// Bug #58 fix - Support both host and socketPath for cPanel
const poolConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  // MySQL wait_timeout should be higher than keepAliveInitialDelay
  // This prevents "packets out of order" errors
  charset: "utf8mb4",
  timezone: "+00:00",
  // For cPanel, support both socket and host
  ...(process.env.DB_SOCKET
    ? { socketPath: process.env.DB_SOCKET }
    : { host: process.env.DB_HOST || "localhost" }),
};

const pool = mysql.createPool(poolConfig);

// Add connection event handlers for auto-reconnect
pool.on("connection", (connection) => {
  console.log(
    `📊 New database connection established (ID: ${connection.threadId})`,
  );

  // Set session variables to prevent timeout issues
  connection.query("SET SESSION wait_timeout=28800");
  connection.query("SET SESSION interactive_timeout=28800");
});

pool.on("error", (err) => {
  console.error("❌ Database pool error:", err);
  if (err.code === "PROTOCOL_CONNECTION_LOST") {
    console.log("🔄 Attempting to reconnect to database...");
  }
});

const connectDB = async () => {
  try {
    // Test the connection with proper error handling
    const connection = await pool.getConnection();
    const hostInfo = poolConfig.socketPath
      ? `socket ${poolConfig.socketPath}`
      : `host ${poolConfig.host || "localhost"}`;
    console.log(`✅ MySQL Database Connected Successfully (${hostInfo})`);

    // Create tables if they don't exist (Bug #53 fix - check if already created)
    const tablesCreated = await createTablesIfNeeded(connection);
    if (tablesCreated) {
      console.log("✅ Database tables verified/created");
    } else {
      console.log("✅ Database tables already exist");
    }

    connection.release(); // Bug #59 fix - Always release connection
    
    // IMPORTANT: Start cleanup cron AFTER tables are verified/created
    await ensureCleanupCronStarted();
    
    return true;
  } catch (error) {
    console.error("❌ MySQL Connection Error:", error.message);
    console.error("❌ Error details:", error.code, error.errno);
    console.warn("⚠️ Running without database - some features may be limited");
    console.warn("💡 Check your cPanel database configuration in .env file");
    // Don't crash the app - let it run with JSON storage fallback
    return false;
  }
};

// Check if specific table exists
const tableExists = async (connection, tableName) => {
  try {
    const [tables] = await connection.query(`SHOW TABLES LIKE '${tableName}'`);
    return tables.length > 0;
  } catch (error) {
    return false;
  }
};

// Check if all required tables exist
const allTablesExist = async (connection) => {
  try {
    const requiredTables = [
      'users',
      'colleges',
      'mentors',
      'mentor_applications',
      'bookings',
      'study_materials',
      'personal_planners',
      'payments',
      'otps',
      'tokens',
      'token_blacklist'
    ];
    
    for (const table of requiredTables) {
      const exists = await tableExists(connection, table);
      if (!exists) {
        console.log(`⚠️ Table '${table}' does not exist`);
        return false;
      }
    }
    
    return true;
  } catch (error) {
    console.error("❌ Error checking tables:", error.message);
    return false;
  }
};

// Create all necessary tables only if needed (Bug #53 fix + Token table fix)
const createTablesIfNeeded = async (connection) => {
  try {
    // Check if all tables exist
    const allExist = await allTablesExist(connection);
    if (allExist) {
      console.log("✅ All database tables already exist, skipping creation");
      return false;
    }

    console.log("📊 Creating/verifying database tables...");

    // Users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
        phone VARCHAR(20),
        profile_photo VARCHAR(500),
        referral_code VARCHAR(20) UNIQUE,
        referred_by VARCHAR(20),
        total_referrals INT DEFAULT 0,
        role ENUM('student', 'mentor', 'admin1', 'admin2', 'admin3') DEFAULT 'student',
        is_verified BOOLEAN DEFAULT FALSE,
        failed_login_attempts INT DEFAULT 0,
        account_locked_until TIMESTAMP NULL,
        last_login TIMESTAMP NULL,
        is_active BOOLEAN DEFAULT TRUE,
        is_suspended BOOLEAN DEFAULT FALSE,
        suspended_until TIMESTAMP NULL,
        google_id VARCHAR(255) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_google_id (google_id),
        INDEX idx_referral_code (referral_code)
      )
    `);

    // Colleges table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS colleges (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        state VARCHAR(100),
        type ENUM('Government', 'Private', 'Deemed') DEFAULT 'Government',
        cutoff_data JSON,
        photos JSON,
        facilities TEXT,
        fees JSON,
        ranking INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Mentors table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS mentors (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        college_name VARCHAR(255),
        specialization VARCHAR(255),
        experience_years INT,
        subjects JSON,
        hourly_rate DECIMAL(10,2),
        availability JSON,
        rating DECIMAL(3,2) DEFAULT 0,
        total_sessions INT DEFAULT 0,
        bio TEXT,
        is_verified BOOLEAN DEFAULT FALSE,
        is_available BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Mentor applications table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS mentor_applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        college_name VARCHAR(255),
        specialization VARCHAR(255),
        experience_years INT,
        subjects JSON,
        hourly_rate DECIMAL(10,2),
        bio TEXT,
        documents JSON,
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        admin_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Bookings table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS bookings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_id INT,
        mentor_id INT,
        session_date DATE,
        session_time TIME,
        duration INT,
        subject VARCHAR(255),
        amount DECIMAL(10,2),
        status ENUM('pending', 'confirmed', 'completed', 'cancelled') DEFAULT 'pending',
        payment_id VARCHAR(255),
        meeting_link VARCHAR(500),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (mentor_id) REFERENCES mentors(id) ON DELETE CASCADE
      )
    `);

    // Study materials table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS study_materials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        subject VARCHAR(100),
        type ENUM('pdf', 'video', 'image', 'document') DEFAULT 'pdf',
        file_path VARCHAR(500),
        description TEXT,
        is_premium BOOLEAN DEFAULT FALSE,
        uploaded_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Personal planners table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS personal_planners (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        title VARCHAR(255),
        subjects JSON,
        schedule JSON,
        milestones JSON,
        progress JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Payments table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        booking_id INT,
        razorpay_order_id VARCHAR(255),
        razorpay_payment_id VARCHAR(255),
        amount DECIMAL(10,2),
        currency VARCHAR(10) DEFAULT 'INR',
        status ENUM('pending', 'completed', 'failed', 'refunded') DEFAULT 'pending',
        payment_method VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE SET NULL
      )
    `);

    // OTP table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS otps (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(10) NOT NULL,
        type ENUM('login', 'signup', 'reset') DEFAULT 'login',
        expires_at TIMESTAMP,
        is_used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email_type (email, type),
        INDEX idx_expires_at (expires_at)
      )
    `);

    // Tokens table - Store access tokens, refresh tokens, temp tokens
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token_type ENUM('access', 'refresh', 'temp', 'reset') DEFAULT 'access',
        token VARCHAR(500) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_token (token(255)),
        INDEX idx_expires_at (expires_at),
        INDEX idx_user_type (user_id, token_type),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Token blacklist table - Store invalidated tokens
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS token_blacklist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        token VARCHAR(500) NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token(255)),
        INDEX idx_expires_at (expires_at)
      )
    `);

    console.log("✅ All database tables verified/created successfully");
    return true;
  } catch (error) {
    console.error("❌ Error creating tables:", error.message);
    throw error;
  }
};

// Add auto-reconnect mechanism
const autoReconnect = () => {
  setInterval(async () => {
    try {
      const connection = await pool.getConnection();
      await connection.query("SELECT 1");
      connection.release();
      console.log("✅ Database connection verified");
    } catch (error) {
      console.error("❌ Database connection lost:", error.message);
      console.log("🔄 Attempting to reconnect...");
    }
  }, 30000); // Check every 30 seconds (keep connection alive)
};

// Start auto-reconnect in all environments (Bug #52 fix)
autoReconnect();

// OTP Cleanup Function (Bug #9, #50 fix)
const cleanupExpiredOTPs = async () => {
  try {
    const [result] = await pool.execute(
      "DELETE FROM otps WHERE expires_at < NOW() OR (is_used = TRUE AND created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR))",
    );

    if (result.affectedRows > 0) {
      console.log(`🧹 Cleaned up ${result.affectedRows} expired/used OTPs`);
    }

    return { success: true, deletedCount: result.affectedRows };
  } catch (error) {
    console.error("❌ Error cleaning up OTPs:", error.message);
    return { success: false, error: error.message };
  }
};

// Start OTP cleanup cron job (runs every hour)
const startOTPCleanupCron = () => {
  // Run cleanup immediately on startup
  cleanupExpiredOTPs();

  // Then run every hour
  setInterval(
    async () => {
      await cleanupExpiredOTPs();
    },
    60 * 60 * 1000,
  ); // 1 hour

  console.log("✅ OTP cleanup cron job started (runs every hour)");
};

// Start OTP cleanup cron job (Bug #9, #50 fix)
startOTPCleanupCron();

// Token Cleanup Function - Remove expired tokens
const cleanupExpiredTokens = async () => {
  try {
    // First check if tokens table exists
    const connection = await pool.getConnection();
    let tokensTableExists = false;
    let blacklistTableExists = false;
    
    try {
      const [tokensTables] = await connection.query("SHOW TABLES LIKE 'tokens'");
      tokensTableExists = tokensTables.length > 0;
      
      const [blacklistTables] = await connection.query("SHOW TABLES LIKE 'token_blacklist'");
      blacklistTableExists = blacklistTables.length > 0;
      
      connection.release();
    } catch (checkError) {
      connection.release();
      // If we can't check, assume tables don't exist
      tokensTableExists = false;
      blacklistTableExists = false;
    }

    let deletedTokens = 0;
    let deletedBlacklist = 0;

    // Cleanup expired tokens if table exists
    if (tokensTableExists) {
  try {
    const [result] = await pool.execute(
      "DELETE FROM tokens WHERE expires_at < NOW()",
    );
        deletedTokens = result.affectedRows;
        if (deletedTokens > 0) {
          console.log(`🧹 Cleaned up ${deletedTokens} expired tokens`);
        }
      } catch (tokenError) {
        if (!tokenError.message.includes("doesn't exist")) {
          console.warn("⚠️ Error cleaning tokens:", tokenError.message);
        }
      }
    }

    // Also cleanup expired blacklisted tokens if table exists
    if (blacklistTableExists) {
      try {
    const [blacklistResult] = await pool.execute(
      "DELETE FROM token_blacklist WHERE expires_at < NOW()",
    );
        deletedBlacklist = blacklistResult.affectedRows;
        if (deletedBlacklist > 0) {
          console.log(`🧹 Cleaned up ${deletedBlacklist} expired blacklisted tokens`);
        }
      } catch (blacklistError) {
        if (!blacklistError.message.includes("doesn't exist")) {
          console.warn("⚠️ Error cleaning blacklist:", blacklistError.message);
    }
      }
    }

    // If tables don't exist, silently skip (not an error)
    if (!tokensTableExists && !blacklistTableExists) {
      return { success: true, deletedTokens: 0, deletedBlacklist: 0 };
    }

    return { success: true, deletedTokens, deletedBlacklist };
  } catch (error) {
    // Don't log as error if table doesn't exist
    if (error.message && error.message.includes("doesn't exist")) {
      return { success: true, deletedTokens: 0, deletedBlacklist: 0 };
    }
    console.error("❌ Error cleaning up tokens:", error.message);
    return { success: false, error: error.message };
  }
};

// Start token cleanup cron job (runs every hour)
// IMPORTANT: Only start after tables are verified/created
let cleanupCronStarted = false;
const startTokenCleanupCron = async () => {
  if (cleanupCronStarted) {
    return; // Already started
  }

  try {
    // Wait a bit to ensure tables are created
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Verify tokens table exists before starting cleanup
    const connection = await pool.getConnection();
    try {
      const [tables] = await connection.query("SHOW TABLES LIKE 'tokens'");
      connection.release();
      
      if (tables.length === 0) {
        console.log("⚠️ Tokens table doesn't exist yet, cleanup cron will retry after 10 seconds");
        // Retry after 10 seconds
        setTimeout(() => startTokenCleanupCron(), 10000);
        return;
      }
    } catch (checkError) {
      connection.release();
      console.log("⚠️ Could not verify tokens table, cleanup cron will retry after 10 seconds");
      setTimeout(() => startTokenCleanupCron(), 10000);
      return;
    }

    // Mark as started
    cleanupCronStarted = true;

  // Run cleanup immediately on startup
    await cleanupExpiredTokens();

  // Then run every hour
  setInterval(
    async () => {
      await cleanupExpiredTokens();
    },
    60 * 60 * 1000,
  ); // 1 hour

  console.log("✅ Token cleanup cron job started (runs every hour)");
  } catch (error) {
    console.error("❌ Error starting token cleanup cron:", error.message);
    // Retry after 10 seconds
    setTimeout(() => startTokenCleanupCron(), 10000);
  }
};

// Don't start cleanup cron immediately - wait for table creation
// This will be called after connectDB() completes
const ensureCleanupCronStarted = async () => {
  if (!cleanupCronStarted) {
    await startTokenCleanupCron();
  }
};

// Graceful pool shutdown for proper connection handling (Bug #59 fix)
const gracefulShutdown = async () => {
  try {
    console.log("🔄 Closing database pool...");
    await pool.end();
    console.log("✅ Database pool closed gracefully");
  } catch (error) {
    console.error("❌ Error closing pool:", error.message);
  }
};

// Handle process termination
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

// Test connection function
const testConnection = async () => {
  try {
    const hostInfo = poolConfig.socketPath
      ? `socket ${poolConfig.socketPath}`
      : `host ${poolConfig.host}`;
    console.log(`Testing database connection at ${hostInfo}...`);
    const connection = await pool.getConnection();
    console.log(`✅ Database connection successful (${hostInfo})`);
    await connection.query("SELECT 1");
    connection.release();
    return true;
  } catch (error) {
    console.error("❌ Database connection failed:", error.message);
    return false;
  }
};

// Export with proper connection handling (Bug #59 fix)
module.exports = {
  connectDB,
  pool,
  testConnection,
  cleanupExpiredOTPs,
  cleanupExpiredTokens,
  gracefulShutdown,
  createTablesIfNeeded,
  ensureCleanupCronStarted,
};
