const mysql = require("mysql2/promise");

// Create MySQL connection pool with cPanel configuration
// Bug #58 fix - Support both host and socketPath for cPanel
const poolConfig = {
  user: process.env.DB_USER || "uyasrwcb_medscore_user_new",
  password: process.env.DB_PASSWORD || "PK32UIvx!lL_",
  database: process.env.DB_NAME || "uyasrwcb_medscore_new",
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
    }

    connection.release(); // Bug #59 fix - Always release connection
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

// Check if tables already exist (Bug #53 fix)
const tablesExist = async (connection) => {
  try {
    const [tables] = await connection.query("SHOW TABLES LIKE 'users'");
    return tables.length > 0;
  } catch (error) {
    return false;
  }
};

// Create all necessary tables only if needed (Bug #53 fix)
const createTablesIfNeeded = async (connection) => {
  try {
    // Check if tables already exist
    const exists = await tablesExist(connection);
    if (exists) {
      console.log("✅ Database tables already exist, skipping creation");
      return false;
    }

    console.log("📊 Creating database tables...");

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

    console.log("✅ All database tables created successfully");
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
  }, 120000); // Check every 2 minutes (reduced frequency for Render)
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
  gracefulShutdown,
  createTablesIfNeeded,
};
