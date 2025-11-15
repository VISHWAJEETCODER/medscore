// ===== TOKEN BLACKLIST SYSTEM =====
// Bug #18 fix - Token blacklist for logout functionality
// This provides a blacklist system for JWT tokens to invalidate them on logout

const { pool } = require("../config/mysql-db");

// In-memory blacklist for fast lookups (for cPanel environments without Redis)
const memoryBlacklist = new Set();

// Maximum entries in memory blacklist (prevent memory overflow)
const MAX_MEMORY_BLACKLIST_SIZE = 10000;

/**
 * Add token to blacklist
 * @param {string} token - JWT token to blacklist
 * @param {number} expiresIn - Token expiration time in seconds
 * @returns {Promise<boolean>} Success status
 */
const addToBlacklist = async (token, expiresIn = 2592000) => {
  try {
    // Add to memory blacklist
    if (memoryBlacklist.size < MAX_MEMORY_BLACKLIST_SIZE) {
      memoryBlacklist.add(token);
    }

    // Try to add to database for persistence
    try {
      const expiryDate = new Date(Date.now() + expiresIn * 1000);
      await pool.execute(
        "INSERT INTO token_blacklist (token, expires_at) VALUES (?, ?) ON DUPLICATE KEY UPDATE expires_at = ?",
        [token, expiryDate, expiryDate]
      );
      console.log("✅ Token added to blacklist (DB + Memory)");
    } catch (dbError) {
      console.warn("⚠️ Could not add token to DB blacklist:", dbError.message);
      console.log("✅ Token added to memory blacklist only");
    }

    // Auto-remove from memory after expiry
    setTimeout(() => {
      memoryBlacklist.delete(token);
    }, expiresIn * 1000);

    return true;
  } catch (error) {
    console.error("❌ Error adding token to blacklist:", error);
    return false;
  }
};

/**
 * Check if token is blacklisted
 * @param {string} token - JWT token to check
 * @returns {Promise<boolean>} True if blacklisted
 */
const isBlacklisted = async (token) => {
  try {
    // Check memory blacklist first (fastest)
    if (memoryBlacklist.has(token)) {
      return true;
    }

    // Check database blacklist
    try {
      const [rows] = await pool.execute(
        "SELECT id FROM token_blacklist WHERE token = ? AND expires_at > NOW()",
        [token]
      );

      if (rows.length > 0) {
        // Add to memory blacklist for faster future checks
        if (memoryBlacklist.size < MAX_MEMORY_BLACKLIST_SIZE) {
          memoryBlacklist.add(token);
        }
        return true;
      }
    } catch (dbError) {
      console.warn("⚠️ Could not check DB blacklist:", dbError.message);
    }

    return false;
  } catch (error) {
    console.error("❌ Error checking blacklist:", error);
    return false;
  }
};

/**
 * Remove token from blacklist (rare case)
 * @param {string} token - JWT token to remove
 * @returns {Promise<boolean>} Success status
 */
const removeFromBlacklist = async (token) => {
  try {
    // Remove from memory
    memoryBlacklist.delete(token);

    // Remove from database
    try {
      await pool.execute("DELETE FROM token_blacklist WHERE token = ?", [
        token,
      ]);
    } catch (dbError) {
      console.warn("⚠️ Could not remove from DB blacklist:", dbError.message);
    }

    return true;
  } catch (error) {
    console.error("❌ Error removing from blacklist:", error);
    return false;
  }
};

/**
 * Clean up expired tokens from blacklist
 * @returns {Promise<number>} Number of tokens removed
 */
const cleanupExpiredTokens = async () => {
  try {
    // First check if table exists
    const connection = await pool.getConnection();
    try {
      const [tables] = await connection.query("SHOW TABLES LIKE 'token_blacklist'");
      connection.release();
      
      if (tables.length === 0) {
        // Table doesn't exist yet, silently skip (not an error)
        return 0;
      }
    } catch (checkError) {
      connection.release();
      // If we can't check, assume table doesn't exist
      return 0;
    }

    const [result] = await pool.execute(
      "DELETE FROM token_blacklist WHERE expires_at < NOW()"
    );

    if (result.affectedRows > 0) {
      console.log(`🧹 Cleaned up ${result.affectedRows} expired blacklisted tokens`);
    }
    return result.affectedRows;
  } catch (error) {
    // Don't log as error if table doesn't exist
    if (error.message && error.message.includes("doesn't exist")) {
      return 0;
    }
    console.error("❌ Error cleaning up tokens:", error);
    return 0;
  }
};

/**
 * Start automatic cleanup cron job
 */
const startCleanupCron = () => {
  // Clean up expired tokens every 6 hours
  setInterval(
    async () => {
      await cleanupExpiredTokens();
    },
    6 * 60 * 60 * 1000
  );

  console.log("✅ Token blacklist cleanup cron started (runs every 6 hours)");
};

/**
 * Get blacklist statistics
 * @returns {Promise<Object>} Blacklist stats
 */
const getBlacklistStats = async () => {
  try {
    const [rows] = await pool.execute(
      "SELECT COUNT(*) as total FROM token_blacklist WHERE expires_at > NOW()"
    );

    return {
      memoryCount: memoryBlacklist.size,
      databaseCount: rows[0].total,
      maxMemorySize: MAX_MEMORY_BLACKLIST_SIZE,
    };
  } catch (error) {
    return {
      memoryCount: memoryBlacklist.size,
      databaseCount: 0,
      maxMemorySize: MAX_MEMORY_BLACKLIST_SIZE,
    };
  }
};

/**
 * Initialize blacklist system
 * Creates database table if needed
 */
const initializeBlacklist = async () => {
  try {
    const connection = await pool.getConnection();

    // Create token_blacklist table if it doesn't exist
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS token_blacklist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        token VARCHAR(500) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token),
        INDEX idx_expires (expires_at)
      )
    `);

    connection.release();
    console.log("✅ Token blacklist table initialized");

    // Start cleanup cron
    startCleanupCron();

    // Run initial cleanup
    await cleanupExpiredTokens();

    return true;
  } catch (error) {
    console.error("❌ Failed to initialize blacklist:", error.message);
    console.warn("⚠️ Using memory-only blacklist");
    return false;
  }
};

/**
 * Middleware to check if token is blacklisted
 */
const checkBlacklist = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);

      if (await isBlacklisted(token)) {
        return res.status(401).json({
          error: "Token has been revoked. Please login again.",
          code: "TOKEN_BLACKLISTED",
        });
      }
    }

    next();
  } catch (error) {
    console.error("❌ Error in blacklist middleware:", error);
    next(); // Continue even if check fails
  }
};

/**
 * Clear all blacklisted tokens (admin function)
 */
const clearBlacklist = async () => {
  try {
    // Clear memory
    memoryBlacklist.clear();

    // Clear database
    await pool.execute("TRUNCATE TABLE token_blacklist");

    console.log("✅ Token blacklist cleared");
    return true;
  } catch (error) {
    console.error("❌ Error clearing blacklist:", error);
    return false;
  }
};

module.exports = {
  addToBlacklist,
  isBlacklisted,
  removeFromBlacklist,
  cleanupExpiredTokens,
  getBlacklistStats,
  initializeBlacklist,
  checkBlacklist,
  clearBlacklist,
};

/**
 * USAGE EXAMPLE:
 *
 * // In auth.js logout route:
 * const { addToBlacklist } = require('../utils/tokenBlacklist');
 *
 * router.post('/logout', authenticate, async (req, res) => {
 *   const token = req.headers.authorization.substring(7);
 *   await addToBlacklist(token);
 *   res.json({ message: 'Logged out successfully' });
 * });
 *
 * // In auth middleware:
 * const { checkBlacklist } = require('../utils/tokenBlacklist');
 * router.use(checkBlacklist); // Add before authenticate
 */
