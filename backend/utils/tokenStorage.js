// ===== TOKEN STORAGE IN MYSQL =====
// Store all tokens in MySQL for security

const { pool } = require("../config/mysql-db");

/**
 * Store token in MySQL
 * @param {number} userId - User ID
 * @param {string} token - JWT token
 * @param {string} tokenType - Type: 'access', 'refresh', 'temp', 'reset'
 * @param {number} expiresInSeconds - Expiration time in seconds
 * @returns {Promise<boolean>} Success status
 */
const storeToken = async (userId, token, tokenType = "access", expiresInSeconds = 604800) => {
  try {
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

    await pool.execute(
      "INSERT INTO tokens (user_id, token_type, token, expires_at) VALUES (?, ?, ?, ?)",
      [userId, tokenType, token, expiresAt]
    );

    console.log(`✅ Token stored in MySQL for user ${userId}, type: ${tokenType}`);
    return true;
  } catch (error) {
    console.error("❌ Error storing token in MySQL:", error.message);
    // Don't fail the request if token storage fails
    return false;
  }
};

/**
 * Verify token exists in MySQL and is not expired
 * @param {string} token - JWT token
 * @param {string} tokenType - Type: 'access', 'refresh', 'temp', 'reset'
 * @returns {Promise<{valid: boolean, userId: number|null}>}
 */
const verifyTokenInDB = async (token, tokenType = "access") => {
  try {
    const [rows] = await pool.execute(
      "SELECT user_id FROM tokens WHERE token = ? AND token_type = ? AND expires_at > NOW() LIMIT 1",
      [token, tokenType]
    );

    if (rows.length > 0) {
      return { valid: true, userId: rows[0].user_id };
    }

    return { valid: false, userId: null };
  } catch (error) {
    console.error("❌ Error verifying token in MySQL:", error.message);
    return { valid: false, userId: null };
  }
};

/**
 * Remove token from MySQL (logout)
 * @param {string} token - JWT token
 * @returns {Promise<boolean>} Success status
 */
const removeToken = async (token) => {
  try {
    await pool.execute("DELETE FROM tokens WHERE token = ?", [token]);
    console.log("✅ Token removed from MySQL");
    return true;
  } catch (error) {
    console.error("❌ Error removing token from MySQL:", error.message);
    return false;
  }
};

/**
 * Remove all tokens for a user (logout all devices)
 * @param {number} userId - User ID
 * @returns {Promise<boolean>} Success status
 */
const removeAllUserTokens = async (userId) => {
  try {
    await pool.execute("DELETE FROM tokens WHERE user_id = ?", [userId]);
    console.log(`✅ All tokens removed for user ${userId}`);
    return true;
  } catch (error) {
    console.error("❌ Error removing user tokens from MySQL:", error.message);
    return false;
  }
};

module.exports = {
  storeToken,
  verifyTokenInDB,
  removeToken,
  removeAllUserTokens,
};

