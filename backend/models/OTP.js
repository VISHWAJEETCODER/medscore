// OTP Model for MySQL Database
// This is just a reference - actual OTP table is created in mysql-db.js

const { pool } = require('../config/mysql-db');

// OTP Helper Functions for MySQL
const OTP = {
  // Create new OTP
  create: async (email, otp, expiresAt) => {
    const [result] = await pool.execute(
      'INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt]
    );
    return result;
  },

  // Find OTP by email
  findByEmail: async (email) => {
    const [rows] = await pool.execute(
      'SELECT * FROM otps WHERE email = ? AND is_used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [email]
    );
    return rows[0];
  },

  // Verify and mark OTP as used
  verifyAndMarkUsed: async (email, otp) => {
    const [result] = await pool.execute(
      'UPDATE otps SET is_used = TRUE WHERE email = ? AND otp = ? AND is_used = FALSE AND expires_at > NOW()',
      [email, otp]
    );
    return result.affectedRows > 0;
  },

  // Delete expired OTPs
  deleteExpired: async () => {
    const [result] = await pool.execute(
      'DELETE FROM otps WHERE expires_at < NOW() OR is_used = TRUE'
    );
    return result.affectedRows;
  }
};

module.exports = OTP;



