const { pool } = require('../config/mysql-db');

// Payout Model for MySQL (uses payments table for completed transactions)
const Payout = {
  // Find payout by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM payments WHERE id = ? AND status = "completed" LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('Payout.findById error:', error);
      throw error;
    }
  },

  // Find one payout
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM payments WHERE status = "completed"';
      const values = [];

      if (query.id) {
        sql += ' AND id = ?';
        values.push(query.id);
      }
      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }

      sql += ' LIMIT 1';
      const [rows] = await pool.execute(sql, values);
      return rows[0] || null;
    } catch (error) {
      console.error('Payout.findOne error:', error);
      throw error;
    }
  },

  // Find all payouts
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM payments WHERE status = "completed"';
      const values = [];

      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }

      sql += ' ORDER BY created_at DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('Payout.find error:', error);
      throw error;
    }
  },

  // Get total payouts for a user
  getTotalPayouts: async (user_id) => {
    try {
      const sql = `
        SELECT SUM(amount) as total 
        FROM payments 
        WHERE user_id = ? AND status = 'completed'
      `;
      const [rows] = await pool.execute(sql, [user_id]);
      return rows[0]?.total || 0;
    } catch (error) {
      console.error('Payout.getTotalPayouts error:', error);
      throw error;
    }
  }
};

module.exports = Payout;
