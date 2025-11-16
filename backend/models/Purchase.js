const { pool } = require('../config/mysql-db');

// Purchase Model for MySQL (uses payments table)
const Purchase = {
  // Find purchase by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM payments WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('Purchase.findById error:', error);
      throw error;
    }
  },

  // Find one purchase
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM payments WHERE ';
      const conditions = [];
      const values = [];

      if (query.id) {
        conditions.push('id = ?');
        values.push(query.id);
      }
      if (query.razorpay_payment_id) {
        conditions.push('razorpay_payment_id = ?');
        values.push(query.razorpay_payment_id);
      }
      if (query.razorpay_order_id) {
        conditions.push('razorpay_order_id = ?');
        values.push(query.razorpay_order_id);
      }

      sql += conditions.join(' AND ') + ' LIMIT 1';
      const [rows] = await pool.execute(sql, values);
      return rows[0] || null;
    } catch (error) {
      console.error('Purchase.findOne error:', error);
      throw error;
    }
  },

  // Find all purchases
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM payments WHERE 1=1';
      const values = [];

      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }
      if (query.status) {
        sql += ' AND status = ?';
        values.push(query.status);
      }

      sql += ' ORDER BY created_at DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('Purchase.find error:', error);
      throw error;
    }
  },

  // Create new purchase
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO payments 
        (user_id, booking_id, razorpay_order_id, razorpay_payment_id,
         amount, currency, status, payment_method)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.user_id,
        data.booking_id || null,
        data.razorpay_order_id || null,
        data.razorpay_payment_id || null,
        data.amount || 0,
        data.currency || 'INR',
        data.status || 'pending',
        data.payment_method || 'razorpay'
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('Purchase.create error:', error);
      throw error;
    }
  },

  // Update purchase by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE payments SET
          razorpay_payment_id = ?, status = ?,
          payment_method = ?, updated_at = NOW()
        WHERE id = ?
      `;
      const values = [
        data.razorpay_payment_id,
        data.status,
        data.payment_method,
        id
      ];

      await pool.execute(sql, values);
      return await Purchase.findById(id);
    } catch (error) {
      console.error('Purchase.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update purchase (alias)
  update: async (id, data) => {
    return await Purchase.findByIdAndUpdate(id, data);
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM payments WHERE 1=1';
      const values = [];

      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }
      if (query.status) {
        sql += ' AND status = ?';
        values.push(query.status);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('Purchase.countDocuments error:', error);
      throw error;
    }
  }
};

module.exports = Purchase;
