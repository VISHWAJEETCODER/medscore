const { pool } = require('../config/mysql-db');

// Booking Model for MySQL
const Booking = {
  // Find booking by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM bookings WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('Booking.findById error:', error);
      throw error;
    }
  },

  // Find one booking
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM bookings WHERE ';
      const conditions = [];
      const values = [];

      if (query.id) {
        conditions.push('id = ?');
        values.push(query.id);
      }
      if (query.student_id) {
        conditions.push('student_id = ?');
        values.push(query.student_id);
      }
      if (query.payment_id) {
        conditions.push('payment_id = ?');
        values.push(query.payment_id);
      }

      sql += conditions.join(' AND ') + ' LIMIT 1';
      const [rows] = await pool.execute(sql, values);
      return rows[0] || null;
    } catch (error) {
      console.error('Booking.findOne error:', error);
      throw error;
    }
  },

  // Find all bookings
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM bookings WHERE 1=1';
      const values = [];

      if (query.student_id) {
        sql += ' AND student_id = ?';
        values.push(query.student_id);
      }
      if (query.mentor_id) {
        sql += ' AND mentor_id = ?';
        values.push(query.mentor_id);
      }
      if (query.status) {
        sql += ' AND status = ?';
        values.push(query.status);
      }

      sql += ' ORDER BY session_date DESC, session_time DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('Booking.find error:', error);
      throw error;
    }
  },

  // Create new booking
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO bookings 
        (student_id, mentor_id, session_date, session_time, duration, 
         subject, amount, status, payment_id, meeting_link, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.student_id,
        data.mentor_id,
        data.session_date,
        data.session_time,
        data.duration || 60,
        data.subject || '',
        data.amount || 0,
        data.status || 'pending',
        data.payment_id || null,
        data.meeting_link || null,
        data.notes || null
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('Booking.create error:', error);
      throw error;
    }
  },

  // Update booking by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE bookings SET
          session_date = ?, session_time = ?, duration = ?,
          subject = ?, amount = ?, status = ?,
          payment_id = ?, meeting_link = ?, notes = ?,
          updated_at = NOW()
        WHERE id = ?
      `;
      const values = [
        data.session_date,
        data.session_time,
        data.duration,
        data.subject,
        data.amount,
        data.status,
        data.payment_id,
        data.meeting_link,
        data.notes,
        id
      ];

      await pool.execute(sql, values);
      return await Booking.findById(id);
    } catch (error) {
      console.error('Booking.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update booking (alias)
  update: async (id, data) => {
    return await Booking.findByIdAndUpdate(id, data);
  },

  // Delete booking
  findByIdAndDelete: async (id) => {
    try {
      const booking = await Booking.findById(id);
      if (!booking) return null;
      
      const sql = 'DELETE FROM bookings WHERE id = ?';
      await pool.execute(sql, [id]);
      return booking;
    } catch (error) {
      console.error('Booking.findByIdAndDelete error:', error);
      throw error;
    }
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM bookings WHERE 1=1';
      const values = [];

      if (query.student_id) {
        sql += ' AND student_id = ?';
        values.push(query.student_id);
      }
      if (query.mentor_id) {
        sql += ' AND mentor_id = ?';
        values.push(query.mentor_id);
      }
      if (query.status) {
        sql += ' AND status = ?';
        values.push(query.status);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('Booking.countDocuments error:', error);
      throw error;
    }
  }
};

module.exports = Booking;
