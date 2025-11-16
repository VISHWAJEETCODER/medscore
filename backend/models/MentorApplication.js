const { pool } = require('../config/mysql-db');

// MentorApplication Model for MySQL
const MentorApplication = {
  // Find application by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM mentor_applications WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('MentorApplication.findById error:', error);
      throw error;
    }
  },

  // Find one application
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM mentor_applications WHERE ';
      const conditions = [];
      const values = [];

      if (query.id) {
        conditions.push('id = ?');
        values.push(query.id);
      }
      if (query.user_id) {
        conditions.push('user_id = ?');
        values.push(query.user_id);
      }

      sql += conditions.join(' AND ') + ' LIMIT 1';
      const [rows] = await pool.execute(sql, values);
      return rows[0] || null;
    } catch (error) {
      console.error('MentorApplication.findOne error:', error);
      throw error;
    }
  },

  // Find all applications
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM mentor_applications WHERE 1=1';
      const values = [];

      if (query.status) {
        sql += ' AND status = ?';
        values.push(query.status);
      }
      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }

      sql += ' ORDER BY created_at DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('MentorApplication.find error:', error);
      throw error;
    }
  },

  // Create new application
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO mentor_applications 
        (user_id, college_name, specialization, experience_years, 
         subjects, hourly_rate, bio, documents, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.user_id,
        data.college_name,
        data.specialization,
        data.experience_years || 0,
        JSON.stringify(data.subjects || []),
        data.hourly_rate || 50,
        data.bio || '',
        JSON.stringify(data.documents || []),
        data.status || 'pending'
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('MentorApplication.create error:', error);
      throw error;
    }
  },

  // Update application by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE mentor_applications SET
          status = ?, admin_notes = ?, updated_at = NOW()
        WHERE id = ?
      `;
      const values = [data.status, data.admin_notes || '', id];

      await pool.execute(sql, values);
      return await MentorApplication.findById(id);
    } catch (error) {
      console.error('MentorApplication.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update application (alias)
  update: async (id, data) => {
    return await MentorApplication.findByIdAndUpdate(id, data);
  },

  // Delete application
  findByIdAndDelete: async (id) => {
    try {
      const application = await MentorApplication.findById(id);
      if (!application) return null;
      
      const sql = 'DELETE FROM mentor_applications WHERE id = ?';
      await pool.execute(sql, [id]);
      return application;
    } catch (error) {
      console.error('MentorApplication.findByIdAndDelete error:', error);
      throw error;
    }
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM mentor_applications WHERE 1=1';
      const values = [];

      if (query.status) {
        sql += ' AND status = ?';
        values.push(query.status);
      }
      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('MentorApplication.countDocuments error:', error);
      throw error;
    }
  }
};

module.exports = MentorApplication;
