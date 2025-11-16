const { pool } = require('../config/mysql-db');

// PersonalPlanner Model for MySQL
const PersonalPlanner = {
  // Find planner by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM personal_planners WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('PersonalPlanner.findById error:', error);
      throw error;
    }
  },

  // Find one planner
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM personal_planners WHERE ';
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
      console.error('PersonalPlanner.findOne error:', error);
      throw error;
    }
  },

  // Find all planners
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM personal_planners WHERE 1=1';
      const values = [];

      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }

      sql += ' ORDER BY created_at DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('PersonalPlanner.find error:', error);
      throw error;
    }
  },

  // Create new planner
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO personal_planners 
        (user_id, title, subjects, schedule, milestones, progress)
        VALUES (?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.user_id,
        data.title || 'My Study Plan',
        JSON.stringify(data.subjects || []),
        JSON.stringify(data.schedule || {}),
        JSON.stringify(data.milestones || []),
        JSON.stringify(data.progress || {})
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('PersonalPlanner.create error:', error);
      throw error;
    }
  },

  // Update planner by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE personal_planners SET
          title = ?, subjects = ?, schedule = ?,
          milestones = ?, progress = ?, updated_at = NOW()
        WHERE id = ?
      `;
      const values = [
        data.title,
        JSON.stringify(data.subjects || []),
        JSON.stringify(data.schedule || {}),
        JSON.stringify(data.milestones || []),
        JSON.stringify(data.progress || {}),
        id
      ];

      await pool.execute(sql, values);
      return await PersonalPlanner.findById(id);
    } catch (error) {
      console.error('PersonalPlanner.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update planner (alias)
  update: async (id, data) => {
    return await PersonalPlanner.findByIdAndUpdate(id, data);
  },

  // Delete planner
  findByIdAndDelete: async (id) => {
    try {
      const planner = await PersonalPlanner.findById(id);
      if (!planner) return null;
      
      const sql = 'DELETE FROM personal_planners WHERE id = ?';
      await pool.execute(sql, [id]);
      return planner;
    } catch (error) {
      console.error('PersonalPlanner.findByIdAndDelete error:', error);
      throw error;
    }
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM personal_planners WHERE 1=1';
      const values = [];

      if (query.user_id) {
        sql += ' AND user_id = ?';
        values.push(query.user_id);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('PersonalPlanner.countDocuments error:', error);
      throw error;
    }
  }
};

module.exports = PersonalPlanner;
