const { pool } = require('../config/mysql-db');

// AdminLog Model for MySQL
const AdminLog = {
  // Create new log entry
  create: async (data) => {
    try {
      // Try to create admin_logs table if it doesn't exist
      const createTableSql = `
        CREATE TABLE IF NOT EXISTS admin_logs (
          id INT AUTO_INCREMENT PRIMARY KEY,
          admin_id INT,
          action VARCHAR(255),
          entity_type VARCHAR(100),
          entity_id INT,
          details JSON,
          ip_address VARCHAR(45),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `;
      await pool.execute(createTableSql);

      const sql = `
        INSERT INTO admin_logs 
        (admin_id, action, entity_type, entity_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.admin_id,
        data.action || 'unknown',
        data.entity_type || '',
        data.entity_id || null,
        JSON.stringify(data.details || {}),
        data.ip_address || ''
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.warn('AdminLog.create - silent fail:', error.message);
      return null;
    }
  },

  // Find all logs
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM admin_logs WHERE 1=1';
      const values = [];

      if (query.admin_id) {
        sql += ' AND admin_id = ?';
        values.push(query.admin_id);
      }
      if (query.action) {
        sql += ' AND action = ?';
        values.push(query.action);
      }
      if (query.entity_type) {
        sql += ' AND entity_type = ?';
        values.push(query.entity_type);
      }

      sql += ' ORDER BY created_at DESC LIMIT 100';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.warn('AdminLog.find - table may not exist:', error.message);
      return [];
    }
  },

  // Get recent logs
  getRecentLogs: async (limit = 50) => {
    try {
      const sql = 'SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT ?';
      const [rows] = await pool.execute(sql, [limit]);
      return rows;
    } catch (error) {
      console.warn('AdminLog.getRecentLogs error:', error.message);
      return [];
    }
  }
};

module.exports = AdminLog;
