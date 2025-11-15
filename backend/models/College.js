const { pool } = require('../config/mysql-db');

// College Model for MySQL
const College = {
  // Find one college by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM colleges WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('College.findById error:', error);
      throw error;
    }
  },

  // Find one college
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM colleges WHERE ';
      const conditions = [];
      const values = [];

      if (query.id) {
        conditions.push('id = ?');
        values.push(query.id);
      }
      if (query.name) {
        conditions.push('name = ?');
        values.push(query.name);
      }

      sql += conditions.join(' AND ') + ' LIMIT 1';
      const [rows] = await pool.execute(sql, values);
      return rows[0] || null;
    } catch (error) {
      console.error('College.findOne error:', error);
      throw error;
    }
  },

  // Find all colleges with filters
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM colleges WHERE 1=1';
      const values = [];

      if (query.state) {
        sql += ' AND state = ?';
        values.push(query.state);
      }
      if (query.type) {
        sql += ' AND type = ?';
        values.push(query.type);
      }

      sql += ' ORDER BY ranking ASC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('College.find error:', error);
      throw error;
    }
  },

  // Create new college
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO colleges (name, state, type, cutoff_data, photos, facilities, fees, ranking)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.name,
        data.state || null,
        data.type || 'Government',
        JSON.stringify(data.cutoff_data || {}),
        JSON.stringify(data.photos || []),
        data.facilities || null,
        JSON.stringify(data.fees || {}),
        data.ranking || null
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('College.create error:', error);
      throw error;
    }
  },

  // Update college by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE colleges SET
          name = ?, state = ?, type = ?, cutoff_data = ?,
          photos = ?, facilities = ?, fees = ?, ranking = ?,
          updated_at = NOW()
        WHERE id = ?
      `;
      const values = [
        data.name,
        data.state,
        data.type,
        JSON.stringify(data.cutoff_data || {}),
        JSON.stringify(data.photos || []),
        data.facilities,
        JSON.stringify(data.fees || {}),
        data.ranking,
        id
      ];

      await pool.execute(sql, values);
      return await College.findById(id);
    } catch (error) {
      console.error('College.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update college (alias)
  update: async (id, data) => {
    return await College.findByIdAndUpdate(id, data);
  },

  // Delete college
  findByIdAndDelete: async (id) => {
    try {
      const college = await College.findById(id);
      if (!college) return null;
      
      const sql = 'DELETE FROM colleges WHERE id = ?';
      await pool.execute(sql, [id]);
      return college;
    } catch (error) {
      console.error('College.findByIdAndDelete error:', error);
      throw error;
    }
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM colleges WHERE 1=1';
      const values = [];

      if (query.state) {
        sql += ' AND state = ?';
        values.push(query.state);
      }
      if (query.type) {
        sql += ' AND type = ?';
        values.push(query.type);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('College.countDocuments error:', error);
      throw error;
    }
  },

  // Search colleges (Static method equivalent)
  searchColleges: async (searchParams) => {
    const {
      query,
      state,
      city,
      type,
      category,
      minRating,
      sortBy = 'ranking',
      sortOrder = 'asc',
      page = 1,
      limit = 20
    } = searchParams;

    try {
      let sql = 'SELECT * FROM colleges WHERE 1=1';
      const values = [];

      if (query) {
        sql += ' AND (name LIKE ? OR state LIKE ?)';
        values.push(`%${query}%`, `%${query}%`);
      }
      if (state) {
        sql += ' AND state = ?';
        values.push(state);
      }
      if (type) {
        sql += ' AND type = ?';
        values.push(type);
      }

      const offset = (page - 1) * limit;
      const order = sortOrder === 'desc' ? 'DESC' : 'ASC';
      sql += ` ORDER BY ${sortBy} ${order} LIMIT ? OFFSET ?`;
      values.push(parseInt(limit), offset);

      const [rows] = await pool.execute(sql, values);
      
      // Get total count
      let countSql = 'SELECT COUNT(*) as total FROM colleges WHERE 1=1';
      const countValues = [];
      
      if (query) {
        countSql += ' AND (name LIKE ? OR state LIKE ?)';
        countValues.push(`%${query}%`, `%${query}%`);
      }
      if (state) {
        countSql += ' AND state = ?';
        countValues.push(state);
      }
      if (type) {
        countSql += ' AND type = ?';
        countValues.push(type);
      }

      const [countRows] = await pool.execute(countSql, countValues);
      const total = countRows[0].total;

      return {
        colleges: rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      console.error('College.searchColleges error:', error);
      throw error;
    }
  },

  // Get trending colleges
  getTrendingColleges: async (limit = 10) => {
    try {
      const sql = `
        SELECT * FROM colleges 
        WHERE 1=1
        ORDER BY ranking ASC
        LIMIT ?
      `;
      const [rows] = await pool.execute(sql, [limit]);
      return rows;
    } catch (error) {
      console.error('College.getTrendingColleges error:', error);
      throw error;
    }
  },

  // Get colleges by state
  getCollegesByState: async (state) => {
    try {
      const sql = `
        SELECT * FROM colleges
        WHERE state = ?
        ORDER BY ranking ASC
      `;
      const [rows] = await pool.execute(sql, [state]);
      return rows;
    } catch (error) {
      console.error('College.getCollegesByState error:', error);
      throw error;
    }
  }
};

module.exports = College;



