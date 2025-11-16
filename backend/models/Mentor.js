const { pool } = require('../config/mysql-db');

// Mentor Model for MySQL
const Mentor = {
  // Find mentor by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM mentors WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('Mentor.findById error:', error);
      throw error;
    }
  },

  // Find one mentor
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM mentors WHERE ';
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
      console.error('Mentor.findOne error:', error);
      throw error;
    }
  },

  // Find all mentors
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM mentors WHERE is_available = 1';
      const values = [];

      if (query.college_name) {
        sql += ' AND college_name = ?';
        values.push(query.college_name);
      }
      if (query.specialization) {
        sql += ' AND specialization = ?';
        values.push(query.specialization);
      }
      if (query.is_verified !== undefined) {
        sql += ' AND is_verified = ?';
        values.push(query.is_verified);
      }

      sql += ' ORDER BY rating DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('Mentor.find error:', error);
      throw error;
    }
  },

  // Create new mentor
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO mentors 
        (user_id, college_name, specialization, experience_years, subjects, 
         hourly_rate, availability, bio, is_verified, is_available)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.user_id,
        data.college_name,
        data.specialization,
        data.experience_years || 0,
        JSON.stringify(data.subjects || []),
        data.hourly_rate || 50,
        JSON.stringify(data.availability || {}),
        data.bio || '',
        data.is_verified || false,
        data.is_available !== undefined ? data.is_available : true
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('Mentor.create error:', error);
      throw error;
    }
  },

  // Update mentor by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE mentors SET
          college_name = ?, specialization = ?, experience_years = ?,
          subjects = ?, hourly_rate = ?, availability = ?,
          bio = ?, is_verified = ?, is_available = ?,
          updated_at = NOW()
        WHERE id = ?
      `;
      const values = [
        data.college_name,
        data.specialization,
        data.experience_years,
        JSON.stringify(data.subjects || []),
        data.hourly_rate,
        JSON.stringify(data.availability || {}),
        data.bio,
        data.is_verified,
        data.is_available,
        id
      ];

      await pool.execute(sql, values);
      return await Mentor.findById(id);
    } catch (error) {
      console.error('Mentor.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update mentor (alias)
  update: async (id, data) => {
    return await Mentor.findByIdAndUpdate(id, data);
  },

  // Delete mentor
  findByIdAndDelete: async (id) => {
    try {
      const mentor = await Mentor.findById(id);
      if (!mentor) return null;
      
      const sql = 'DELETE FROM mentors WHERE id = ?';
      await pool.execute(sql, [id]);
      return mentor;
    } catch (error) {
      console.error('Mentor.findByIdAndDelete error:', error);
      throw error;
    }
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM mentors WHERE 1=1';
      const values = [];

      if (query.is_verified !== undefined) {
        sql += ' AND is_verified = ?';
        values.push(query.is_verified);
      }
      if (query.is_available !== undefined) {
        sql += ' AND is_available = ?';
        values.push(query.is_available);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('Mentor.countDocuments error:', error);
      throw error;
    }
  },

  // Search mentors
  searchMentors: async (searchParams) => {
    const {
      query,
      college_name,
      specialization,
      minRating,
      maxRate,
      sortBy = 'rating',
      sortOrder = 'desc',
      page = 1,
      limit = 20
    } = searchParams;

    try {
      let sql = 'SELECT * FROM mentors WHERE is_available = 1 AND is_verified = 1';
      const values = [];

      if (query) {
        sql += ' AND (college_name LIKE ? OR specialization LIKE ?)';
        values.push(`%${query}%`, `%${query}%`);
      }
      if (college_name) {
        sql += ' AND college_name = ?';
        values.push(college_name);
      }
      if (specialization) {
        sql += ' AND specialization = ?';
        values.push(specialization);
      }
      if (minRating) {
        sql += ' AND rating >= ?';
        values.push(minRating);
      }
      if (maxRate) {
        sql += ' AND hourly_rate <= ?';
        values.push(maxRate);
      }

      const offset = (page - 1) * limit;
      const order = sortOrder === 'desc' ? 'DESC' : 'ASC';
      sql += ` ORDER BY ${sortBy} ${order}, total_sessions DESC LIMIT ? OFFSET ?`;
      values.push(parseInt(limit), offset);

      const [rows] = await pool.execute(sql, values);
      
      // Get total count
      let countSql = 'SELECT COUNT(*) as total FROM mentors WHERE is_available = 1 AND is_verified = 1';
      const countValues = [];
      
      if (query) {
        countSql += ' AND (college_name LIKE ? OR specialization LIKE ?)';
        countValues.push(`%${query}%`, `%${query}%`);
      }
      if (college_name) {
        countSql += ' AND college_name = ?';
        countValues.push(college_name);
      }
      if (specialization) {
        countSql += ' AND specialization = ?';
        countValues.push(specialization);
      }
      if (minRating) {
        countSql += ' AND rating >= ?';
        countValues.push(minRating);
      }
      if (maxRate) {
        countSql += ' AND hourly_rate <= ?';
        countValues.push(maxRate);
      }

      const [countRows] = await pool.execute(countSql, countValues);
      const total = countRows[0].total;

      return {
        mentors: rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      console.error('Mentor.searchMentors error:', error);
      throw error;
    }
  },

  // Get top mentors
  getTopMentors: async (limit = 10) => {
    try {
      const sql = `
        SELECT * FROM mentors 
        WHERE is_available = 1 AND is_verified = 1
        ORDER BY rating DESC, total_sessions DESC
        LIMIT ?
      `;
      const [rows] = await pool.execute(sql, [limit]);
      return rows;
    } catch (error) {
      console.error('Mentor.getTopMentors error:', error);
      throw error;
    }
  },

  // Get mentors by college
  getMentorsByCollege: async (collegeName) => {
    try {
      const sql = `
        SELECT * FROM mentors
        WHERE college_name = ? AND is_available = 1
        ORDER BY rating DESC
      `;
      const [rows] = await pool.execute(sql, [collegeName]);
      return rows;
    } catch (error) {
      console.error('Mentor.getMentorsByCollege error:', error);
      throw error;
    }
  }
};

module.exports = Mentor;




