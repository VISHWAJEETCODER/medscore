const { pool } = require('../config/mysql-db');

// StudyMaterial Model for MySQL
const StudyMaterial = {
  // Find material by ID
  findById: async (id) => {
    try {
      const sql = 'SELECT * FROM study_materials WHERE id = ? LIMIT 1';
      const [rows] = await pool.execute(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      console.error('StudyMaterial.findById error:', error);
      throw error;
    }
  },

  // Find one material
  findOne: async (query) => {
    try {
      let sql = 'SELECT * FROM study_materials WHERE ';
      const conditions = [];
      const values = [];

      if (query.id) {
        conditions.push('id = ?');
        values.push(query.id);
      }
      if (query.title) {
        conditions.push('title = ?');
        values.push(query.title);
      }

      sql += conditions.join(' AND ') + ' LIMIT 1';
      const [rows] = await pool.execute(sql, values);
      return rows[0] || null;
    } catch (error) {
      console.error('StudyMaterial.findOne error:', error);
      throw error;
    }
  },

  // Find all materials
  find: async (query = {}) => {
    try {
      let sql = 'SELECT * FROM study_materials WHERE 1=1';
      const values = [];

      if (query.subject) {
        sql += ' AND subject = ?';
        values.push(query.subject);
      }
      if (query.type) {
        sql += ' AND type = ?';
        values.push(query.type);
      }
      if (query.is_premium !== undefined) {
        sql += ' AND is_premium = ?';
        values.push(query.is_premium);
      }
      if (query.uploaded_by) {
        sql += ' AND uploaded_by = ?';
        values.push(query.uploaded_by);
      }

      sql += ' ORDER BY created_at DESC';
      const [rows] = await pool.execute(sql, values);
      return rows;
    } catch (error) {
      console.error('StudyMaterial.find error:', error);
      throw error;
    }
  },

  // Create new material
  create: async (data) => {
    try {
      const sql = `
        INSERT INTO study_materials 
        (title, subject, type, file_path, description, is_premium, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [
        data.title,
        data.subject || '',
        data.type || 'pdf',
        data.file_path || '',
        data.description || '',
        data.is_premium || false,
        data.uploaded_by || null
      ];

      const [result] = await pool.execute(sql, values);
      return { id: result.insertId, ...data };
    } catch (error) {
      console.error('StudyMaterial.create error:', error);
      throw error;
    }
  },

  // Update material by ID
  findByIdAndUpdate: async (id, data) => {
    try {
      const sql = `
        UPDATE study_materials SET
          title = ?, subject = ?, type = ?,
          file_path = ?, description = ?, is_premium = ?,
          updated_at = NOW()
        WHERE id = ?
      `;
      const values = [
        data.title,
        data.subject,
        data.type,
        data.file_path,
        data.description,
        data.is_premium,
        id
      ];

      await pool.execute(sql, values);
      return await StudyMaterial.findById(id);
    } catch (error) {
      console.error('StudyMaterial.findByIdAndUpdate error:', error);
      throw error;
    }
  },

  // Update material (alias)
  update: async (id, data) => {
    return await StudyMaterial.findByIdAndUpdate(id, data);
  },

  // Delete material
  findByIdAndDelete: async (id) => {
    try {
      const material = await StudyMaterial.findById(id);
      if (!material) return null;
      
      const sql = 'DELETE FROM study_materials WHERE id = ?';
      await pool.execute(sql, [id]);
      return material;
    } catch (error) {
      console.error('StudyMaterial.findByIdAndDelete error:', error);
      throw error;
    }
  },

  // Count documents
  countDocuments: async (query = {}) => {
    try {
      let sql = 'SELECT COUNT(*) as total FROM study_materials WHERE 1=1';
      const values = [];

      if (query.subject) {
        sql += ' AND subject = ?';
        values.push(query.subject);
      }
      if (query.type) {
        sql += ' AND type = ?';
        values.push(query.type);
      }
      if (query.is_premium !== undefined) {
        sql += ' AND is_premium = ?';
        values.push(query.is_premium);
      }

      const [rows] = await pool.execute(sql, values);
      return rows[0].total;
    } catch (error) {
      console.error('StudyMaterial.countDocuments error:', error);
      throw error;
    }
  },

  // Search materials
  searchMaterials: async (searchParams) => {
    const {
      query,
      subject,
      type,
      is_premium,
      sortBy = 'created_at',
      sortOrder = 'desc',
      page = 1,
      limit = 20
    } = searchParams;

    try {
      let sql = 'SELECT * FROM study_materials WHERE 1=1';
      const values = [];

      if (query) {
        sql += ' AND (title LIKE ? OR description LIKE ?)';
        values.push(`%${query}%`, `%${query}%`);
      }
      if (subject) {
        sql += ' AND subject = ?';
        values.push(subject);
      }
      if (type) {
        sql += ' AND type = ?';
        values.push(type);
      }
      if (is_premium !== undefined) {
        sql += ' AND is_premium = ?';
        values.push(is_premium);
      }

      const offset = (page - 1) * limit;
      const order = sortOrder === 'desc' ? 'DESC' : 'ASC';
      sql += ` ORDER BY ${sortBy} ${order} LIMIT ? OFFSET ?`;
      values.push(parseInt(limit), offset);

      const [rows] = await pool.execute(sql, values);
      
      // Get total count
      let countSql = 'SELECT COUNT(*) as total FROM study_materials WHERE 1=1';
      const countValues = [];
      
      if (query) {
        countSql += ' AND (title LIKE ? OR description LIKE ?)';
        countValues.push(`%${query}%`, `%${query}%`);
      }
      if (subject) {
        countSql += ' AND subject = ?';
        countValues.push(subject);
      }
      if (type) {
        countSql += ' AND type = ?';
        countValues.push(type);
      }
      if (is_premium !== undefined) {
        countSql += ' AND is_premium = ?';
        countValues.push(is_premium);
      }

      const [countRows] = await pool.execute(countSql, countValues);
      const total = countRows[0].total;

      return {
        materials: rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      console.error('StudyMaterial.searchMaterials error:', error);
      throw error;
    }
  }
};

module.exports = StudyMaterial;
