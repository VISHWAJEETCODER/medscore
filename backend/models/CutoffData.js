const { pool } = require('../config/mysql-db');

// CutoffData Model for MySQL (stores data in colleges table as JSON)
const CutoffData = {
  // Get cutoff data for a college
  getCutoffByCollege: async (collegeId) => {
    try {
      const sql = 'SELECT cutoff_data FROM colleges WHERE id = ?';
      const [rows] = await pool.execute(sql, [collegeId]);
      
      if (rows[0] && rows[0].cutoff_data) {
        return typeof rows[0].cutoff_data === 'string' 
          ? JSON.parse(rows[0].cutoff_data) 
          : rows[0].cutoff_data;
      }
      return null;
    } catch (error) {
      console.error('CutoffData.getCutoffByCollege error:', error);
      throw error;
    }
  },

  // Update cutoff data for a college
  updateCutoff: async (collegeId, cutoffData) => {
    try {
      const sql = 'UPDATE colleges SET cutoff_data = ?, updated_at = NOW() WHERE id = ?';
      await pool.execute(sql, [JSON.stringify(cutoffData), collegeId]);
      return cutoffData;
    } catch (error) {
      console.error('CutoffData.updateCutoff error:', error);
      throw error;
    }
  },

  // Search colleges by cutoff range
  searchByCutoff: async (minCutoff, maxCutoff) => {
    try {
      const sql = 'SELECT * FROM colleges WHERE 1=1 ORDER BY ranking ASC';
      const [rows] = await pool.execute(sql);
      
      // Filter by cutoff (simplified - actual implementation depends on JSON structure)
      return rows.filter(college => {
        if (!college.cutoff_data) return false;
        const cutoff = typeof college.cutoff_data === 'string' 
          ? JSON.parse(college.cutoff_data) 
          : college.cutoff_data;
        
        const generalCutoff = cutoff?.general || cutoff?.rank || 0;
        return generalCutoff >= minCutoff && generalCutoff <= maxCutoff;
      });
    } catch (error) {
      console.error('CutoffData.searchByCutoff error:', error);
      throw error;
    }
  },

  // Get all cutoff data
  getAllCutoffs: async () => {
    try {
      const sql = 'SELECT id, name, state, type, cutoff_data FROM colleges WHERE cutoff_data IS NOT NULL';
      const [rows] = await pool.execute(sql);
      
      return rows.map(row => ({
        ...row,
        cutoff_data: typeof row.cutoff_data === 'string' 
          ? JSON.parse(row.cutoff_data) 
          : row.cutoff_data
      }));
    } catch (error) {
      console.error('CutoffData.getAllCutoffs error:', error);
      throw error;
    }
  }
};

module.exports = CutoffData;
