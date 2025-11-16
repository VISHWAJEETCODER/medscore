const express = require('express');
const { body, param, query } = require('express-validator');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const fs = require('fs');
const path = require('path');

const router = express.Router();

/**
 * @route   GET /api/cutoffs
 * @desc    Get college cutoff data
 * @access  Public
 */
router.get('/', async (req, res) => {
  try {
    const { college, category, year, limit = 50, offset = 0 } = req.query;

    // Read cutoff data
    const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
    let cutoffsData = [];
    
    try {
      cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
    } catch (error) {
      // File doesn't exist, return empty array
      return res.status(200).json({
        success: true,
        cutoffs: [],
        total: 0,
        message: 'No cutoff data available'
      });
    }

    // Apply filters
    let filteredCutoffs = cutoffsData;

    if (college) {
      filteredCutoffs = filteredCutoffs.filter(cutoff => 
        cutoff.collegeName.toLowerCase().includes(college.toLowerCase())
      );
    }

    if (category) {
      filteredCutoffs = filteredCutoffs.filter(cutoff => 
        cutoff.category === category
      );
    }

    if (year) {
      filteredCutoffs = filteredCutoffs.filter(cutoff => 
        cutoff.year === parseInt(year)
      );
    }

    // Apply pagination
    const total = filteredCutoffs.length;
    const paginatedCutoffs = filteredCutoffs.slice(
      parseInt(offset), 
      parseInt(offset) + parseInt(limit)
    );

    res.status(200).json({
      success: true,
      cutoffs: paginatedCutoffs,
      total,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

  } catch (error) {
    logger.error('Error fetching cutoff data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   GET /api/cutoffs/:id
 * @desc    Get specific cutoff data by ID
 * @access  Public
 */
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Read cutoff data
    const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
    let cutoffsData = [];
    
    try {
      cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
  } catch (error) {
      return res.status(404).json({ error: 'Cutoff data not found' });
    }

    const cutoff = cutoffsData.find(c => c.id === id);
    if (!cutoff) {
      return res.status(404).json({ error: 'Cutoff not found' });
    }

    res.status(200).json({
      success: true,
      cutoff
    });

  } catch (error) {
    logger.error('Error fetching cutoff:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   GET /api/cutoffs/college/:collegeId
 * @desc    Get cutoff data for specific college
 * @access  Public
 */
router.get('/college/:collegeId', async (req, res) => {
  try {
    const { collegeId } = req.params;
    const { year, category } = req.query;

    // Read cutoff data
    const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
    let cutoffsData = [];
    
    try {
      cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
    } catch (error) {
      return res.status(200).json({
        success: true,
        cutoffs: [],
        message: 'No cutoff data available for this college'
      });
    }

    let collegeCutoffs = cutoffsData.filter(cutoff => cutoff.collegeId === collegeId);

    if (year) {
      collegeCutoffs = collegeCutoffs.filter(cutoff => cutoff.year === parseInt(year));
    }

    if (category) {
      collegeCutoffs = collegeCutoffs.filter(cutoff => cutoff.category === category);
    }

    // Sort by year (newest first)
    collegeCutoffs.sort((a, b) => b.year - a.year);

    res.status(200).json({
      success: true,
      cutoffs: collegeCutoffs,
      total: collegeCutoffs.length
    });

  } catch (error) {
    logger.error('Error fetching college cutoff data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/cutoffs
 * @desc    Add new cutoff data
 * @access  Admin only
 */
router.post('/',
  adminAuth(['admin1', 'admin2']),
  [
    body('collegeId').notEmpty().withMessage('College ID is required'),
    body('collegeName').notEmpty().withMessage('College name is required'),
    body('year').isInt({ min: 2020, max: 2030 }).withMessage('Year must be between 2020 and 2030'),
    body('category').isIn(['General', 'OBC', 'SC', 'ST', 'EWS']).withMessage('Invalid category'),
    body('openingRank').isInt({ min: 1 }).withMessage('Opening rank must be a positive integer'),
    body('closingRank').isInt({ min: 1 }).withMessage('Closing rank must be a positive integer'),
    body('course').notEmpty().withMessage('Course is required')
  ],
  logAdminAction('add_cutoff'),
  async (req, res) => {
    try {
      const cutoffData = req.body;

      // Read cutoff data
      const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
      let cutoffsData = [];
      
      try {
        cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
      } catch (error) {
        // File doesn't exist, create new array
      }

      // Generate new ID
      const newId = `cutoff_${Date.now()}`;

      // Create new cutoff entry
      const newCutoff = {
        id: newId,
        ...cutoffData,
        createdAt: new Date().toISOString(),
        createdBy: req.admin.id
      };

      cutoffsData.push(newCutoff);
      fs.writeFileSync(cutoffsPath, JSON.stringify(cutoffsData, null, 2));

      logger.info(`Admin ${req.admin.email} added cutoff data for ${cutoffData.collegeName}`);

      res.status(201).json({
        success: true,
        message: 'Cutoff data added successfully',
        cutoff: newCutoff
      });

    } catch (error) {
      logger.error('Error adding cutoff data:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   PUT /api/cutoffs/:id
 * @desc    Update cutoff data
 * @access  Admin only
 */
router.put('/:id',
  adminAuth(['admin1', 'admin2']),
  [
    body('year').optional().isInt({ min: 2020, max: 2030 }).withMessage('Year must be between 2020 and 2030'),
    body('category').optional().isIn(['General', 'OBC', 'SC', 'ST', 'EWS']).withMessage('Invalid category'),
    body('openingRank').optional().isInt({ min: 1 }).withMessage('Opening rank must be a positive integer'),
    body('closingRank').optional().isInt({ min: 1 }).withMessage('Closing rank must be a positive integer')
  ],
  logAdminAction('update_cutoff'),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      // Read cutoff data
      const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
      let cutoffsData = [];
      
      try {
        cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Cutoff data not found' });
      }

      const cutoffIndex = cutoffsData.findIndex(cutoff => cutoff.id === id);
      if (cutoffIndex === -1) {
        return res.status(404).json({ error: 'Cutoff not found' });
      }

      // Update cutoff
      cutoffsData[cutoffIndex] = {
        ...cutoffsData[cutoffIndex],
        ...updates,
        updatedAt: new Date().toISOString(),
        updatedBy: req.admin.id
      };

      fs.writeFileSync(cutoffsPath, JSON.stringify(cutoffsData, null, 2));

      logger.info(`Admin ${req.admin.email} updated cutoff data: ${id}`);

      res.status(200).json({
        success: true,
        message: 'Cutoff data updated successfully',
        cutoff: cutoffsData[cutoffIndex]
      });

    } catch (error) {
      logger.error('Error updating cutoff data:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   DELETE /api/cutoffs/:id
 * @desc    Delete cutoff data
 * @access  Admin only
 */
router.delete('/:id',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('delete_cutoff'),
  async (req, res) => {
    try {
      const { id } = req.params;

      // Read cutoff data
      const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
      let cutoffsData = [];
      
      try {
        cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Cutoff data not found' });
      }

      const cutoffIndex = cutoffsData.findIndex(cutoff => cutoff.id === id);
      if (cutoffIndex === -1) {
        return res.status(404).json({ error: 'Cutoff not found' });
      }

      // Remove cutoff
      const deletedCutoff = cutoffsData.splice(cutoffIndex, 1)[0];
      fs.writeFileSync(cutoffsPath, JSON.stringify(cutoffsData, null, 2));

      logger.info(`Admin ${req.admin.email} deleted cutoff data: ${id}`);

      res.status(200).json({
        success: true,
        message: 'Cutoff data deleted successfully',
        cutoff: deletedCutoff
      });

    } catch (error) {
      logger.error('Error deleting cutoff data:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   GET /api/cutoffs/stats/overview
 * @desc    Get cutoff statistics overview
 * @access  Public
 */
router.get('/stats/overview', async (req, res) => {
  try {
    // Read cutoff data
    const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
    let cutoffsData = [];
    
    try {
      cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
    } catch (error) {
      return res.status(200).json({
        success: true,
        stats: {
          totalCutoffs: 0,
          totalColleges: 0,
          yearRange: { min: null, max: null },
          categories: [],
          topColleges: []
        }
      });
    }

    // Calculate statistics
    const totalCutoffs = cutoffsData.length;
    const uniqueColleges = [...new Set(cutoffsData.map(c => c.collegeId))].length;
    const years = cutoffsData.map(c => c.year);
    const yearRange = {
      min: Math.min(...years),
      max: Math.max(...years)
    };
    
    const categories = [...new Set(cutoffsData.map(c => c.category))];
    
    // Top colleges by number of cutoff entries
    const collegeCounts = {};
    cutoffsData.forEach(cutoff => {
      collegeCounts[cutoff.collegeName] = (collegeCounts[cutoff.collegeName] || 0) + 1;
    });
    
    const topColleges = Object.entries(collegeCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([name, count]) => ({ name, count }));

    res.status(200).json({
        success: true,
      stats: {
        totalCutoffs,
        totalColleges: uniqueColleges,
        yearRange,
        categories,
        topColleges
        }
      });

    } catch (error) {
    logger.error('Error fetching cutoff statistics:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/cutoffs/bulk-import
 * @desc    Bulk import cutoff data
 * @access  Admin only
 */
router.post('/bulk-import',
  adminAuth(['admin1', 'admin2']),
  [
    body('cutoffs').isArray().withMessage('Cutoffs must be an array'),
    body('cutoffs.*.collegeId').notEmpty().withMessage('College ID is required for each cutoff'),
    body('cutoffs.*.collegeName').notEmpty().withMessage('College name is required for each cutoff'),
    body('cutoffs.*.year').isInt({ min: 2020, max: 2030 }).withMessage('Year must be between 2020 and 2030'),
    body('cutoffs.*.category').isIn(['General', 'OBC', 'SC', 'ST', 'EWS']).withMessage('Invalid category'),
    body('cutoffs.*.openingRank').isInt({ min: 1 }).withMessage('Opening rank must be a positive integer'),
    body('cutoffs.*.closingRank').isInt({ min: 1 }).withMessage('Closing rank must be a positive integer'),
    body('cutoffs.*.course').notEmpty().withMessage('Course is required for each cutoff')
  ],
  logAdminAction('bulk_import_cutoffs'),
  async (req, res) => {
    try {
      const { cutoffs } = req.body;

      // Read cutoff data
      const cutoffsPath = path.join(__dirname, '../data/cutoffs.json');
      let cutoffsData = [];
      
      try {
        cutoffsData = JSON.parse(fs.readFileSync(cutoffsPath, 'utf8'));
      } catch (error) {
        // File doesn't exist, create new array
      }

      // Add new cutoffs
      const newCutoffs = cutoffs.map(cutoff => ({
        id: `cutoff_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        ...cutoff,
        createdAt: new Date().toISOString(),
        createdBy: req.admin.id
      }));

      cutoffsData.push(...newCutoffs);
      fs.writeFileSync(cutoffsPath, JSON.stringify(cutoffsData, null, 2));

      logger.info(`Admin ${req.admin.email} bulk imported ${cutoffs.length} cutoff entries`);

      res.status(201).json({
        success: true,
        message: `${cutoffs.length} cutoff entries imported successfully`,
        imported: cutoffs.length,
        cutoffs: newCutoffs
      });

    } catch (error) {
      logger.error('Error bulk importing cutoff data:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

module.exports = router;

