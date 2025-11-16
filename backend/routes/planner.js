const express = require('express');
const { body, param, query } = require('express-validator');
const { authenticate } = require('../middleware/auth');
const logger = require('../utils/logger');
const fs = require('fs');
const path = require('path');

const router = express.Router();

/**
 * @route   GET /api/planner/data
 * @desc    Get user's study planner data
 * @access  Private
 */
router.get('/data', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    // Read planner data
    const plannerPath = path.join(__dirname, '../data/planners.json');
    let plannerData = [];
    
    try {
      plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
    } catch (error) {
      // File doesn't exist, return empty data
      return res.status(200).json({
        success: true,
        goals: [],
        sessions: [],
        notes: [],
        message: 'No planner data found'
      });
    }

    // Find user's planner data
    const userPlanner = plannerData.find(p => p.userId === userId);
    
    if (!userPlanner) {
      // Create new planner entry for user
      const newPlanner = {
        userId: userId,
        goals: [],
        sessions: [],
        notes: [],
        preferences: {
          dailyStudyHours: 6,
          preferredSubjects: [],
          studyTime: 'morning',
          reminders: true
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      plannerData.push(newPlanner);
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      return res.status(200).json({
        success: true,
        goals: [],
        sessions: [],
        notes: [],
        preferences: newPlanner.preferences
      });
    }

    res.status(200).json({
      success: true,
      goals: userPlanner.goals || [],
      sessions: userPlanner.sessions || [],
      notes: userPlanner.notes || [],
      preferences: userPlanner.preferences || {}
    });

  } catch (error) {
    logger.error('Error fetching planner data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/planner/goals
 * @desc    Add study goal
 * @access  Private
 */
router.post('/goals',
  authenticate,
  [
    body('text').notEmpty().withMessage('Goal text is required'),
    body('priority').optional().isIn(['low', 'medium', 'high']).withMessage('Invalid priority'),
    body('deadline').optional().isISO8601().withMessage('Invalid deadline format')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { text, priority = 'medium', deadline } = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        // File doesn't exist, create new array
      }

      // Find user's planner
      let userPlanner = plannerData.find(p => p.userId === userId);
      
      if (!userPlanner) {
        userPlanner = {
          userId: userId,
          goals: [],
          sessions: [],
          notes: [],
          preferences: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        plannerData.push(userPlanner);
      }

      // Create new goal
      const newGoal = {
        id: `goal_${Date.now()}`,
        text: text,
        priority: priority,
        deadline: deadline,
        completed: false,
        createdAt: new Date().toISOString()
      };

      userPlanner.goals.push(newGoal);
      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} added new study goal`);

    res.status(201).json({
      success: true,
        message: 'Goal added successfully',
        goal: newGoal
    });

  } catch (error) {
      logger.error('Error adding study goal:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   PUT /api/planner/goals/:goalId
 * @desc    Update study goal
 * @access  Private
 */
router.put('/goals/:goalId',
  authenticate,
  [
    body('text').optional().notEmpty().withMessage('Goal text cannot be empty'),
    body('priority').optional().isIn(['low', 'medium', 'high']).withMessage('Invalid priority'),
    body('deadline').optional().isISO8601().withMessage('Invalid deadline format'),
    body('completed').optional().isBoolean().withMessage('Completed must be boolean')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { goalId } = req.params;
      const updates = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Planner data not found' });
      }

      const userPlanner = plannerData.find(p => p.userId === userId);
      if (!userPlanner) {
        return res.status(404).json({ error: 'User planner not found' });
      }

      const goalIndex = userPlanner.goals.findIndex(g => g.id === goalId);
      if (goalIndex === -1) {
        return res.status(404).json({ error: 'Goal not found' });
      }

      // Update goal
      userPlanner.goals[goalIndex] = {
        ...userPlanner.goals[goalIndex],
        ...updates,
        updatedAt: new Date().toISOString()
      };

      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} updated goal: ${goalId}`);

      res.status(200).json({
        success: true,
        message: 'Goal updated successfully',
        goal: userPlanner.goals[goalIndex]
      });

    } catch (error) {
      logger.error('Error updating study goal:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   DELETE /api/planner/goals/:goalId
 * @desc    Delete study goal
 * @access  Private
 */
router.delete('/goals/:goalId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { goalId } = req.params;

    // Read planner data
    const plannerPath = path.join(__dirname, '../data/planners.json');
    let plannerData = [];
    
    try {
      plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
    } catch (error) {
      return res.status(404).json({ error: 'Planner data not found' });
    }

    const userPlanner = plannerData.find(p => p.userId === userId);
    if (!userPlanner) {
      return res.status(404).json({ error: 'User planner not found' });
    }

    const goalIndex = userPlanner.goals.findIndex(g => g.id === goalId);
    if (goalIndex === -1) {
      return res.status(404).json({ error: 'Goal not found' });
    }

    // Remove goal
    const deletedGoal = userPlanner.goals.splice(goalIndex, 1)[0];
    userPlanner.updatedAt = new Date().toISOString();

    // Update planner data
    const plannerIndex = plannerData.findIndex(p => p.userId === userId);
    plannerData[plannerIndex] = userPlanner;
    fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

    logger.info(`User ${userId} deleted goal: ${goalId}`);

    res.status(200).json({
      success: true,
      message: 'Goal deleted successfully',
      goal: deletedGoal
    });

  } catch (error) {
    logger.error('Error deleting study goal:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/planner/sessions
 * @desc    Add study session
 * @access  Private
 */
router.post('/sessions',
  authenticate,
  [
    body('subject').notEmpty().withMessage('Subject is required'),
    body('topic').notEmpty().withMessage('Topic is required'),
    body('date').isISO8601().withMessage('Invalid date format'),
    body('time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Invalid time format'),
    body('duration').isFloat({ min: 0.5, max: 8 }).withMessage('Duration must be between 0.5 and 8 hours'),
    body('type').isIn(['study', 'practice', 'revision', 'test']).withMessage('Invalid session type')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { subject, topic, date, time, duration, type, notes } = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        // File doesn't exist, create new array
      }

      // Find user's planner
      let userPlanner = plannerData.find(p => p.userId === userId);
      
      if (!userPlanner) {
        userPlanner = {
          userId: userId,
          goals: [],
          sessions: [],
          notes: [],
          preferences: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        plannerData.push(userPlanner);
      }

      // Create new session
      const newSession = {
        id: `session_${Date.now()}`,
        subject: subject,
        topic: topic,
        date: date,
        time: time,
        duration: duration,
        type: type,
        notes: notes || '',
        completed: false,
        createdAt: new Date().toISOString()
      };

      userPlanner.sessions.push(newSession);
      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} added new study session`);

      res.status(201).json({
      success: true,
        message: 'Study session added successfully',
        session: newSession
    });

  } catch (error) {
      logger.error('Error adding study session:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   PUT /api/planner/sessions/:sessionId
 * @desc    Update study session
 * @access  Private
 */
router.put('/sessions/:sessionId',
  authenticate,
  [
    body('subject').optional().notEmpty().withMessage('Subject cannot be empty'),
    body('topic').optional().notEmpty().withMessage('Topic cannot be empty'),
    body('date').optional().isISO8601().withMessage('Invalid date format'),
    body('time').optional().matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Invalid time format'),
    body('duration').optional().isFloat({ min: 0.5, max: 8 }).withMessage('Duration must be between 0.5 and 8 hours'),
    body('type').optional().isIn(['study', 'practice', 'revision', 'test']).withMessage('Invalid session type'),
    body('completed').optional().isBoolean().withMessage('Completed must be boolean')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { sessionId } = req.params;
      const updates = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Planner data not found' });
      }

      const userPlanner = plannerData.find(p => p.userId === userId);
      if (!userPlanner) {
        return res.status(404).json({ error: 'User planner not found' });
      }

      const sessionIndex = userPlanner.sessions.findIndex(s => s.id === sessionId);
      if (sessionIndex === -1) {
        return res.status(404).json({ error: 'Session not found' });
      }

      // Update session
      userPlanner.sessions[sessionIndex] = {
        ...userPlanner.sessions[sessionIndex],
        ...updates,
        updatedAt: new Date().toISOString()
      };

      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} updated session: ${sessionId}`);

      res.status(200).json({
        success: true,
        message: 'Study session updated successfully',
        session: userPlanner.sessions[sessionIndex]
      });

    } catch (error) {
      logger.error('Error updating study session:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   DELETE /api/planner/sessions/:sessionId
 * @desc    Delete study session
 * @access  Private
 */
router.delete('/sessions/:sessionId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { sessionId } = req.params;

    // Read planner data
    const plannerPath = path.join(__dirname, '../data/planners.json');
    let plannerData = [];
    
    try {
      plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
    } catch (error) {
      return res.status(404).json({ error: 'Planner data not found' });
    }

    const userPlanner = plannerData.find(p => p.userId === userId);
    if (!userPlanner) {
      return res.status(404).json({ error: 'User planner not found' });
    }

    const sessionIndex = userPlanner.sessions.findIndex(s => s.id === sessionId);
    if (sessionIndex === -1) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Remove session
    const deletedSession = userPlanner.sessions.splice(sessionIndex, 1)[0];
    userPlanner.updatedAt = new Date().toISOString();

    // Update planner data
    const plannerIndex = plannerData.findIndex(p => p.userId === userId);
    plannerData[plannerIndex] = userPlanner;
    fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

    logger.info(`User ${userId} deleted session: ${sessionId}`);

    res.status(200).json({
      success: true,
      message: 'Study session deleted successfully',
      session: deletedSession
    });

  } catch (error) {
    logger.error('Error deleting study session:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/planner/notes
 * @desc    Add study note
 * @access  Private
 */
router.post('/notes',
  authenticate,
  [
    body('title').notEmpty().withMessage('Note title is required'),
    body('content').notEmpty().withMessage('Note content is required'),
    body('subject').optional().notEmpty().withMessage('Subject cannot be empty'),
    body('tags').optional().isArray().withMessage('Tags must be an array')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { title, content, subject, tags = [] } = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        // File doesn't exist, create new array
      }

      // Find user's planner
      let userPlanner = plannerData.find(p => p.userId === userId);
      
      if (!userPlanner) {
        userPlanner = {
          userId: userId,
          goals: [],
          sessions: [],
          notes: [],
          preferences: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        plannerData.push(userPlanner);
      }

      // Create new note
      const newNote = {
        id: `note_${Date.now()}`,
        title: title,
        content: content,
        subject: subject,
        tags: tags,
        createdAt: new Date().toISOString()
      };

      userPlanner.notes.push(newNote);
      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} added new study note`);

      res.status(201).json({
      success: true,
        message: 'Study note added successfully',
        note: newNote
    });

  } catch (error) {
      logger.error('Error adding study note:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   PUT /api/planner/notes/:noteId
 * @desc    Update study note
 * @access  Private
 */
router.put('/notes/:noteId',
  authenticate,
  [
    body('title').optional().notEmpty().withMessage('Note title cannot be empty'),
    body('content').optional().notEmpty().withMessage('Note content cannot be empty'),
    body('subject').optional().notEmpty().withMessage('Subject cannot be empty'),
    body('tags').optional().isArray().withMessage('Tags must be an array')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { noteId } = req.params;
      const updates = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Planner data not found' });
      }

      const userPlanner = plannerData.find(p => p.userId === userId);
      if (!userPlanner) {
        return res.status(404).json({ error: 'User planner not found' });
      }

      const noteIndex = userPlanner.notes.findIndex(n => n.id === noteId);
      if (noteIndex === -1) {
        return res.status(404).json({ error: 'Note not found' });
      }

      // Update note
      userPlanner.notes[noteIndex] = {
        ...userPlanner.notes[noteIndex],
        ...updates,
        updatedAt: new Date().toISOString()
      };

      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} updated note: ${noteId}`);

      res.status(200).json({
        success: true,
        message: 'Study note updated successfully',
        note: userPlanner.notes[noteIndex]
      });

    } catch (error) {
      logger.error('Error updating study note:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   DELETE /api/planner/notes/:noteId
 * @desc    Delete study note
 * @access  Private
 */
router.delete('/notes/:noteId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { noteId } = req.params;

    // Read planner data
    const plannerPath = path.join(__dirname, '../data/planners.json');
    let plannerData = [];
    
    try {
      plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
    } catch (error) {
      return res.status(404).json({ error: 'Planner data not found' });
    }

    const userPlanner = plannerData.find(p => p.userId === userId);
    if (!userPlanner) {
      return res.status(404).json({ error: 'User planner not found' });
    }

    const noteIndex = userPlanner.notes.findIndex(n => n.id === noteId);
    if (noteIndex === -1) {
      return res.status(404).json({ error: 'Note not found' });
    }

    // Remove note
    const deletedNote = userPlanner.notes.splice(noteIndex, 1)[0];
    userPlanner.updatedAt = new Date().toISOString();

    // Update planner data
    const plannerIndex = plannerData.findIndex(p => p.userId === userId);
    plannerData[plannerIndex] = userPlanner;
    fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

    logger.info(`User ${userId} deleted note: ${noteId}`);

    res.status(200).json({
      success: true,
      message: 'Study note deleted successfully',
      note: deletedNote
    });

  } catch (error) {
    logger.error('Error deleting study note:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   PUT /api/planner/preferences
 * @desc    Update study preferences
 * @access  Private
 */
router.put('/preferences',
  authenticate,
  [
    body('dailyStudyHours').optional().isInt({ min: 1, max: 12 }).withMessage('Daily study hours must be between 1 and 12'),
    body('preferredSubjects').optional().isArray().withMessage('Preferred subjects must be an array'),
    body('studyTime').optional().isIn(['morning', 'afternoon', 'evening', 'night']).withMessage('Invalid study time'),
    body('reminders').optional().isBoolean().withMessage('Reminders must be boolean')
  ],
  async (req, res) => {
    try {
      const userId = req.user.id;
      const preferences = req.body;

      // Read planner data
      const plannerPath = path.join(__dirname, '../data/planners.json');
      let plannerData = [];
      
      try {
        plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Planner data not found' });
      }

      const userPlanner = plannerData.find(p => p.userId === userId);
      if (!userPlanner) {
        return res.status(404).json({ error: 'User planner not found' });
      }

      // Update preferences
      userPlanner.preferences = {
        ...userPlanner.preferences,
        ...preferences,
        updatedAt: new Date().toISOString()
      };

      userPlanner.updatedAt = new Date().toISOString();

      // Update planner data
      const plannerIndex = plannerData.findIndex(p => p.userId === userId);
      plannerData[plannerIndex] = userPlanner;
      fs.writeFileSync(plannerPath, JSON.stringify(plannerData, null, 2));

      logger.info(`User ${userId} updated study preferences`);

      res.status(200).json({
      success: true,
        message: 'Study preferences updated successfully',
        preferences: userPlanner.preferences
    });

  } catch (error) {
      logger.error('Error updating study preferences:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   GET /api/planner/stats
 * @desc    Get study statistics
 * @access  Private
 */
router.get('/stats', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { period = 'month' } = req.query; // week, month, year

    // Read planner data
    const plannerPath = path.join(__dirname, '../data/planners.json');
    let plannerData = [];
    
    try {
      plannerData = JSON.parse(fs.readFileSync(plannerPath, 'utf8'));
    } catch (error) {
      return res.status(404).json({ error: 'Planner data not found' });
    }

    const userPlanner = plannerData.find(p => p.userId === userId);
    if (!userPlanner) {
      return res.status(404).json({ error: 'User planner not found' });
    }

    // Calculate date range
    const now = new Date();
    let startDate;
    
    switch (period) {
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        break;
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    }

    // Filter sessions by period
    const sessionsInPeriod = userPlanner.sessions.filter(session => {
      const sessionDate = new Date(session.date);
      return sessionDate >= startDate && sessionDate <= now;
    });

    // Calculate statistics
    const totalSessions = sessionsInPeriod.length;
    const completedSessions = sessionsInPeriod.filter(s => s.completed).length;
    const totalStudyHours = sessionsInPeriod.reduce((total, session) => total + session.duration, 0);
    const completedStudyHours = sessionsInPeriod
      .filter(s => s.completed)
      .reduce((total, session) => total + session.duration, 0);

    // Subject breakdown
    const subjectStats = {};
    sessionsInPeriod.forEach(session => {
      if (!subjectStats[session.subject]) {
        subjectStats[session.subject] = { sessions: 0, hours: 0 };
      }
      subjectStats[session.subject].sessions++;
      subjectStats[session.subject].hours += session.duration;
    });

    // Goal statistics
    const totalGoals = userPlanner.goals.length;
    const completedGoals = userPlanner.goals.filter(g => g.completed).length;

    res.status(200).json({
      success: true,
      stats: {
        period: period,
        totalSessions: totalSessions,
        completedSessions: completedSessions,
        completionRate: totalSessions > 0 ? (completedSessions / totalSessions * 100).toFixed(1) : 0,
        totalStudyHours: totalStudyHours.toFixed(1),
        completedStudyHours: completedStudyHours.toFixed(1),
        subjectStats: subjectStats,
        totalGoals: totalGoals,
        completedGoals: completedGoals,
        goalCompletionRate: totalGoals > 0 ? (completedGoals / totalGoals * 100).toFixed(1) : 0
      }
    });

  } catch (error) {
    logger.error('Error fetching study statistics:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

