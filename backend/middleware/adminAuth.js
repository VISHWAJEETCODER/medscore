const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

/**
 * Admin Authentication Middleware
 */
const adminAuth = (requiredPermissions = []) => {
  return async (req, res, next) => {
    try {
      const token = req.header('Authorization')?.replace('Bearer ', '');
      
      if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Read admins from JSON file
      const adminsPath = path.join(__dirname, '../data/admins.json');
      const adminsData = JSON.parse(fs.readFileSync(adminsPath, 'utf8'));
      
      const admin = adminsData.find(a => a.id === decoded.adminId && a.isActive);
      
      if (!admin) {
        return res.status(401).json({ error: 'Invalid admin token.' });
      }

      // Check permissions
      if (requiredPermissions.length > 0) {
        const hasPermission = requiredPermissions.some(permission => 
          admin.permissions.includes(permission)
        );
        
        if (!hasPermission) {
          return res.status(403).json({ error: 'Insufficient permissions.' });
        }
      }

      req.admin = {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
        permissions: admin.permissions
      };

      next();
    } catch (error) {
      console.error('Admin auth error:', error);
      res.status(401).json({ error: 'Invalid token.' });
    }
  };
};

/**
 * Super Admin Only Middleware
 */
const superAdminOnly = (req, res, next) => {
  if (req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'Super admin access required.' });
  }
  next();
};

/**
 * Admin Hierarchy Check
 */
const adminHierarchy = (req, res, next) => {
  const { role } = req.admin;
  const targetRole = req.body.role || req.params.role;
  
  const hierarchy = {
    'super_admin': 3,
    'content_manager': 2,
    'support_manager': 1
  };
  
  if (hierarchy[role] <= hierarchy[targetRole]) {
    return res.status(403).json({ error: 'Cannot modify admin of equal or higher level.' });
  }
  
  next();
};

/**
 * Log Admin Actions
 */
const logAdminAction = (action, details = {}) => {
  return (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log admin action
      const logEntry = {
        adminId: req.admin.id,
        adminName: req.admin.name,
        action: action,
        details: details,
        timestamp: new Date().toISOString(),
        ip: req.ip,
        userAgent: req.get('User-Agent')
      };
      
      // Write to log file
      const logPath = path.join(__dirname, '../logs/admin-actions.log');
      fs.appendFileSync(logPath, JSON.stringify(logEntry) + '\n');
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

module.exports = {
  adminAuth,
  superAdminOnly,
  adminHierarchy,
  logAdminAction
};