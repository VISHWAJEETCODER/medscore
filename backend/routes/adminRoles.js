const express = require('express');
const { body, param, query } = require('express-validator');
const { adminAuth, logAdminAction, superAdminOnly } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const fs = require('fs');
const path = require('path');

const router = express.Router();

/**
 * @route   GET /api/admin/roles
 * @desc    Get all admin roles and permissions
 * @access  Super Admin only
 */
router.get('/roles', adminAuth(['superadmin']), async (req, res) => {
  try {
    const roles = [
      {
        id: 'superadmin',
        name: 'Super Admin',
        description: 'Full system access with all permissions',
        permissions: [
          'manage_users',
          'manage_mentors',
          'manage_colleges',
          'manage_materials',
          'view_payments',
          'manage_admins',
          'system_settings',
          'view_analytics'
        ],
        level: 1
      },
      {
        id: 'admin1',
        name: 'Content Manager',
        description: 'Manages content, colleges, and study materials',
        permissions: [
          'manage_colleges',
          'manage_materials',
          'manage_mentors',
          'view_payments'
        ],
        level: 2
      },
      {
        id: 'admin2',
        name: 'Support Manager',
        description: 'Handles user support and mentor applications',
        permissions: [
          'manage_users',
          'manage_mentors',
          'view_payments'
        ],
        level: 3
      }
    ];

    res.status(200).json({
      success: true,
      roles
    });

  } catch (error) {
    logger.error('Error fetching admin roles:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   GET /api/admin/roles/:roleId
 * @desc    Get specific admin role details
 * @access  Super Admin only
 */
router.get('/roles/:roleId', adminAuth(['superadmin']), async (req, res) => {
  try {
    const { roleId } = req.params;
    
    const roles = {
      'superadmin': {
        id: 'superadmin',
          name: 'Super Admin',
        description: 'Full system access with all permissions',
          permissions: [
          'manage_users',
          'manage_mentors',
          'manage_colleges',
          'manage_materials',
          'view_payments',
          'manage_admins',
          'system_settings',
          'view_analytics'
        ],
        level: 1
      },
      'admin1': {
        id: 'admin1',
        name: 'Content Manager',
        description: 'Manages content, colleges, and study materials',
          permissions: [
          'manage_colleges',
          'manage_materials',
          'manage_mentors',
          'view_payments'
        ],
        level: 2
      },
      'admin2': {
        id: 'admin2',
        name: 'Support Manager',
        description: 'Handles user support and mentor applications',
          permissions: [
          'manage_users',
          'manage_mentors',
          'view_payments'
        ],
        level: 3
      }
    };

    const role = roles[roleId];
    if (!role) {
      return res.status(404).json({ error: 'Role not found' });
    }

    res.status(200).json({
        success: true,
      role
      });

    } catch (error) {
    logger.error('Error fetching admin role:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/admin/roles
 * @desc    Create new admin role
 * @access  Super Admin only
 */
router.post('/roles', 
  adminAuth(['superadmin']),
  [
    body('name').notEmpty().withMessage('Role name is required'),
    body('description').notEmpty().withMessage('Role description is required'),
    body('permissions').isArray().withMessage('Permissions must be an array'),
    body('level').isInt({ min: 1, max: 10 }).withMessage('Level must be between 1 and 10')
  ],
  logAdminAction('create_role'),
  async (req, res) => {
    try {
      const { name, description, permissions, level } = req.body;

      // Read current admins
      const adminsPath = path.join(__dirname, '../data/admins.json');
      const adminsData = JSON.parse(fs.readFileSync(adminsPath, 'utf8'));

      // Generate new role ID
      const roleId = `admin${adminsData.length + 1}`;

      // Create new role
      const newRole = {
        id: roleId,
        name,
        description,
        permissions,
        level,
        createdAt: new Date().toISOString(),
        createdBy: req.admin.id
      };

      // Add to roles data (in a real app, this would be in a separate roles.json file)
      const rolesPath = path.join(__dirname, '../data/roles.json');
      let rolesData = [];
      
      try {
        rolesData = JSON.parse(fs.readFileSync(rolesPath, 'utf8'));
      } catch (error) {
        // File doesn't exist, create new array
      }

      rolesData.push(newRole);
      fs.writeFileSync(rolesPath, JSON.stringify(rolesData, null, 2));

      logger.info(`Admin ${req.admin.email} created new role: ${name}`);

      res.status(201).json({
        success: true,
        message: 'Role created successfully',
        role: newRole
      });

    } catch (error) {
      logger.error('Error creating admin role:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   PUT /api/admin/roles/:roleId
 * @desc    Update admin role
 * @access  Super Admin only
 */
router.put('/roles/:roleId',
  adminAuth(['superadmin']),
  [
    body('name').optional().notEmpty().withMessage('Role name cannot be empty'),
    body('description').optional().notEmpty().withMessage('Role description cannot be empty'),
    body('permissions').optional().isArray().withMessage('Permissions must be an array'),
    body('level').optional().isInt({ min: 1, max: 10 }).withMessage('Level must be between 1 and 10')
  ],
  logAdminAction('update_role'),
  async (req, res) => {
    try {
      const { roleId } = req.params;
      const updates = req.body;

      // Read roles data
      const rolesPath = path.join(__dirname, '../data/roles.json');
      let rolesData = [];
      
      try {
        rolesData = JSON.parse(fs.readFileSync(rolesPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Roles data not found' });
      }

      const roleIndex = rolesData.findIndex(role => role.id === roleId);
      if (roleIndex === -1) {
        return res.status(404).json({ error: 'Role not found' });
      }

      // Update role
      rolesData[roleIndex] = {
        ...rolesData[roleIndex],
        ...updates,
        updatedAt: new Date().toISOString(),
        updatedBy: req.admin.id
      };

      fs.writeFileSync(rolesPath, JSON.stringify(rolesData, null, 2));

      logger.info(`Admin ${req.admin.email} updated role: ${roleId}`);

      res.status(200).json({
        success: true,
        message: 'Role updated successfully',
        role: rolesData[roleIndex]
      });

    } catch (error) {
      logger.error('Error updating admin role:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   DELETE /api/admin/roles/:roleId
 * @desc    Delete admin role
 * @access  Super Admin only
 */
router.delete('/roles/:roleId',
  adminAuth(['superadmin']),
  logAdminAction('delete_role'),
  async (req, res) => {
    try {
      const { roleId } = req.params;

      // Check if role is being used by any admin
      const adminsPath = path.join(__dirname, '../data/admins.json');
      const adminsData = JSON.parse(fs.readFileSync(adminsPath, 'utf8'));
      
      const roleInUse = adminsData.some(admin => admin.role === roleId);
      if (roleInUse) {
        return res.status(400).json({ 
          error: 'Cannot delete role that is currently assigned to admins' 
        });
      }

      // Read roles data
      const rolesPath = path.join(__dirname, '../data/roles.json');
      let rolesData = [];
      
      try {
        rolesData = JSON.parse(fs.readFileSync(rolesPath, 'utf8'));
      } catch (error) {
        return res.status(404).json({ error: 'Roles data not found' });
      }

      const roleIndex = rolesData.findIndex(role => role.id === roleId);
      if (roleIndex === -1) {
        return res.status(404).json({ error: 'Role not found' });
      }

      // Remove role
      const deletedRole = rolesData.splice(roleIndex, 1)[0];
      fs.writeFileSync(rolesPath, JSON.stringify(rolesData, null, 2));

      logger.info(`Admin ${req.admin.email} deleted role: ${roleId}`);

      res.status(200).json({
        success: true,
        message: 'Role deleted successfully',
        role: deletedRole
      });

    } catch (error) {
      logger.error('Error deleting admin role:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * @route   GET /api/admin/permissions
 * @desc    Get all available permissions
 * @access  Admin only
 */
router.get('/permissions', adminAuth(), async (req, res) => {
  try {
    const permissions = [
      {
        id: 'manage_users',
        name: 'Manage Users',
        description: 'Create, update, delete, and view user accounts',
        category: 'User Management'
      },
      {
        id: 'manage_mentors',
        name: 'Manage Mentors',
        description: 'Approve, update, and manage mentor accounts',
        category: 'Mentor Management'
      },
      {
        id: 'manage_colleges',
        name: 'Manage Colleges',
        description: 'Add, update, and manage college information',
        category: 'Content Management'
      },
      {
        id: 'manage_materials',
        name: 'Manage Study Materials',
        description: 'Upload, update, and manage study materials',
        category: 'Content Management'
      },
      {
        id: 'view_payments',
        name: 'View Payments',
        description: 'View payment history and transaction details',
        category: 'Financial'
      },
      {
        id: 'manage_admins',
        name: 'Manage Admins',
        description: 'Create, update, and manage admin accounts',
        category: 'Admin Management'
      },
      {
        id: 'system_settings',
        name: 'System Settings',
        description: 'Configure system-wide settings and preferences',
        category: 'System'
      },
      {
        id: 'view_analytics',
        name: 'View Analytics',
        description: 'Access system analytics and reports',
        category: 'Analytics'
      }
    ];

    res.status(200).json({
      success: true,
      permissions
    });

  } catch (error) {
    logger.error('Error fetching permissions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @route   POST /api/admin/assign-role
 * @desc    Assign role to admin
 * @access  Super Admin only
 */
router.post('/assign-role',
  adminAuth(['superadmin']),
  [
    body('adminId').notEmpty().withMessage('Admin ID is required'),
    body('roleId').notEmpty().withMessage('Role ID is required')
  ],
  logAdminAction('assign_role'),
  async (req, res) => {
    try {
      const { adminId, roleId } = req.body;

      // Read admins data
      const adminsPath = path.join(__dirname, '../data/admins.json');
      const adminsData = JSON.parse(fs.readFileSync(adminsPath, 'utf8'));

      const adminIndex = adminsData.findIndex(admin => admin.id === adminId);
      if (adminIndex === -1) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      // Update admin role
      adminsData[adminIndex].role = roleId;
      adminsData[adminIndex].updatedAt = new Date().toISOString();
      adminsData[adminIndex].updatedBy = req.admin.id;

      fs.writeFileSync(adminsPath, JSON.stringify(adminsData, null, 2));

      logger.info(`Admin ${req.admin.email} assigned role ${roleId} to admin ${adminId}`);

      res.status(200).json({
        success: true,
        message: 'Role assigned successfully',
        admin: adminsData[adminIndex]
      });

    } catch (error) {
      logger.error('Error assigning role:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

module.exports = router;

