const express = require("express");
const { body, param, query } = require("express-validator");
const User = require("../models/User");
const AdminLog = require("../models/AdminLog");
const {
  adminAuth,
  logAdminAction,
  superAdminOnly,
  adminHierarchy,
} = require("../middleware/adminAuth");
const logger = require("../utils/logger");
const { authenticate } = require("../middleware/auth");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const router = express.Router();

/**
 * @route   POST /api/admin/login
 * @desc    Admin login
 * @access  Public
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Read admins from JSON file (async)
    const adminsPath = path.join(__dirname, "../data/admins.json");
    const adminsData = JSON.parse(
      await fs.promises.readFile(adminsPath, "utf8"),
    );

    const admin = adminsData.find((a) => a.email === email && a.isActive);

    if (!admin) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Validate password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, admin.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        adminId: admin.id,
        email: admin.email,
        role: admin.role,
        permissions: admin.permissions,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

    // Update last login (async)
    admin.lastLogin = new Date().toISOString();
    await fs.promises.writeFile(
      adminsPath,
      JSON.stringify(adminsData, null, 2),
    );

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      admin: {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
        permissions: admin.permissions,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * @route   GET /api/admin/dashboard
 * @desc    Get admin dashboard data
 * @access  Private (Admin only)
 */
router.get(
  "/dashboard",
  adminAuth(["admin1", "admin2", "admin3"]),
  async (req, res) => {
    try {
      const { role } = req.admin;

      // Get user statistics
      const userStats = await User.aggregate([
        {
          $group: {
            _id: "$role",
            count: { $sum: 1 },
            active: {
              $sum: {
                $cond: [{ $eq: ["$isActive", true] }, 1, 0],
              },
            },
            suspended: {
              $sum: {
                $cond: [{ $eq: ["$isSuspended", true] }, 1, 0],
              },
            },
          },
        },
      ]);

      // Get recent users (last 30 days)
      const recentUsers = await User.find({
        createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
      })
        .select("email role profile.name createdAt isActive")
        .sort({ createdAt: -1 })
        .limit(10);

      // Get admin activity summary
      const adminActivity = await AdminLog.getSystemActivity(7);

      // Get recent admin actions
      const recentActions = await AdminLog.find()
        // .populate('adminId', 'email profile.name') // TODO: Replace with JOIN query for MySQL
        .sort({ timestamp: -1 })
        .limit(10)
        .select(
          "adminId adminEmail adminRole action description timestamp status",
        );

      // Get system health
      const systemHealth = {
        totalUsers: await User.countDocuments(),
        activeUsers: await User.countDocuments({ isActive: true }),
        suspendedUsers: await User.countDocuments({ isSuspended: true }),
        totalAdmins: await User.countDocuments({
          role: { $in: ["admin1", "admin2", "admin3"] },
        }),
        recentLogins: await User.countDocuments({
          lastLogin: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        }),
      };

      // Role-based data access
      let dashboardData = {
        userStats,
        systemHealth,
        recentUsers,
        adminActivity,
        recentActions: recentActions.map((action) => ({
          id: action._id,
          admin: action.adminId
            ? action.adminId.profile.name
            : action.adminEmail,
          role: action.adminRole,
          action: action.action,
          description: action.description,
          timestamp: action.timestamp,
          status: action.status,
        })),
      };

      // Grade 1 and 2 admins get additional data
      if (["admin1", "admin2"].includes(role)) {
        dashboardData.revenue = {
          totalTransactions: 0, // Will be implemented in payment phase
          totalRevenue: 0,
          pendingPayouts: 0,
        };
      }

      // Grade 1 admin gets system settings
      if (role === "admin1") {
        dashboardData.systemSettings = {
          maintenanceMode: false,
          registrationEnabled: true,
          emailNotifications: true,
        };
      }

      logger.adminAction(req.admin.id, "dashboard_access", {
        adminRole: role,
        dataAccessed: Object.keys(dashboardData),
      });

      res.json({
        success: true,
        data: dashboardData,
        adminRole: role,
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "dashboard_access",
      });
      res.status(500).json({
        error: "Failed to fetch dashboard data",
      });
    }
  },
);

/**
 * @route   GET /api/admin/users
 * @desc    Get all users with pagination and filtering
 * @access  Private (Admin only)
 */
router.get(
  "/users",
  adminAuth(["admin1", "admin2", "admin3"]),
  logAdminAction("users_list", "Admin viewed users list"),
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 20,
        role,
        status,
        search,
        sortBy = "createdAt",
        sortOrder = "desc",
      } = req.query;

      // Build query
      const query = {};

      if (role) {
        query.role = role;
      }

      if (status === "active") {
        query.isActive = true;
      } else if (status === "suspended") {
        query.isSuspended = true;
      } else if (status === "inactive") {
        query.isActive = false;
      }

      if (search) {
        query.$or = [
          { email: { $regex: search, $options: "i" } },
          { "profile.name": { $regex: search, $options: "i" } },
          { "profile.phone": { $regex: search, $options: "i" } },
        ];
      }

      // Role-based filtering
      const { adminRole } = req.admin;
      if (adminRole === "admin3") {
        // Grade 3 can only see students and mentors
        query.role = { $in: ["student", "mentor"] };
      }

      // Execute query
      const users = await User.find(query)
        .select("-password")
        .sort({ [sortBy]: sortOrder === "desc" ? -1 : 1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await User.countDocuments(query);

      res.json({
        success: true,
        data: {
          users,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit),
          },
        },
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "users_list",
      });
      res.status(500).json({
        error: "Failed to fetch users",
      });
    }
  },
);

/**
 * @route   GET /api/admin/users/:id
 * @desc    Get specific user details
 * @access  Private (Admin only)
 */
router.get(
  "/users/:id",
  adminAuth(["admin1", "admin2", "admin3"]),
  logAdminAction("user_view", "Admin viewed user details"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select("-password");

      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      // Role-based access control
      const { adminRole } = req.admin;
      if (
        adminRole === "admin3" &&
        !["student", "mentor"].includes(user.role)
      ) {
        return res.status(403).json({
          error: "Access denied. You can only view students and mentors.",
        });
      }

      // Get user's recent activity
      const recentActivity = await AdminLog.find({
        $or: [{ adminId: user._id }, { targetId: user._id }],
      })
        .sort({ timestamp: -1 })
        .limit(10)
        .select("action description timestamp status");

      res.json({
        success: true,
        data: {
          user,
          recentActivity,
        },
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "user_view",
        userId: req.params.id,
      });
      res.status(500).json({
        error: "Failed to fetch user details",
      });
    }
  },
);

/**
 * @route   PUT /api/admin/users/:id
 * @desc    Update user details
 * @access  Private (Admin Grade 2+)
 */
router.put(
  "/users/:id",
  adminAuth(["admin1", "admin2"]),
  adminHierarchy,
  [
    body("profile.name").optional().trim().isLength({ min: 2, max: 50 }),
    body("profile.phone").optional().isMobilePhone("en-IN"),
    body("profile.state")
      .optional()
      .isIn([
        "Andhra Pradesh",
        "Arunachal Pradesh",
        "Assam",
        "Bihar",
        "Chhattisgarh",
        "Goa",
        "Gujarat",
        "Haryana",
        "Himachal Pradesh",
        "Jharkhand",
        "Karnataka",
        "Kerala",
        "Madhya Pradesh",
        "Maharashtra",
        "Manipur",
        "Meghalaya",
        "Mizoram",
        "Nagaland",
        "Odisha",
        "Punjab",
        "Rajasthan",
        "Sikkim",
        "Tamil Nadu",
        "Telangana",
        "Tripura",
        "Uttar Pradesh",
        "Uttarakhand",
        "West Bengal",
        "Delhi",
        "Puducherry",
      ]),
    body("isActive").optional().isBoolean(),
    body("isSuspended").optional().isBoolean(),
  ],
  logAdminAction("user_update", "Admin updated user details"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      // Role-based access control
      const { adminRole } = req.admin;
      if (
        adminRole === "admin2" &&
        ["admin1", "admin2", "admin3"].includes(user.role)
      ) {
        return res.status(403).json({
          error: "Access denied. You cannot modify admin accounts.",
        });
      }

      // Update user
      const updateData = req.body;
      Object.keys(updateData).forEach((key) => {
        if (key === "profile" && updateData[key]) {
          Object.assign(user.profile, updateData[key]);
        } else if (key !== "profile") {
          user[key] = updateData[key];
        }
      });

      await user.save();

      logger.adminAction(req.admin.id, "user_updated", {
        userId: user._id,
        userEmail: user.email,
        changes: updateData,
      });

      res.json({
        success: true,
        message: "User updated successfully",
        data: {
          user: {
            id: user._id,
            email: user.email,
            role: user.role,
            profile: user.profile,
            isActive: user.isActive,
            isSuspended: user.isSuspended,
          },
        },
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "user_update",
        userId: req.params.id,
      });
      res.status(500).json({
        error: "Failed to update user",
      });
    }
  },
);

/**
 * @route   DELETE /api/admin/users/:id
 * @desc    Delete user (Grade 2+ only)
 * @access  Private (Admin Grade 2+)
 */
router.delete(
  "/users/:id",
  adminAuth(["admin1", "admin2"]),
  adminHierarchy,
  logAdminAction("user_delete", "Admin deleted user account"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      // Prevent deleting admin accounts
      if (["admin1", "admin2", "admin3"].includes(user.role)) {
        return res.status(403).json({
          error: "Cannot delete admin accounts",
        });
      }

      // Role-based access control
      const { adminRole } = req.admin;
      if (adminRole === "admin2" && user.role === "mentor") {
        return res.status(403).json({
          error: "Access denied. You cannot delete mentor accounts.",
        });
      }

      await User.findByIdAndDelete(req.params.id);

      logger.adminAction(req.admin.id, "user_deleted", {
        deletedUserId: user._id,
        deletedUserEmail: user.email,
        deletedUserRole: user.role,
      });

      res.json({
        success: true,
        message: "User deleted successfully",
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "user_delete",
        userId: req.params.id,
      });
      res.status(500).json({
        error: "Failed to delete user",
      });
    }
  },
);

/**
 * @route   GET /api/admin/logs
 * @desc    Get admin activity logs
 * @access  Private (Admin only)
 */
router.get(
  "/logs",
  adminAuth(["admin1", "admin2", "admin3"]),
  logAdminAction("logs_view", "Admin viewed activity logs"),
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        action,
        adminId,
        startDate,
        endDate,
        status,
      } = req.query;

      // Build query
      const query = {};

      if (action) {
        query.action = action;
      }

      if (adminId) {
        query.adminId = adminId;
      }

      if (status) {
        query.status = status;
      }

      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) query.timestamp.$gte = new Date(startDate);
        if (endDate) query.timestamp.$lte = new Date(endDate);
      }

      // Role-based filtering
      const { adminRole, id } = req.admin;
      if (adminRole === "admin3") {
        // Grade 3 can only see their own logs
        query.adminId = id;
      }

      // Execute query
      const logs = await AdminLog.find(query)
        // .populate('adminId', 'email profile.name') // TODO: Replace with JOIN query for MySQL
        .sort({ timestamp: -1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await AdminLog.countDocuments(query);

      res.json({
        success: true,
        data: {
          logs,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit),
          },
        },
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "logs_view",
      });
      res.status(500).json({
        error: "Failed to fetch logs",
      });
    }
  },
);

/**
 * @route   GET /api/admin/stats
 * @desc    Get system statistics
 * @access  Private (Admin only)
 */
router.get(
  "/stats",
  adminAuth(["admin1", "admin2", "admin3"]),
  logAdminAction("stats_view", "Admin viewed system statistics"),
  async (req, res) => {
    try {
      const { period = "30" } = req.query;
      const days = parseInt(period);

      // User statistics
      const userStats = await User.aggregate([
        {
          $group: {
            _id: "$role",
            total: { $sum: 1 },
            active: {
              $sum: {
                $cond: [{ $eq: ["$isActive", true] }, 1, 0],
              },
            },
            suspended: {
              $sum: {
                $cond: [{ $eq: ["$isSuspended", true] }, 1, 0],
              },
            },
            recent: {
              $sum: {
                $cond: [
                  {
                    $gte: [
                      "$createdAt",
                      new Date(Date.now() - days * 24 * 60 * 60 * 1000),
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
          },
        },
      ]);

      // Admin activity statistics
      const adminStats = await AdminLog.aggregate([
        {
          $match: {
            timestamp: {
              $gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000),
            },
          },
        },
        {
          $group: {
            _id: "$adminRole",
            actions: { $sum: 1 },
            success: {
              $sum: {
                $cond: [{ $eq: ["$status", "success"] }, 1, 0],
              },
            },
            failed: {
              $sum: {
                $cond: [{ $eq: ["$status", "failed"] }, 1, 0],
              },
            },
          },
        },
      ]);

      // Daily activity for chart
      const dailyActivity = await AdminLog.aggregate([
        {
          $match: {
            timestamp: {
              $gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000),
            },
          },
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$timestamp",
              },
            },
            count: { $sum: 1 },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ]);

      res.json({
        success: true,
        data: {
          userStats,
          adminStats,
          dailyActivity,
          period: days,
        },
      });
    } catch (error) {
      logger.errorWithContext(error, {
        adminId: req.admin.id,
        action: "stats_view",
      });
      res.status(500).json({
        error: "Failed to fetch statistics",
      });
    }
  },
);

module.exports = router;
