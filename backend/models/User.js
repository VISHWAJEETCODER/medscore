const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const { pool } = require("../config/mysql-db");

// User Schema Definition (for validation)
const userSchema = {
  email: { required: true, type: "string", unique: true },
  password: { required: true, type: "string", minlength: 8 },
  role: {
    type: "string",
    enum: ["student", "mentor", "admin3", "admin2", "admin1"],
    default: "student",
  },
  profile: {
    name: { type: "string" },
    phone: { type: "string" },
    avatar: { type: "string" },
    defaultAvatar: { type: "string", default: null },
    gender: {
      type: "string",
      enum: ["male", "female", "other"],
      default: null,
    },
    state: { type: "string" },
    college: { type: "string" },
    year: { type: "number" },
  },
  failedLoginAttempts: { type: "number", default: 0 },
  accountLockedUntil: { type: "date", default: null },
  lastLogin: { type: "date" },
  loginIPs: { type: "array", default: [] },
  isActive: { type: "boolean", default: true },
  isSuspended: { type: "boolean", default: false },
  suspendedUntil: { type: "date", default: null },
  suspendedBy: { type: "string", default: null },
  referralCode: { type: "string", unique: true, default: null },
  referredBy: { type: "string", default: null },
  referralCount: { type: "number", default: 0 },
  referralRewards: { type: "array", default: [] },
  createdAt: { type: "date", default: Date.now },
  updatedAt: { type: "date", default: Date.now },
};

// User Model Class
class User {
  constructor(data) {
    Object.assign(this, data);
  }

  // Hash password
  static async hashPassword(password) {
    const salt = await bcrypt.genSalt(12);
    return await bcrypt.hash(password, salt);
  }

  // Compare password
  async comparePassword(candidatePassword) {
    try {
      // Debug: Check if password exists
      if (!this.password) {
        console.error("❌ Password field is missing in user object");
        console.error("User object keys:", Object.keys(this));
        return false;
      }
      
      if (!candidatePassword) {
        console.error("❌ Candidate password is missing");
        return false;
      }
      
      const isMatch = await bcrypt.compare(candidatePassword, this.password);
      console.log("🔐 Password comparison result:", isMatch);
      return isMatch;
    } catch (error) {
      console.error("❌ Password comparison error:", error);
      throw new Error("Password comparison failed: " + error.message);
    }
  }

  // Check if account is locked
  isAccountLocked() {
    return (
      this.accountLockedUntil && new Date(this.accountLockedUntil) > new Date()
    );
  }

  // Check if account is suspended
  isAccountSuspended() {
    return (
      this.isSuspended &&
      (!this.suspendedUntil || new Date(this.suspendedUntil) > new Date())
    );
  }

  // Generate unique referral code (Bug #15, #54 fix - add max retry limit)
  static async generateReferralCode() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let code;
    let isUnique = false;
    let attempts = 0;
    const maxAttempts = 100; // Prevent infinite loop

    while (!isUnique && attempts < maxAttempts) {
      code = "";
      for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
      }

      // Check if code already exists
      const existingUser = await User.findOne({ referralCode: code });
      isUnique = !existingUser;
      attempts++;
    }

    if (!isUnique) {
      throw new Error(
        "Failed to generate unique referral code after maximum attempts",
      );
    }

    return code;
  }

  // Add referral reward
  addReferralReward(rewardType, amount, description) {
    if (!this.referralRewards) this.referralRewards = [];
    this.referralRewards.push({
      rewardType,
      amount,
      description,
      earnedAt: new Date().toISOString(),
    });
    return this.save();
  }

  // Get available rewards
  getAvailableRewards() {
    return (this.referralRewards || []).filter((reward) => !reward.isUsed);
  }

  // Increment failed login attempts
  async incrementLoginAttempts() {
    // Reset if lock expired
    if (
      this.accountLockedUntil &&
      new Date(this.accountLockedUntil) < new Date()
    ) {
      this.failedLoginAttempts = 1;
      this.accountLockedUntil = null;
      return this.save();
    }

    this.failedLoginAttempts = (this.failedLoginAttempts || 0) + 1;

    // Lock account after 5 failed attempts (30 minutes) - Bug #14 fix: This method is now actively used in auth.js
    if (this.failedLoginAttempts >= 5) {
      this.accountLockedUntil = new Date(
        Date.now() + 30 * 60 * 1000,
      ).toISOString();
    }

    return this.save();
  }

  // Reset login attempts on successful login
  resetLoginAttempts() {
    this.failedLoginAttempts = 0;
    this.lastLogin = new Date().toISOString();
    this.accountLockedUntil = null;

    // Keep last 10 IPs
    if (!this.loginIPs) this.loginIPs = [];
    // Add current IP logic here if needed

    return this.save();
  }

  // Update last login - Added missing method
  async updateLastLogin() {
    this.lastLogin = new Date().toISOString();
    return this.save();
  }

  // Save user to storage
  async save() {
    try {
      if (this.id) {
        // Update existing user
        const sql = `
          UPDATE users SET
            name = ?, email = ?, password = ?, phone = ?, state = ?, college = ?, year = ?,
            role = ?, profile_photo = ?,
            referral_code = ?, referred_by = ?, total_referrals = ?,
            failed_login_attempts = ?, account_locked_until = ?,
            last_login = ?, is_active = ?, is_suspended = ?,
            suspended_until = ?, google_id = ?, is_verified = ?, updated_at = NOW()
          WHERE id = ?
        `;

        const values = [
          this.name || this.profile?.name || "",
          this.email,
          this.password || null,
          this.phone || this.profile?.phone || "",
          this.state || null,
          this.college || null,
          this.year || null,
          this.role || "student",
          this.profile?.avatar || "",
          this.referral_code || this.referralCode || null,
          this.referred_by || this.referredBy || null,
          this.total_referrals || this.referralCount || 0,
          this.failedLoginAttempts || 0,
          this.accountLockedUntil || null,
          this.lastLogin || null,
          this.isActive !== undefined ? this.isActive : true,
          this.isSuspended || false,
          this.suspendedUntil || null,
          this.google_id || this.googleId || null,
          this.is_verified !== undefined
            ? this.is_verified
            : this.isVerified !== undefined
              ? this.isVerified
              : false,
          this.id,
        ];

        await pool.execute(sql, values);
        return this;
      } else {
        // Create new user
        return await User.create(this);
      }
    } catch (error) {
      console.error("User.save error:", error);
      throw error;
    }
  }

  // Static methods for database operations
  static async findOne(query) {
    let connection;
    try {
      // Bug #59 fix - Get connection from pool
      connection = await pool.getConnection();

      let sql = "SELECT * FROM users WHERE ";
      const conditions = [];
      const values = [];

      if (query.email) {
        // Use LOWER() for case-insensitive email comparison
        conditions.push("LOWER(email) = LOWER(?)");
        values.push(query.email);
      }
      if (query.id) {
        conditions.push("id = ?");
        values.push(query.id);
      }
      if (query.referralCode) {
        conditions.push("referral_code = ?");
        values.push(query.referralCode);
      }
      if (query.googleId) {
        conditions.push("google_id = ?");
        values.push(query.googleId);
      }

      if (conditions.length === 0) {
        sql = "SELECT * FROM users LIMIT 1";
      } else {
        sql += conditions.join(" AND ");
      }

      const [rows] = await connection.execute(sql, values);
      
      if (rows.length > 0) {
        const userData = rows[0];
        // Debug: Log user data (without password for security)
        console.log("📊 User found in DB:", {
          id: userData.id,
          email: userData.email,
          hasPassword: !!userData.password,
          passwordLength: userData.password ? userData.password.length : 0,
          role: userData.role
        });
        return new User(userData);
      }
      
      return null;
    } catch (error) {
      console.error("User.findOne error:", error);
      // Bug #49 fix - throw error for better error handling
      throw error;
    } finally {
      // Bug #59 fix - Always release connection
      if (connection) connection.release();
    }
  }

  static async find(query = {}) {
    let connection;
    try {
      // Bug #59 fix - Get connection from pool
      connection = await pool.getConnection();

      let sql = "SELECT * FROM users";
      const conditions = [];
      const values = [];

      if (query.role) {
        conditions.push("role = ?");
        values.push(query.role);
      }
      if (query.isActive !== undefined) {
        conditions.push("is_active = ?");
        values.push(query.isActive);
      }

      if (conditions.length > 0) {
        sql += " WHERE " + conditions.join(" AND ");
      }

      const [rows] = await connection.execute(sql, values);
      return rows.map((user) => new User(user));
    } catch (error) {
      console.error("User.find error:", error);
      return [];
    } finally {
      // Bug #59 fix - Always release connection
      if (connection) connection.release();
    }
  }

  static async findById(id) {
    let connection;
    try {
      // Bug #59 fix - Get connection from pool
      connection = await pool.getConnection();

      const [rows] = await connection.execute(
        "SELECT * FROM users WHERE id = ?",
        [id],
      );
      
      if (rows.length > 0) {
        const userData = rows[0];
        // Debug: Log user data (without password for security)
        console.log("📊 User found by ID in DB:", {
          id: userData.id,
          email: userData.email,
          hasPassword: !!userData.password,
          passwordLength: userData.password ? userData.password.length : 0,
          role: userData.role
        });
        return new User(userData);
      }
      
      return null;
    } catch (error) {
      console.error("User.findById error:", error);
      // Bug #49 fix - throw error instead of returning null
      // This allows callers to distinguish between "user not found" and "database error"
      throw error;
    } finally {
      // Bug #59 fix - Always release connection
      if (connection) connection.release();
    }
  }

  static async create(data) {
    try {
      // Hash password before saving
      if (data.password) {
        data.password = await User.hashPassword(data.password);
      }

      // Generate referral code if not exists and not explicitly set to null
      if (!data.referral_code && data.referral_code !== null) {
        data.referral_code = await User.generateReferralCode();
      }

      const sql = `
        INSERT INTO users (
          name, email, password, phone, state, college, year,
          role, profile_photo,
          referral_code, referred_by, total_referrals,
          failed_login_attempts, account_locked_until,
          last_login, is_active, is_suspended,
          suspended_until, google_id, is_verified, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `;

      const values = [
        data.name || data.profile?.name || "",
        data.email,
        data.password || null,
        data.phone || data.profile?.phone || "",
        data.state || null,
        data.college || null,
        data.year || null,
        data.role || "student",
        data.profile?.avatar || "",
        data.referral_code || data.referralCode || null,
        data.referred_by || data.referredBy || null,
        data.total_referrals || data.referralCount || 0,
        data.failedLoginAttempts || 0,
        data.accountLockedUntil || null,
        data.lastLogin || null,
        data.isActive !== undefined ? data.isActive : true,
        data.isSuspended || false,
        data.suspendedUntil || null,
        data.google_id || data.googleId || null,
        data.is_verified !== undefined
          ? data.is_verified
          : data.isVerified !== undefined
            ? data.isVerified
            : false,
      ];

      const [result] = await pool.execute(sql, values);
      return await User.findById(result.insertId);
    } catch (error) {
      console.error("User.create error:", error);
      throw error;
    }
  }

  static async updateOne(query, update) {
    let connection;
    try {
      // Bug #59 fix - Get connection from pool
      connection = await pool.getConnection();

      let sql = "UPDATE users SET ";
      const setClause = [];
      const values = [];

      // Build SET clause
      Object.keys(update).forEach((key) => {
        if (key === "updatedAt") return; // Skip updatedAt, we'll set it manually
        setClause.push(`${key} = ?`);
        // Ensure undefined values are converted to null for MySQL
        values.push(update[key] !== undefined ? update[key] : null);
      });

      setClause.push("updated_at = NOW()");
      sql += setClause.join(", ") + " WHERE ";

      // Build WHERE clause
      const conditions = [];
      if (query.email) {
        conditions.push("email = ?");
        values.push(query.email);
      }
      if (query.id) {
        conditions.push("id = ?");
        values.push(query.id);
      }

      if (conditions.length === 0) {
        throw new Error("No WHERE condition provided for update");
      }

      sql += conditions.join(" AND ");

      const [result] = await connection.execute(sql, values);
      return { modifiedCount: result.affectedRows };
    } catch (error) {
      console.error("User.updateOne error:", error);
      return { modifiedCount: 0 };
    } finally {
      // Bug #59 fix - Always release connection
      if (connection) connection.release();
    }
  }

  static async deleteOne(query) {
    let connection;
    try {
      // Bug #59 fix - Get connection from pool
      connection = await pool.getConnection();

      let sql = "DELETE FROM users WHERE ";
      const conditions = [];
      const values = [];

      if (query.email) {
        conditions.push("email = ?");
        values.push(query.email);
      }
      if (query.id) {
        conditions.push("id = ?");
        values.push(query.id);
      }

      if (conditions.length === 0) {
        throw new Error("No WHERE condition provided for delete");
      }

      sql += conditions.join(" AND ");

      const [result] = await connection.execute(sql, values);
      return { deletedCount: result.affectedRows };
    } catch (error) {
      console.error("User.deleteOne error:", error);
      return { deletedCount: 0 };
    } finally {
      // Bug #59 fix - Always release connection
      if (connection) connection.release();
    }
  }
}

module.exports = User;