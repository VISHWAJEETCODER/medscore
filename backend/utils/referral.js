const User = require("../models/User");
const { pool } = require("../config/mysql-db");

/**
 * Validate referral code
 * @param {string} referralCode - The referral code to validate
 * @returns {Object} - Validation result
 */
async function validateReferralCode(referralCode) {
  try {
    if (!referralCode || typeof referralCode !== "string") {
      return { success: false, error: "Invalid referral code format" };
    }

    // Find user with this referral code
    const referrer = await User.findOne({
      referralCode: referralCode.toUpperCase(),
    });

    if (!referrer) {
      return { success: false, error: "Invalid referral code" };
    }

    if (!referrer.isActive) {
      return { success: false, error: "Referral code is no longer active" };
    }

    return {
      success: true,
      referrer: {
        id: referrer.id,
        name: referrer.profile?.name || referrer.email,
        referralCode: referrer.referralCode,
      },
    };
  } catch (error) {
    console.error("Referral validation error:", error);
    return { success: false, error: "Failed to validate referral code" };
  }
}

/**
 * Process referral when new user signs up
 * @param {string} referralCode - The referral code used
 * @param {string} newUserId - The new user's ID
 * @returns {Object} - Processing result
 */
async function processReferral(referralCode, newUserId) {
  try {
    if (!referralCode || !newUserId) {
      return { success: false, error: "Missing referral code or user ID" };
    }

    // Validate referral code
    const validation = await validateReferralCode(referralCode);
    if (!validation.success) {
      return validation;
    }

    const referrer = await User.findById(validation.referrer.id);
    if (!referrer) {
      return { success: false, error: "Referrer not found" };
    }

    // Update referrer's referral count (Bug #51 fix - also update in database directly)
    referrer.referralCount = (referrer.referralCount || 0) + 1;
    await referrer.save();

    // Also update total_referrals in database for consistency
    try {
      await pool.execute(
        "UPDATE users SET total_referrals = total_referrals + 1 WHERE id = ?",
        [referrer.id],
      );
    } catch (dbError) {
      console.warn(
        "⚠️ Could not update total_referrals in database:",
        dbError.message,
      );
    }

    // Add referral reward to referrer
    const rewardAmount = 100; // 100 credits or points
    await referrer.addReferralReward(
      "bonus_credits",
      rewardAmount,
      `Referral bonus for ${newUserId}`,
    );

    // Update new user's referredBy field
    const newUser = await User.findById(newUserId);
    if (newUser) {
      newUser.referredBy = referrer.id;
      await newUser.save();
    }

    return {
      success: true,
      message: "Referral processed successfully",
      reward: {
        type: "bonus_credits",
        amount: rewardAmount,
        description: "Welcome referral bonus",
      },
    };
  } catch (error) {
    console.error("Referral processing error:", error);
    return { success: false, error: "Failed to process referral" };
  }
}

/**
 * Get referral statistics for a user
 * @param {string} userId - User ID
 * @returns {Object} - Referral statistics
 */
async function getReferralStats(userId) {
  try {
    const user = await User.findById(userId);
    if (!user) {
      return { success: false, error: "User not found" };
    }

    // Get all users referred by this user
    const referredUsers = await User.find({ referredBy: userId });

    // Get available rewards
    const availableRewards = user.getAvailableRewards();

    // Calculate total rewards earned
    const totalRewards = (user.referralRewards || []).reduce(
      (total, reward) => {
        return total + reward.amount;
      },
      0,
    );

    return {
      success: true,
      stats: {
        referralCode: user.referralCode,
        referralCount: user.referralCount || 0,
        referredUsers: referredUsers.length,
        totalRewards,
        availableRewards: availableRewards.length,
        rewards: user.referralRewards || [],
      },
    };
  } catch (error) {
    console.error("Referral stats error:", error);
    return { success: false, error: "Failed to get referral statistics" };
  }
}

/**
 * Use a referral reward
 * @param {string} userId - User ID
 * @param {string} rewardId - Reward ID
 * @returns {Object} - Result
 */
async function useReferralReward(userId, rewardId) {
  try {
    const user = await User.findById(userId);
    if (!user) {
      return { success: false, error: "User not found" };
    }

    const reward = (user.referralRewards || []).find((r) => r.id === rewardId);
    if (!reward) {
      return { success: false, error: "Reward not found" };
    }

    if (reward.isUsed) {
      return { success: false, error: "Reward already used" };
    }

    // Mark reward as used
    reward.isUsed = true;
    reward.usedAt = new Date().toISOString();
    await user.save();

    return {
      success: true,
      message: "Reward used successfully",
      reward: {
        type: reward.rewardType,
        amount: reward.amount,
        description: reward.description,
      },
    };
  } catch (error) {
    console.error("Use referral reward error:", error);
    return { success: false, error: "Failed to use reward" };
  }
}

module.exports = {
  validateReferralCode,
  processReferral,
  getReferralStats,
  useReferralReward,
};
