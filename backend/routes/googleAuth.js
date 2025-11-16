const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const User = require('../models/User');

const router = express.Router();

// Initialize Google OAuth client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/**
 * @route   POST /api/auth/google
 * @desc    Google OAuth authentication
 * @access  Public
 */
router.post('/google', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Google token is required' });
    }

    // Verify Google token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Check if user exists
    let user = await User.findOne({ googleId });

    if (!user) {
      // Check if user exists with this email
      user = await User.findOne({ email });
      
      if (!user) {
        // Create new user
        user = new User({
          name: name,
          email: email,
          profile: {
            avatar: picture
          },
          googleId: googleId,
          role: 'student',
          isVerified: true, // Google users are pre-verified
          isActive: true
        });
        
        await user.save();
        
        logger.info(`New user registered via Google: ${email}`);
      } else {
        // Link Google account to existing user
        user.googleId = googleId;
        user.profile = user.profile || {};
        user.profile.avatar = picture;
        await user.save();
        
        logger.info(`Existing user linked Google account: ${email}`);
      }
    } else {
      // Update existing user
      user.lastLogin = new Date().toISOString();
      user.profile = user.profile || {};
      user.profile.avatar = picture; // Update profile picture
      await user.save();
      
      logger.info(`User logged in via Google: ${email}`);
    }

    // Generate JWT token
    const jwtToken = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '30d' }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRE || '90d' }
    );

    res.status(200).json({
      success: true,
      message: 'Google authentication successful',
      token: jwtToken,
      refreshToken: refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        photo: user.profile?.avatar,
        role: user.role,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    logger.error('Google authentication error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

/**
 * @route   POST /api/auth/google/verify
 * @desc    Verify Google token
 * @access  Public
 */
router.post('/google/verify', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Google token is required' });
    }

    // Verify Google token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Check if user exists
    let user = await User.findOne({ googleId });
    
    if (!user) {
      // Check if user exists with this email
      user = await User.findOne({ email });
    }

    res.status(200).json({
      success: true,
      message: 'Google token is valid',
      user: {
        googleId: googleId,
        email: email,
        name: name,
        picture: picture,
        emailVerified: payload.email_verified,
        exists: !!user
      }
    });

  } catch (error) {
    logger.error('Google token verification error:', error);
    res.status(400).json({ error: 'Invalid Google token' });
  }
});

/**
 * @route   GET /api/auth/google/callback
 * @desc    Google OAuth callback (for web flow)
 * @access  Public
 */
router.get('/google/callback', async (req, res) => {
  try {
    // This route is handled by the passport strategy in config/googleAuth.js
    // This is a fallback implementation
    res.redirect(`${process.env.FRONTEND_URL || 'https://www.medscore.xyz'}/login?error=oauth_failed`);
  } catch (error) {
    logger.error('Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL || 'https://www.medscore.xyz'}/login?error=oauth_failed`);
  }
});

/**
 * @route   POST /api/auth/google/disconnect
 * @desc    Disconnect Google account
 * @access  Private
 */
router.post('/google/disconnect', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove Google connection
    user.googleId = null;
    await user.save();

    logger.info(`User ${user.email} disconnected Google account`);

    res.status(200).json({
      success: true,
      message: 'Google account disconnected successfully'
    });

  } catch (error) {
    logger.error('Google disconnect error:', error);
    res.status(500).json({ error: 'Failed to disconnect Google account' });
  }
});

/**
 * @route   GET /api/auth/google/url
 * @desc    Get Google OAuth URL for web flow
 * @access  Public
 */
router.get('/google/url', async (req, res) => {
  try {
    const { redirectUri } = req.query;
    
    if (!redirectUri) {
      return res.status(400).json({ error: 'Redirect URI is required' });
    }

    const authUrl = client.generateAuthUrl({
      access_type: 'offline',
      scope: ['profile', 'email'],
      redirect_uri: redirectUri,
      state: 'google_oauth_state' // You can generate a random state for security
    });

    res.status(200).json({
      success: true,
      authUrl: authUrl
    });

  } catch (error) {
    logger.error('Error generating Google OAuth URL:', error);
    res.status(500).json({ error: 'Failed to generate OAuth URL' });
  }
});

module.exports = router;