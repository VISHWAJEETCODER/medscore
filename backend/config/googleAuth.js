const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

// Construct callback URL - must be absolute for Google OAuth
const getCallbackURL = () => {
  if (process.env.GOOGLE_CALLBACK_URL) {
    return process.env.GOOGLE_CALLBACK_URL;
  }
  // Construct from environment or default
  const baseUrl = process.env.BACKEND_URL || process.env.API_URL || "https://api.medscore.xyz";
  return `${baseUrl}/api/auth/google/callback`;
};

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: getCallbackURL()  // Fixed callback URL - must be absolute
  },
  async function(accessToken, refreshToken, profile, done) {
    try {
      // Check if user already exists with this Google ID
      let existingUser = await User.findOne({ googleId: profile.id });
      
      if (existingUser) {
        return done(null, existingUser);
      }
      
      // Check if user exists with this email
      existingUser = await User.findOne({ email: profile.emails[0].value });
      
      if (existingUser) {
        // Link Google account to existing user
        existingUser.googleId = profile.id;
        existingUser.name = profile.displayName;
        existingUser.profile = existingUser.profile || {};
        existingUser.profile.avatar = profile.photos[0].value;
        await existingUser.save();
        return done(null, existingUser);
      }
      
      // Create new user
      const newUser = new User({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        profile: {
          avatar: profile.photos[0].value
        },
        role: 'student', // Default role
        isVerified: true // Google users are automatically verified
      });
      
      await newUser.save();
      return done(null, newUser);
    } catch (error) {
      return done(error, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

module.exports = passport;