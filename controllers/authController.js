const User = require('../models/User');
const jwt = require('jsonwebtoken');

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

exports.signup = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const newUser = await User.create({ username, email, password });
        res.status(201).json(newUser);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password, passkey } = req.body;

        if (!email || !password || !passkey) {
            return res.status(400).json({ message: 'Email, password and passkey are required' });
        }

        const user = await User.findOne({ email, passkey });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isMatch = await user.validatePassword(password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials : password' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({ 
          token: token,
          userId :user._id,
          username : user.username
         });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/api/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile.emails[0].value,
          avatar: profile.photos[0].value
        });
      }
      
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }
));

exports.googleAuth = (req, res, next) => {
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
};

exports.googleAuthCallback = (req, res, next) => {
  passport.authenticate('google', { failureRedirect: '/login' }, (err, user) => {
    if (err || !user) {
      return res.redirect('/login');
    }
    req.login(user, (err) => {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
};

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
