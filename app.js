const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const cors = require('cors');
let dotenv = require("dotenv").config();

const app = express();

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const postRoutes = require('./routes/postRoutes');
const eventRoutes = require('./routes/eventRoutes');
const commentRoutes = require('./routes/commentRoutes');
const contactRoute = require('./contact');
const workshopRoutes = require('./routes/workshopRoutes');
const adminRoutes = require('./routes/adminRoutes'); // Import admin routes
const { createDefaultAdmin } = require('./models/admin'); // Import createDefaultAdmin function
const teamRoutes = require('./routes/teamRoutes'); // Import team routes


// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Route handlers

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/post', postRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/comment', commentRoutes);
app.use('/api/reg', workshopRoutes);
// app.use('/api/search', searchRoutes);
app.use('/api/workshop', workshopRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/contact', contactRoute);
app.use('/api/team', teamRoutes);


// Serve index.html on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  // useNewUrlParser: true,
  // useUnifiedTopology: true,
  dbName: "myapp"
})
  .then(async () => {
    console.log('MongoDB Connected');
    await createDefaultAdmin(); // Create default admin user
  })
  .catch(err => console.log('MongoDB Connection Error:', err));

// Start the server
const PORT = 5000;
app.listen(PORT, (err) => {
  if (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
  }
  console.log(`Server running on port ${PORT}`);
});

// Export the Express app
module.exports = app;