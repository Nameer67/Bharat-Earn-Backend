require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy
const bcrypt = require('bcryptjs')

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))
app.use(passport.initialize())
app.use(passport.session())

// MongoDB User model
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String
})
const User = mongoose.model('User', userSchema)

// Passport local strategy
passport.use(new LocalStrategy({ usernameField: 'email' },
  (email, password, done) => {
    User.findOne({ email }, (err, user) => {
      if (err) return done(err)
      if (!user) return done(null, false, { message: 'Incorrect email' })
      if (!bcrypt.compareSync(password, user.password)) {
        return done(null, false, { message: 'Incorrect password' })
      }
      return done(null, user)
    })
  }
))

// Passport Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    User.findOne({ googleId: profile.id }, (err, user) => {
      if (err) return done(err)
      if (user) return done(null, user)
      // New user
      const newUser = new User({ googleId: profile.id, email: profile.emails[0].value })
      newUser.save((err) => done(err, newUser))
    })
  }
))

passport.serializeUser((user, done) => done(null, user.id))
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => done(err, user))
})

// Routes
app.get('/', (req, res) => res.send('Hello from BharatEarn!'))
app.get('/signup', (req, res) => {
  res.send(`
    <h2>Sign Up</h2>
    <form method="post" action="/signup">
      <input name="email" placeholder="Email" required/><br/>
      <input type="password" name="password" placeholder="Password" required/><br/>
      <button type="submit">Sign Up</button>
    </form>
    <a href="/login">Login</a>`)
})

app.post('/signup', async (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 10)
  const user = new User({ email: req.body.email, password: hash })
  await user.save()
  res.redirect('/login')
})

app.get('/login', (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form method="post" action="/login">
      <input name="email" placeholder="Email" required/><br/>
      <input type="password" name="password" placeholder="Password" required/><br/>
      <button type="submit">Login</button>
    </form>
    <a href="/auth/google">Login with Google</a>`)
})

app.post('/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  })
)

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
)

app.get('/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  })
)

app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login')
  res.send(`<h2>Welcome ${req.user.email}</h2><a href="/logout">Logout</a>`)
})

app.get('/logout', (req, res) => {
  req.logout(() => {})
  res.redirect('/')
})

// Connect DB & start server
mongoose.connect(process.env.MONGO_URI)
  .then(() => app.listen(process.env.PORT || 3000, () => console.log('Server started')))
