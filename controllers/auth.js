// Load required packages
var passport = require('passport')
var BasicStrategy = require('passport-http').BasicStrategy

// Load the models
var User = require('../models/user')
var Client = require('../models/client');

passport.use(new BasicStrategy(
  function(username, password, callback) {
    User.findOne({ username: username }, function (err, user) {
      if (err) { return callback(err) }

      // No user found with that username
      if (!user) { return callback(null, false) }

      // Make sure the password is correct
      user.verifyPassword(password, function(err, isMatch) {
        if (err) { return callback(err) }

        // Password did not match
        if (!isMatch) { return callback(null, false) }

        // Success
        return callback(null, user)
      })
    })
  }
))

passport.use('client-basic', new BasicStrategy(
  function(username, password, callback) {
    Client.findOne({ id: username }, function (err, client) {
      if (err) { return callback(err) }

      // No client found with that id or bad password
      if (!client || client.secret !== password) { return callback(null, false) }

      // Success
      return callback(null, client)
    })
  }
))

// export as functions
exports.isAuthenticated = passport.authenticate('basic', { session : false })
exports.isClientAuthenticated = passport.authenticate('client-basic', { session : false })
