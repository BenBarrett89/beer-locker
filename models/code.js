// Load required packages
var mongoose = require('mongoose')
var bcrypt = require('bcrypt-nodejs')

// Define our token schema
var CodeSchema   = new mongoose.Schema({
  value: { type: String, required: true },
  redirectUri: { type: String, required: true },
  userId: { type: String, required: true },
  clientId: { type: String, required: true }
})

// Execute before each code.save() call
CodeSchema.pre('save', function(callback) {
  var code = this

  // Break out if the password hasn't changed
  if (!code.isModified('value')) return callback()

  // Password changed so we need to hash it
  bcrypt.genSalt(5, function(err, salt) {
    if (err) return callback(err)

    bcrypt.hash(code.value, salt, null, function(err, hash) {
      if (err) return callback(err)
      code.value = hash
      callback()
    })
  })
})

// Export the Mongoose model
module.exports = mongoose.model('Code', CodeSchema)
