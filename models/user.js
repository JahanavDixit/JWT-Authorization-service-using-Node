let mongoose = require('mongoose');

let UserSchema = new mongoose.Schema({
  username: String,
  password: String
}, {timestamps: true});

mongoose.model('User', UserSchema);