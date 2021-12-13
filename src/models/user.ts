import mongoose from 'mongoose';
import uniqueValidator from 'mongoose-unique-validator'

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// 3rd party mongoose plugin that makes sure that an error returns when an email is used twice because of "unique"
userSchema.plugin(uniqueValidator);

module.exports = mongoose.model('User', userSchema);