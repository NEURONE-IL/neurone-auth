import mongoose from 'mongoose';

const logUserSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Profile", required: true },
  email: { type: String },
  clientDate: { type: Date },
  serverDate: { type: Date },
  type: { type: String }
});

module.exports = mongoose.model('LogUser', logUserSchema);
