import mongoose from 'mongoose';

const logUserSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Profile", required: true },
  username: { type: String },
  email: { type: String },
  clientTimestamp: { type: Number },
  serverTimestamp: { type: Number },
  clientDate: { type: Date },
  serverDate: { type: Date },
  type: { type: String },
  userAgent: { type: String },
  userAgentRaw: { type: String}
});

module.exports = mongoose.model('log-auth', logUserSchema);
