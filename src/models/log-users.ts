import mongoose from 'mongoose';

interface ILogAuth {
  userId: mongoose.Schema.Types.ObjectId,
  username?: string,
  email?: string,
  clientTimestamp?: number,
  serverTimestamp?: number,
  clientDate?: Date,
  serverDate?: Date,
  type?: string,
  userAgent?: string,
  userAgentRaw?: string
}

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

export default mongoose.model<ILogAuth>('log-auth', logUserSchema);
