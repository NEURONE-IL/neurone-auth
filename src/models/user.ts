import mongoose from 'mongoose';
import uniqueValidator from 'mongoose-unique-validator';

interface IUser {
  username: string,
  email?: string,
  password: string
}

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String },
  password: { type: String, required: true },
});

// 3rd party mongoose plugin that makes sure that an error returns when an email is used twice because of "unique"
userSchema.plugin(uniqueValidator);

export default mongoose.model<IUser>('User', userSchema);