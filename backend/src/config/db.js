import mongoose from 'mongoose';
import env from './env.js';

async function connectDB() {
  try {
    await mongoose.connect(env.MONGODB_URI);
    console.log(`MongoDB connected: ${mongoose.connection.host}`);
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }

  mongoose.connection.on('error', (err) => {
    console.error('MongoDB runtime error:', err.message);
  });
}

export default connectDB;
