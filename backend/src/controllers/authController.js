import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import env from '../config/env.js';
import User from '../models/User.js';

function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  });
}

export async function register(req, res, next) {
  try {
    const { email, password, name } = req.body;
    const normalizedEmail = String(email).toLowerCase();
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res
        .status(409)
        .json({ error: 'Unable to create account — please try a different email' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email: normalizedEmail, passwordHash, name: name || '' });
    const token = signToken(user);
    return res.status(201).json({ token, user: user.toSafeJSON() });
  } catch (err) {
    // Race on unique index: concurrent duplicate inserts surface as E11000
    // instead of a findOne hit. Map to the same 409.
    if (err && err.code === 11000) {
      return res
        .status(409)
        .json({ error: 'Unable to create account — please try a different email' });
    }
    next(err);
  }
}

export async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: String(email).toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const ok = await user.comparePassword(password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = signToken(user);
    return res.json({ token, user: user.toSafeJSON() });
  } catch (err) {
    next(err);
  }
}

export async function me(req, res) {
  return res.json({ user: req.user.toSafeJSON() });
}
