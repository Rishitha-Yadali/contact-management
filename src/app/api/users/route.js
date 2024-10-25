import { openDb } from '../../../contacts-db/contacts'; // Adjust path as needed
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';

// User Registration with Email Verification
export async function POST(req) {
  const db = await openDb();
  const { email, password } = await req.json();

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
  });

  const { error } = schema.validate({ email, password });
  if (error) return new Response(JSON.stringify({ error: error.details[0].message }), { status: 400 });

  const userExists = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  if (userExists) return new Response(JSON.stringify({ error: 'Email already exists' }), { status: 400 });

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = uuidv4();

  await db.run('INSERT INTO users (email, password, verification_token) VALUES (?, ?, ?)', [
    email,
    hashedPassword,
    verificationToken,
  ]);

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Verify your account',
    text: `Please verify your account by clicking the link: http://localhost:3000/api/verify/${verificationToken}`,
  };

  await transporter.sendMail(mailOptions);
  return new Response(JSON.stringify({ message: 'User registered, please verify your email' }), { status: 200 });
}

// User Login with JWT
export async function login(req) {
  const db = await openDb();
  const { email, password } = await req.json();

  const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user) return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 400 });

  if (!user.is_verified) return new Response(JSON.stringify({ error: 'Please verify your email' }), { status: 400 });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 400 });

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  return new Response(JSON.stringify({ token }), { status: 200 });
}
