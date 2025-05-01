// Basic backend for OTP service using Node.js & Express

const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
// const smsService = require('your-sms-service'); // Placeholder for SMS API integration
const BASE_URL = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://your-production-api.com';

const BASE_URL = 'https://api.sms.ir';

const app = express();
app.use(bodyParser.json());

// In-memory store for demonstration (replace with Redis or DB for production)
let otpStore = {};

const OTP_LENGTH = 6;
const OTP_EXPIRY_MS = 2 * 60 * 1000; // 2 minutes
const AES_SECRET = 'your-256-bit-secret-key';

function generateOTP() {
  return Array.from({ length: OTP_LENGTH }, () => Math.floor(Math.random() * 10)).join('');
}

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(AES_SECRET), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const [ivHex, encryptedHex] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(AES_SECRET), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many OTP requests from this IP, please try again later.'
});

async function api(endpoint, data) {
  const response = await fetch(`${BASE_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return response.json();
}

// Usage
api('/send-otp', { contact: 'user@example.com' });

app.post('/send-otp', limiter, (req, res) => {
  const { contact } = req.body; // email or phone number
  const otp = generateOTP();
  const encryptedOTP = encrypt(otp);
  const expiry = Date.now() + OTP_EXPIRY_MS;

  otpStore[contact] = { otp: encryptedOTP, expiry };

  // Send via email or SMS (mocked)
  console.log(`OTP for ${contact}: ${otp}`);

  // Example email send (replace with real credentials)
  /*
  const transporter = nodemailer.createTransport({ /* transport config });
  await transporter.sendMail({
    from: 'your@email.com',
    to: contact,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${otp}`
  });
  */

  res.json({ message: 'OTP sent successfully.' });
});

app.post('/verify-otp', (req, res) => {
  const { contact, otp: submittedOTP } = req.body;
  const record = otpStore[contact];

  if (!record) return res.status(400).json({ error: 'No OTP found for this contact.' });
  if (Date.now() > record.expiry) return res.status(400).json({ error: 'OTP expired.' });

  const originalOTP = decrypt(record.otp);
  if (submittedOTP === originalOTP) {
    delete otpStore[contact];
    return res.json({ success: true, message: 'OTP verified.' });
  } else {
    return res.status(400).json({ error: 'Invalid OTP.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`OTP backend running on port ${PORT}`));
