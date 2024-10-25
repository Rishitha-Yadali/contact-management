import { openDb } from '../../../contacts-db/contacts'; // Adjust path as needed
import { parse } from 'csv-parse';
import multer from 'multer';
import nextConnect from 'next-connect';
import jwt from 'jsonwebtoken';
import Joi from 'joi';

const upload = multer({ storage: multer.memoryStorage() });
const handler = nextConnect();

// Handle CSV upload
handler.use(upload.single('file'));

handler.post(async (req, res) => {
  const db = await openDb();
  const token = req.headers.authorization?.split(' ')[1];

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.id;

  const { buffer } = req.file;

  parse(buffer.toString(), { columns: true }, async (err, records) => {
    if (err) return res.status(400).json({ error: 'Invalid CSV format' });

    const promises = records.map((record) => {
      return db.run(
        'INSERT INTO contacts (userId, name, email, phone, address, timezone, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, datetime("now"), datetime("now"))',
        [userId, record.name, record.email, record.phone, record.address, record.timezone]
      );
    });

    await Promise.all(promises);
    res.status(200).json({ message: 'Contacts uploaded' });
  });
});

// Export Contacts as CSV
handler.get(async (req, res) => {
  const db = await openDb();
  const token = req.headers.authorization?.split(' ')[1];

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.id;

  const contacts = await db.all('SELECT * FROM contacts WHERE userId = ?', [userId]);

  const csv = contacts.map((contact) => ({
    name: contact.name,
    email: contact.email,
    phone: contact.phone,
    address: contact.address,
    timezone: contact.timezone,
    created_at: contact.created_at,
    updated_at: contact.updated_at,
  }));

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment;filename=contacts.csv');

  res.status(200).send(csv);
});

export default handler;
export const config = { api: { bodyParser: false } };
