const express = require('express');
const cors = require('cors');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.axtsmlj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    const database = client.db('swiftcash');
    const usersCollection = database.collection('User');
    const transactionsCollection = database.collection('transactions');

    // JWT verify token
    app.post('/verifyToken', (req, res) => {
      const { token } = req.body;

      if (!token) {
        return res.status(401).send({ valid: false });
      }

      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ valid: false });
        }

        res.send({ valid: true, userId: decoded.userId });
      });
    });

    // User registration
    app.post('/register', async (req, res) => {
      const { name, pin, mobileNumber, email, role } = req.body;
      let balance = 0;
      // Hash the PIN
      const hashedPin = await bcrypt.hash(pin, 10);
      const newUser = { name, pin: hashedPin, mobileNumber, email, role, balance, status: 'pending' };
      const result = await usersCollection.insertOne(newUser);
      res.send(result);
    });

    // Login
    app.post('/login', async (req, res) => {
      const { identifier, pin } = req.body;

      // Find the user by email or phone number
      const user = await usersCollection.findOne({ $or: [{ email: identifier }, { mobileNumber: identifier }] });

      if (!user) {
        return res.status(401).json({ message: 'Invalid email or phone number' });
      }

      // Compare the provided PIN with the hashed PIN in the database
      const isMatch = await bcrypt.compare(pin, user.pin);

      if (!isMatch) {
        return res.status(401).send({ message: 'Invalid PIN' });
      }

      // Generate JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.send({ success: true, token, user });
    });

    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('SwiftCash server is running');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
