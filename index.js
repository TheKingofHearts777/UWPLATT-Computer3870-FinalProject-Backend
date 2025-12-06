import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";

dotenv.config();

const app = express();

const ACCESS_TOKEN_EXPIRE_MINUTES = 30;
const HOST = process.env.HOST || "localhost"
const PORT = process.env.PORT || 8081;
const MONGO_URI = process.env.MONGO_URI;
const DBNAME = process.env.DBNAME;
const SECRET_KEY = process.env.SECRET_KEY;
const COLLECTION = process.env.COLLECTION;

if (!HOST) {
    console.log("HOST not defined in .env, defaulting to localhost");
}
if (!PORT) {
    console.log("PORT not defined in .env, defaulting to 8081");
}
if (!MONGO_URI) {
    throw new Error("MONGO_URI is not defined in .env");
}
if (!DBNAME) {
    throw new Error("DBNAME is not defined in .env");
}
if (!SECRET_KEY) {
    throw new Error("SECRET_KEY is not defined in .env");
}
if (!COLLECTION) {
    throw new Error("COLLECTION is not defined in .env");
}

// Mongo client and collection references
const client = new MongoClient(MONGO_URI);
let db;
let usersCollection;

// Middleware
app.use(cors());
app.use(express.json());

// Helper to generate JWT access token
function generateAccessToken(user) {
    return jwt.sign(
        {
            id: user._id,
            username: user.username,
        },
        SECRET_KEY,
        {
            expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m`,
        }
    );
}

// Auth middleware to protect routes
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Missing token" });
    }

    jwt.verify(token, SECRET_KEY, (err, payload) => {
        if (err) {
            return res.status(403).json({ error: "Invalid or expired token" });
        }
        req.user = payload;
        next();
    });
}

// Simple root for quick testing
app.get("/hello", (req, res) => {
    res.json({ message: "Hello from NodeJS/Express" });
});

// Signup route
app.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ error: "Username and password are required" });
        }

        // Check if user already exists
        const existingUser = await usersCollection.findOne({ username });
        if (existingUser) {
            return res
                .status(409)
                .json({ error: "Username is already taken" });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Insert new user
        const result = await usersCollection.insertOne({
            username,
            passwordHash,
            createdAt: new Date(),
        });

        const user = { _id: result.insertedId, username };

        // Issue token on signup
        const token = generateAccessToken(user);

        res.status(201).json({
            token,
            user: {
                id: user._id,
                username: user.username,
            },
        });
        console.log("New user signed up: ", { user });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Login route
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ error: "Username and password are required" });
        }

        const user = await usersCollection.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = generateAccessToken(user);

        res.status(200).json({
            token,
            user: {
                id: user._id,
                username: user.username,
            },
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Example protected route
app.get("/me", authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// Guest route if you want unauthenticated quick play
app.get("/guest", (req, res) => {
    res.json({ message: "Guest play endpoint" });
});

// Connect to MongoDB and start server
async function startServer() {
    try {
        await client.connect();
        db = client.db(DBNAME);
        usersCollection = db.collection(COLLECTION);

        console.log("MongoDB connected");
        console.log(`Using database: ${DBNAME}, collection: ${COLLECTION}`);

        app.listen(PORT, HOST, () => {
            console.log(`Server running at http://${HOST}:${PORT}`);
        });
    } catch (err) {
        console.error("MongoDB connection error:", err);
        process.exit(1);
    }
}

startServer();
