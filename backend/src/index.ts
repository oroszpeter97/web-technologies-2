import express = require("express");
import * as dotenv from "dotenv";
import { connectDB } from "./db";
import { getUserCollection, hashPassword, sanitizeUser, comparePassword } from "./models/user";
import { getRecipeCollection } from "./models/recipe";
import { ObjectId } from "mongodb";
import jwt = require("jsonwebtoken");
import { randomUUID } from "crypto";

dotenv.config();

const app = express();
app.use(express.json());

const requireAuth: express.RequestHandler = (req, res, next) => {
  const authHeader = req.header("Authorization");
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;

  if (!token) {
    return res.status(401).json({ message: "Missing token" });
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({ message: "JWT secret not configured" });
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

async function start() {
  try {
    const client = await connectDB();
    console.log("MongoDB connected");

    // Register a new user account
    app.post("/api/register", async (req, res) => {
      const { username, email, password } = req.body ?? {};

      if (!username || !email || !password) {
        return res.status(400).json({ message: "Missing required fields" });
      }

      try {
        const users = getUserCollection(client);

        const existing = await users.findOne({
          $or: [{ username }, { email }],
        });

        if (existing) {
          return res.status(409).json({ message: "User already exists" });
        }

        const hashed = await hashPassword(password);
        const insertResult = await users.insertOne({ username, email, password: hashed });

        const created = await users.findOne({ _id: insertResult.insertedId });
        if (!created) {
          return res.status(500).json({ message: "Registration failed" });
        }

        return res.status(201).json(sanitizeUser(created));
      } catch (err) {
        console.error("Registration error:", err);
        return res.status(500).json({ message: "Registration failed" });
      }
    });

    // Authenticate user and issue JWT
    app.post("/api/login", async (req, res) => {
      const { username, email, password } = req.body ?? {};
      const identifier = username ?? email;

      if (!identifier || !password) {
        return res.status(400).json({ message: "Missing required fields" });
      }

      if (!process.env.JWT_SECRET) {
        return res.status(500).json({ message: "JWT secret not configured" });
      }

      try {
        const users = getUserCollection(client);

        const user = await users.findOne({
          $or: [{ username: identifier }, { email: identifier }],
        });

        if (!user) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const ok = await comparePassword(password, user.password);
        if (!ok) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign(
          { sub: user._id.toString(), username: user.username, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "1h", jwtid: randomUUID() }
        );

        return res.status(200).json({ user: sanitizeUser(user), token });
      } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Login failed" });
      }
    });

    // Verify JWT validity (protected)
    app.get("/api/token-test", requireAuth, (_req, res) => {
      return res.status(200).json({ message: "Token is valid" });
    });

    // Create a recipe (protected)
    app.post("/api/recipes", requireAuth, async (req, res) => {
      const authHeader = req.header("Authorization");
      const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;

      if (!token) {
        return res.status(401).json({ message: "Missing token" });
      }

      if (!process.env.JWT_SECRET) {
        return res.status(500).json({ message: "JWT secret not configured" });
      }

      const { title, description, ingredients, instructions } = req.body ?? {};
      if (!title || !description || !Array.isArray(ingredients) || !instructions) {
        return res.status(400).json({ message: "Missing or invalid fields" });
      }

      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET) as jwt.JwtPayload;
        const sub = payload?.sub as string | undefined;
        const username = payload?.username as string | undefined;

        if (!sub) {
          return res.status(401).json({ message: "Invalid token" });
        }

        const recipes = getRecipeCollection(client);
        const ownerId = new ObjectId(sub);

        const insertResult = await recipes.insertOne({
          title,
          description,
          ingredients,
          instructions,
          ownerId,
          ownerUsername: username,
        });

        const created = await recipes.findOne({ _id: insertResult.insertedId });
        if (!created) {
          return res.status(500).json({ message: "Recipe creation failed" });
        }

        return res.status(201).json(created);
      } catch (err) {
        console.error("Create recipe error:", err);
        return res.status(500).json({ message: "Recipe creation failed" });
      }
    });

    // Get all recipes (public)
    app.get("/api/recipes", async (_req, res) => {
      try {
        const recipes = getRecipeCollection(client);
        const items = await recipes.find({}).toArray();
        return res.status(200).json(items);
      } catch (err) {
        console.error("Get recipes error:", err);
        return res.status(500).json({ message: "Failed to fetch recipes" });
      }
    });

    // Minimal global error handler
    app.use(
      (err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        console.error("Unhandled error:", err);
        res.status(500).json({ message: "Internal server error" });
      }
    );

    app.listen(3000, () => {
      console.log("Server running on http://localhost:3000");
    });
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  }
}

start();
