
import { MongoClient } from "mongodb";

let client: MongoClient | null = null;
export let db: any = null;

export async function connectDB(): Promise<MongoClient> {
  const uri = process.env.MONGO_URI as string;
  if (!uri) {
    console.error("MONGO_URI environment variable is not set.");
    process.exit(1);
  }
  try {
    client = new MongoClient(uri);
    await client.connect();
    db = client.db("web-technologies-2-database");
    console.log("Connected to MongoDB");
    return client;
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
}
