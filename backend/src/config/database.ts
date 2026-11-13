import { MongoClient, type Db } from "mongodb";

export class MissingMongoUriError extends Error {
  constructor() {
    super("MONGODB_URI is required.");
    this.name = "MissingMongoUriError";
  }
}

export async function connectDatabase(): Promise<{ client: MongoClient; db: Db }> {
  const uri = process.env.MONGODB_URI;
  const databaseName = process.env.MONGODB_DB_NAME;

  if (!uri) {
    throw new MissingMongoUriError();
  }

  if (!databaseName) {
    throw new Error("MONGODB_DB_NAME is required to connect to the database.");
  }

  const client = new MongoClient(uri);

  try {
    await client.connect();
    return { client, db: client.db(databaseName) };
  } catch (error) {
    await client.close();
    throw error;
  }
}
