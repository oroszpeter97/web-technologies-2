import { MongoClient, Collection, WithId, Document } from 'mongodb';
import * as bcrypt from 'bcrypt';

export interface IUser extends Document {
    username: string;
    email: string;
    password: string;
}

const DB_NAME = process.env.MONGO_DB_NAME;
const COLLECTION_NAME = 'users';

export const getUserCollection = (client: MongoClient): Collection<IUser> => {
    return client.db(DB_NAME).collection<IUser>(COLLECTION_NAME);
};

export const hashPassword = async (plainPassword: string): Promise<string> => {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(plainPassword, salt);
};

export const comparePassword = (candidatePassword: string, hashedPassword: string): Promise<boolean> => {
    return bcrypt.compare(candidatePassword, hashedPassword);
};

export const sanitizeUser = <T extends WithId<IUser>>(user: T) => {
    const { password, ...rest } = user;
    return rest;
};
