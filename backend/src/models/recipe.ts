import { MongoClient, Collection, Document, ObjectId } from 'mongodb';

export interface IRecipe extends Document {
    title: string;
    description: string;
    ingredients: string[];
    instructions: string;
    ownerId: ObjectId;
    ownerUsername?: string;
}

const DB_NAME = process.env.MONGO_DB_NAME;
const COLLECTION_NAME = 'recipes';

export const getRecipeCollection = (client: MongoClient): Collection<IRecipe> => {
    return client.db(DB_NAME).collection<IRecipe>(COLLECTION_NAME);
};

export default getRecipeCollection;
