const mongoose = require('mongoose');
const { MONGODB_URI } = require('./env');

let memoryServer = null;

async function connectDB() {
  try {
    mongoose.set('strictQuery', false);
    
    // First, try connecting to the configured URI
    console.log(`[Database] Attempting connection to MongoDB at: ${MONGODB_URI}`);
    try {
      await mongoose.connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 2500,
        connectTimeoutMS: 3000
      });
      console.log('[Database] Connected to external/local MongoDB successfully.');
      return mongoose.connection;
    } catch (directErr) {
      console.warn(`[Database] Direct connection to ${MONGODB_URI} failed: ${directErr.message}`);
      console.log('[Database] Initializing embedded in-memory MongoDB fallback...');
      
      const { MongoMemoryServer } = require('mongodb-memory-server');
      memoryServer = await MongoMemoryServer.create({
        instance: {
          dbName: 'agent_shield'
        }
      });
      const uri = memoryServer.getUri();
      console.log(`[Database] In-memory MongoDB started at: ${uri}`);
      await mongoose.connect(uri);
      console.log('[Database] Connected to embedded MongoDB fallback.');
      return mongoose.connection;
    }
  } catch (error) {
    console.error('[Database] Critical error connecting to MongoDB:', error);
    throw error;
  }
}

async function disconnectDB() {
  await mongoose.disconnect();
  if (memoryServer) {
    await memoryServer.stop();
  }
}

module.exports = {
  connectDB,
  disconnectDB
};
