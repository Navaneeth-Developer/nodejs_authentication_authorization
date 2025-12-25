import { connectToDB } from "./config/db";
import dotenv from "dotenv";
import http from "http";
import app from "./app";

dotenv.config();

async function startServer() {
  await connectToDB();

  const server = http.createServer(app);
  server.listen(process.env.PORT || 3000, () => {
    console.log(`Server is running on port ${process.env.PORT || 3000}`);
  });
}

startServer().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
