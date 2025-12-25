import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { dot } from "node:test/reporters";
import authRoutes from "./routes/auth.routes";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

app.use("/auth", authRoutes);

export default app;
