import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { dot } from "node:test/reporters";
import authRoutes from "./routes/auth.routes";
import userRoutes from "./routes/user.routes";
import adminRoutes from "./routes/admin.routes";
import googleAuthRoutes from "./routes/googleAuth.routes";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

app.use("/google", googleAuthRoutes);
app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/admin", adminRoutes);
export default app;
