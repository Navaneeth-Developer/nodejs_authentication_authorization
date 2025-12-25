import { Router } from "express";
import {
  googleAuthCallbackHandler,
  googleAuthStartHandler,
} from "../controllers/auth/auth.controller";
const router = Router();
router.get("/", googleAuthStartHandler); // Google OAuth start route
router.get("/callback", googleAuthCallbackHandler); // Google OAuth callback route
export default router;
