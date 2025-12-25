import { Router } from "express";
import {
  loginHandler,
  logoutHandler,
  refreshTokenHandler,
  registerHandler,
  verifyEmailHandler,
  forgotPasswordHandler,
  resetPasswordHandler,
} from "../controllers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh-token", refreshTokenHandler); // Placeholder for refresh token route
router.post("/logout", logoutHandler); // Placeholder for logout route
router.post("/forgot-password", forgotPasswordHandler); // Placeholder for forgot password route
router.post("/reset-password", resetPasswordHandler); // Placeholder for reset password route
export default router;
