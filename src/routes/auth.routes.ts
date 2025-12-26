import { Router } from "express";
import {
  loginHandler,
  logoutHandler,
  refreshTokenHandler,
  registerHandler,
  verifyEmailHandler,
  forgotPasswordHandler,
  resetPasswordHandler,
  googleAuthStartHandler,
  googleAuthCallbackHandler,
  twoFASetuphandler,
  twoFAVerifyHandler,
} from "../controllers/auth/auth.controller";
import requireAuth from "../middleware/requireAuth";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh-token", refreshTokenHandler); // Placeholder for refresh token route
router.post("/logout", logoutHandler); // Placeholder for logout route
router.post("/forgot-password", forgotPasswordHandler); // Placeholder for forgot password route
router.post("/reset-password", resetPasswordHandler); // Placeholder for reset password route
router.post("/2fa/setup", requireAuth, twoFASetuphandler); // Google OAuth start route")
router.post("/2fa/verify", requireAuth, twoFAVerifyHandler); // Google OAuth callback route

export default router;
