import { email } from "zod";
import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { comparePasswords, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
import { authenticator } from "otplib";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT || 4000}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID || "";
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || "";
  if (!clientId || !clientSecret) {
    throw new Error("Google OAuth credentials are not set");
  }
  return new OAuth2Client({ clientId, clientSecret, redirectUri });
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      return res
        .status(400)
        .json({ message: "Invalid data", errors: result.error.flatten() });
    }
    const { email, password, name } = result.data;
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(409).json({ message: "Email already in use" });
    }
    const passwordHash = await hashPassword(password);
    const newUser = await User.create({
      email: normalizedEmail,
      passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
      name,
    });
    // return res.status(201).json({ message: "User registered successfully" });

    // Email verification logic
    const verifyToken = jwt.sign(
      { sub: newUser._id },
      process.env.JWT_ACCESS_SECRET || "default_verify_secret",
      { expiresIn: "1d" }
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;
    await sendEmail(
      newUser.email,
      "Verify your email",
      `<p>Please verify your email by clicking the link below:</p>
       <a href="${verifyUrl}">Verify Email</a>`
    );

    return res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",

      userId: {
        id: newUser._id,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;
  if (!token) {
    return res.status(400).json({ message: "Verification token is missing" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };

    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    if (user.isEmailVerified) {
      return res.status(400).json({ message: "Email is already verified" });
    }
    user.isEmailVerified = true;
    await user.save();
    return res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log(error);

    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function loginHandler(req: Request, res: Response) {
  // Implementation for login handler
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res
        .status(400)
        .json({ message: "Invalid data", errors: result.error.flatten() });
    }
    const { email, password, twoFactorCode } = result.data;
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const isPasswordValid = await comparePasswords(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (!user.isEmailVerified) {
      return res.status(403).json({ message: "Email is not verified" });
    }

    if (user.twoFactorEnabled) {
      if (!twoFactorCode || typeof twoFactorCode !== "string") {
        return res.status(400).json({ message: "Two-factor code is required" });
      }
      if (!user.twoFactorSecret) {
        return res.status(500).json({ message: "Two-factor secret not found" });
      }
    }

    const is2FAValid = authenticator.check(
      twoFactorCode || "",
      user.twoFactorSecret || ""
    );
    if (user.twoFactorEnabled && !is2FAValid) {
      return res.status(400).json({ message: "Invalid two-factor code" });
    }
    const accessToken = createAccessToken(
      user._id.toString(),
      user.role,
      user.tokenVersion
    );
    const refreshToken = createRefreshToken(
      user._id.toString(),
      user.tokenVersion
    );
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twofactorEnabled: user.twoFactorEnabled,
      },
      accessToken,
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  // Implementation for refresh token handler
  console.log("cookies", req.cookies);

  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    const payload = verifyRefreshToken(token);
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Invalid token version" });
    }

    const newAccessToken = createAccessToken(
      user._id.toString(),
      user.role,
      user.tokenVersion
    );
    const newRefreshToken = createRefreshToken(
      user._id.toString(),
      user.tokenVersion
    );

    const isProd = process.env.NODE_ENV === "production";
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Token refreshed successfully",
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twofactorEnabled: user.twoFactorEnabled,
      },
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.log("Refresh token", error);

    res.status(500).json({ message: "Internal server error" });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  // Implementation for logout handler
  res.clearCookie("refreshToken", { path: "/" });
  return res.status(200).json({ message: "Logged out successfully" });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  // Implementation for forgot password handler
  const { email } = req.body as { email?: string };
  console.log("Forgot password request for email:", email);

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const normalizedEmail = email.toLowerCase().trim();
  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(200).json({
        message:
          "If that email is registered, you will receive a password reset link.",
      });
    }
    const rawtoken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawtoken)
      .digest("hex");
    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();
    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawtoken}`;
    await sendEmail(
      user.email,
      "Password Reset Request",
      `<p>You requested a password reset. Click the link below to reset your password:</p>
       <a href="${resetUrl}">Reset Password</a>
       <p>This link will expire in 1 hour.</p>`
    );
    return res.status(200).json({
      message:
        "If that email is registered, you will receive a password reset link.",
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  // Implementation for reset password handler
  const { token, newPassword } = req.body as {
    token: string;
    newPassword: string;
  };
  if (!token) {
    return res.status(400).json({ message: "reset Token is required" });
  }
  if (!newPassword || newPassword.length < 6) {
    return res
      .status(400)
      .json({ message: "New password must be at least 6 characters long" });
  }

  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid or expired reset token" });
    }
    const newHashedPassword = await hashPassword(newPassword);
    user.passwordHash = newHashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.tokenVersion += 1;
    await user.save();
    return res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function googleAuthStartHandler(req: Request, res: Response) {
  try {
    const oauth2Client = getGoogleClient();
    const scopes = ["openid", "profile", "email"];
    const authorizationUrl = oauth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: scopes,
    });
    console.log("Google Auth URL:", authorizationUrl);

    // return res.status(200).json({ url: authorizationUrl });
    return res.redirect(authorizationUrl);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  // Implementation for Google OAuth callback handler
  console.log("googleAuth");

  const code = req.query.code as string | undefined;
  if (!code) {
    return res.status(400).json({ message: "Authorization code is missing" });
  }

  try {
    const oauth2Client = getGoogleClient();
    const { tokens } = await oauth2Client.getToken(code);
    if (!tokens.id_token) {
      return res
        .status(400)
        .json({ message: "ID token is missing in response" });
    }
    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    console.log("payload==>>", payload);

    const email = payload?.email;
    const name = payload?.name || "No Name";
    const emailVerified = payload?.email_verified;
    if (!email || !emailVerified) {
      return res.status(400).json({ message: "Email not verified by Google" });
    }
    const normalizedEmail = email.toLowerCase().trim();
    let user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);
      user = await User.create({
        email: normalizedEmail,
        passwordHash,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
        name,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }
    const accessToken = createAccessToken(
      user._id.toString(),
      user.role as "user" | "admin",
      user.tokenVersion
    );
    const refreshToken = createRefreshToken(
      user._id.toString(),
      user.tokenVersion
    );
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: "Login via Google successful",
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        name: user.name,
      },
      accessToken,
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function twoFASetuphandler(req: Request, res: Response) {
  // Implementation for 2FA setup handler
  const authReq = req as Request & { user?: any };
  const authUser = authReq.user;
  if (!authUser) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  try {
    const user = await User.findById(authUser.id);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const secret = authenticator.generateSecret();
    const issuer = "AuthenticationApp";
    const otpauth = authenticator.keyuri(user.email, issuer, secret);
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = false;
    await user.save();
    return res.status(200).json({
      message: "2FA setup initiated",
      otpauth,
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function twoFAVerifyHandler(req: Request, res: Response) {
  // Implementation for 2FA verification handler
  const authReq = req as Request & { user?: any };
  const authUser = authReq.user;
  if (!authUser) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const { twoFactorCode } = req.body as { twoFactorCode?: string };
  console.log(twoFactorCode);

  if (!twoFactorCode || typeof twoFactorCode !== "string") {
    return res.status(400).json({ message: "Two-factor code is required" });
  }
  try {
    const user = await User.findById(authUser.id);
    if (!user || !user.twoFactorSecret) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const isValid = authenticator.verify({
      token: twoFactorCode,
      secret: user.twoFactorSecret,
    });
    if (!isValid) {
      return res.status(400).json({ message: "Invalid two-factor code" });
    }
    user.twoFactorEnabled = true;
    await user.save();
    return res
      .status(200)
      .json({ message: "Two-factor authentication enabled successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}
