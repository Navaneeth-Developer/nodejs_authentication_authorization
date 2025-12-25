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
import { ca } from "zod/v4/locales";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT || 4000}`;
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
    const { email, password } = result.data;
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
