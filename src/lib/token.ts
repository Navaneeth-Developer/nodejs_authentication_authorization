import jwt from "jsonwebtoken";

export function createAccessToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number
) {
  const payload = { sub: userId, role, tokenVersion };
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: "30m",
  });
}

export function createRefreshToken(userId: string, tokenVersion: number) {
  const payload = { sub: userId, tokenVersion };
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: "7d",
  });
}

export const verifyRefreshToken = (token: string) => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
      sub: string;
      tokenVersion: number;
    };
  } catch (error) {
    throw new Error("Invalid token");
  }
};

export const verifyAccessToken = (token: string) => {
  try {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
      role: "user" | "admin";
      tokenVersion: number;
    };
  } catch (error) {
    throw new Error("Invalid token");
  }
};
