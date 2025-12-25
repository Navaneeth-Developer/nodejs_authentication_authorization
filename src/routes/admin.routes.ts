import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";
import requireRole from "../middleware/requireRole";
import { User } from "../models/user.model";

const router = Router();

router.get(
  "/users",
  requireAuth,
  requireRole("admin"),
  async (req: Request, res: Response) => {
    // Placeholder for getting all users
    try {
      const users = await User.find(
        {},
        {
          email: 1,
          role: 1,
          isEmailVerified: 1,
          createdAt: 1,
        }
      ).sort({ createdAt: -1 });
      const result = users.map((user) => ({
        id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        createdAt: user.createdAt,
      }));
      return res.status(200).json({ users: result });
    } catch (err) {
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

export default router;
