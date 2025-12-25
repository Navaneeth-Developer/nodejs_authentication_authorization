import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";

const router = Router();

router.post("/me", requireAuth, (req: Request, res: Response) => {
  const authReq = req as Request & { user?: any };
  const authUser = authReq.user;
  if (!authUser) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  return res.status(200).json({ user: authUser });
});

export default router;
