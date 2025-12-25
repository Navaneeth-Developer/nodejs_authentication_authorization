import { NextFunction, Request, Response } from "express";

function requireRole(role: string) {
  return function (req: Request, res: Response, next: NextFunction) {
    const authReq = req as Request & { user?: any };
    const user = authReq.user; // Assuming req.user is populated by previous middleware
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (user.role !== role) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };
}

export default requireRole;
