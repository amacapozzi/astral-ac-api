import { type Request, Response, NextFunction } from "express";

export const cliMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const headers = req.headers.authorization?.split(" ")[1];

  if (
    headers?.toString() !==
    "f693a15d589b9bee750fd542038369da3d79f01959ddde151ad668ef11cd1234"
  ) {
    return res.status(400).send("Unauthorized");
  }

  return next();
};
