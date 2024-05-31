import { type Request, Response, NextFunction } from "express";
//import CryptoJS from "crypto-js";

export const apiMiddleware = async (
  _req: Request,
  _res: Response,
  next: NextFunction
) => {
  //const headers = req.headers.authorization?.split(" ")[1];
  /* 
  const bytes = CryptoJS.AES.decrypt(
    headers?.toString() as string,
    "0a]lvd$f5dmfrz&"
  );

  const plainText = bytes.toString(CryptoJS.enc.Utf8);

  if (plainText !== "8LUVNsJ1jCTf7Wfs9ZUj3uPS0wogci7Y") {
    return res.status(400).send("Unauthorized");
  } */

  return next();
};
