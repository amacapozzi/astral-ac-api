import express from "express";
import { saveScanResult, startScan } from "../controllers/auth.controller";
import { cliMiddleware } from "../middleware/cli.midleware";
export const authRouter = express.Router();

authRouter.route("/pin").post(cliMiddleware, startScan);
authRouter.route("/save").post(cliMiddleware, saveScanResult);
