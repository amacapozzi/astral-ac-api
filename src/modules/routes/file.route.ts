import express from "express";
import {
  getUserConfig,
  sendFileByName,
  upload,
  uploadFile,
} from "../controllers/file.controller";
import { cliMiddleware } from "../middleware/cli.midleware";
import { apiMiddleware } from "../middleware/api.middleware";

export const fileRouter = express.Router();

fileRouter.route("/download").get(cliMiddleware, sendFileByName);
fileRouter.route("/getRule").get(cliMiddleware, getUserConfig);
fileRouter
  .route("/upload")
  .post(apiMiddleware, upload.single("file"), uploadFile);
