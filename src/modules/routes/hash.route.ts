import express from "express";
import { getHashes } from "../controllers/hash.controller";
//import { cliMiddleware } from "../middleware/cli.midleware";
export const hashRouter = express.Router();

hashRouter.route("/load").get(getHashes);
