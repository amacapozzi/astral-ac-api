import express from "express";
import morgan from "morgan";
import { fileRouter } from "./modules/routes/file.route";
import cors from "cors";
export const app = express();
import bodyParser from "body-parser";
import { authRouter } from "./modules/routes/auth.route";
import { hashRouter } from "./modules/routes/hash.route";

app.use(bodyParser.json({ limit: "Infinity" }));
app.use(bodyParser.urlencoded({ limit: "Infinity", extended: true }));
app.use(morgan("dev"));
app.use(express.json());
app.use(cors());

app.use("/file", fileRouter);
app.use("/hash", hashRouter);
app.use("/auth", authRouter);
