"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRouter = void 0;
const express_1 = __importDefault(require("express"));
const auth_controller_1 = require("../controllers/auth.controller");
const cli_midleware_1 = require("../middleware/cli.midleware");
exports.authRouter = express_1.default.Router();
exports.authRouter.route("/pin").post(cli_midleware_1.cliMiddleware, auth_controller_1.startScan);
