"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.fileRouter = void 0;
const express_1 = __importDefault(require("express"));
const file_controller_1 = require("../controllers/file.controller");
const cli_midleware_1 = require("../middleware/cli.midleware");
const api_middleware_1 = require("../middleware/api.middleware");
exports.fileRouter = express_1.default.Router();
exports.fileRouter.route("/download").get(cli_midleware_1.cliMiddleware, file_controller_1.sendFileByName);
exports.fileRouter
    .route("/upload")
    .post(api_middleware_1.apiMiddleware, file_controller_1.upload.single("file"), file_controller_1.uploadFile);
