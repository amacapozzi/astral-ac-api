"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashRouter = void 0;
const express_1 = __importDefault(require("express"));
const hash_controller_1 = require("../controllers/hash.controller");
const cli_midleware_1 = require("../middleware/cli.midleware");
exports.hashRouter = express_1.default.Router();
exports.hashRouter.route("/load").get(cli_midleware_1.cliMiddleware, hash_controller_1.getHashes);
