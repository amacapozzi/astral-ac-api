"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getHashes = void 0;
const db_1 = __importDefault(require("../../lib/db"));
const extractRelevantData = (data) => {
    return data.map((item) => ({
        clientName: item.clientName,
        clientHash: item.clientHash,
        processName: item.processName,
        severity: item.severity,
    }));
};
const getHashes = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const game = req.query.game;
    if (!game) {
        return res
            .status(400)
            .json({ error: true, message: "Please enter a game" });
    }
    let gameHashes;
    if (game.toString().toUpperCase() === "MINECRAFT") {
        gameHashes = yield db_1.default.clientStrings.findMany({
            where: { game: "MINECRAFT" },
        });
    }
    else if (game.toString().toUpperCase() === "FIVEM") {
        gameHashes = yield db_1.default.clientStrings.findMany({
            where: { game: "FIVEM" },
        });
    }
    else {
        return res.status(404).json({ error: true, message: "Invalid game" });
    }
    const relevantData = extractRelevantData(gameHashes);
    return res.status(200).json(relevantData);
});
exports.getHashes = getHashes;
