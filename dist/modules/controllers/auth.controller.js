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
exports.startScan = void 0;
const auth_service_1 = require("../services/auth.service");
const db_1 = __importDefault(require("../../lib/db"));
const startScan = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const pin = req.query.pin;
        if (!pin) {
            return res
                .status(404)
                .json({ error: true, message: "Please enter a pin" });
        }
        const isValid = yield (0, auth_service_1.checkIsValidPin)(pin.toString());
        if (!isValid) {
            return res.status(400).json({ error: true, message: "Invalid pin" });
        }
        if (isValid.used) {
            return res.status(400).json({ error: true, message: "Pin already used" });
        }
        yield db_1.default.pin.updateMany({
            where: { pin: pin.toString() },
            data: {
                used: true,
            },
        });
        return res
            .status(200)
            .json({ error: false, message: "Scan started successfully" });
    }
    catch (err) {
        console.log(err);
        return res
            .status(500)
            .json({ error: true, message: "Internal server error" });
    }
});
exports.startScan = startScan;
