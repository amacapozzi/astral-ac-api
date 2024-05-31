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
exports.apiMiddleware = void 0;
const crypto_js_1 = __importDefault(require("crypto-js"));
const apiMiddleware = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const headers = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(" ")[1];
    const bytes = crypto_js_1.default.AES.decrypt(headers === null || headers === void 0 ? void 0 : headers.toString(), "0a]lvd$f5dmfrz&");
    const plainText = bytes.toString(crypto_js_1.default.enc.Utf8);
    if (plainText !== "8LUVNsJ1jCTf7Wfs9ZUj3uPS0wogci7Y") {
        return res.status(400).send("Unauthorized");
    }
    return next();
});
exports.apiMiddleware = apiMiddleware;
