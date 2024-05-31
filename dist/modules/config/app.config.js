"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.appConfig = void 0;
require("dotenv/config");
exports.appConfig = {
    port: process.env.PORT || 3000,
};
