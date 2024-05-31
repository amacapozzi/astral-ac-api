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
exports.sendFileByName = exports.uploadFile = exports.upload = void 0;
const multer_1 = __importDefault(require("multer"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const crypto_1 = __importDefault(require("crypto"));
const storage = multer_1.default.diskStorage({
    destination: (_req, _file, cb) => {
        const uploadPath = path_1.default.join(process.cwd(), "src", "uploads");
        if (!fs_1.default.existsSync(uploadPath)) {
            fs_1.default.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (_req, file, cb) => {
        cb(null, file.originalname);
    },
});
exports.upload = (0, multer_1.default)({ storage });
function getFormattedLinkerTime(filePath) {
    if (!fs_1.default.existsSync(filePath)) {
        throw new Error("File not found");
    }
    const validExtensions = [".exe", ".dll"];
    const fileExtension = filePath.slice(-4).toLowerCase();
    if (!validExtensions.some((ext) => ext === fileExtension)) {
        throw new Error("Invalid file extension");
    }
    const c_PeHeaderOffset = 60;
    const c_LinkerTimestampOffset = 8;
    const buffer = Buffer.alloc(2048);
    const fd = fs_1.default.openSync(filePath, "r");
    fs_1.default.readSync(fd, buffer, 0, 2048, 0);
    fs_1.default.closeSync(fd);
    const offset = buffer.readUInt32LE(c_PeHeaderOffset);
    const timestamp = buffer.readUInt32LE(offset + c_LinkerTimestampOffset);
    const date = new Date(timestamp * 1000);
    const formattedTimestamp = date.toISOString().replace("T", ":").slice(0, 19);
    return formattedTimestamp;
}
function calculateHashes(filePath) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const fileInfo = yield getFormattedLinkerTime(filePath);
            const defaultFileInfo = fs_1.default.readFileSync(filePath);
            const fileStream = fs_1.default.createReadStream(filePath);
            const md5Hash = crypto_1.default.createHash("md5");
            fileStream.on("data", (data) => {
                md5Hash.update(data);
            });
            const sha256Hash = crypto_1.default.createHash("sha256");
            fileStream.on("data", (data) => {
                sha256Hash.update(data);
            });
            yield new Promise((resolve, reject) => {
                fileStream.on("end", () => {
                    resolve(true);
                });
                fileStream.on("error", (err) => {
                    reject(err);
                });
            });
            const md5Digest = md5Hash.digest("hex");
            const sha256Digest = sha256Hash.digest("hex");
            return {
                md5: md5Digest,
                size: defaultFileInfo.length,
                sha256: sha256Digest,
                fileInfo: `!${fileInfo.toString().replace("-", ":")}!`,
            };
        }
        catch (error) {
            console.error(error);
            return {
                error: true,
                message: `An error occurred while processing the file`,
            };
        }
    });
}
const uploadFile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (!req.file) {
        return res
            .status(400)
            .json({ error: true, message: "Please upload a file" });
    }
    const filePath = req.file.path;
    try {
        const fileInfo = yield calculateHashes(filePath);
        return res.status(200).json({ data: fileInfo });
    }
    catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            message: `An error occurred while processing the file`,
        });
    }
});
exports.uploadFile = uploadFile;
const sendFileByName = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { file } = req.query;
        if (!file)
            return res
                .status(400)
                .json({ error: true, message: "Please send a file name" });
        const fileDir = path_1.default.join(process.cwd(), "src", "dependencies", file.toString() + ".exe");
        if (!fs_1.default.existsSync(fileDir)) {
            return res.status(404).json({ error: true, message: "File not found" });
        }
        return res.download(fileDir);
    }
    catch (_a) {
        return res.status(500).json({
            error: true,
            message: "An error occurred while sending the dependency",
        });
    }
});
exports.sendFileByName = sendFileByName;
