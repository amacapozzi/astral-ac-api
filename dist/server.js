"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const app_config_1 = require("./modules/config/app.config");
const app_1 = require("./app");
app_1.app.listen(app_config_1.appConfig.port, () => {
    console.log(`Server ready in port ${app_config_1.appConfig.port}`);
});
