"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = __importDefault(require("express"));
var app = (0, express_1.default)();
var port = 3005;
app.get('/', function (req, res) {
    res.send("This is the neurone-auth backend on port " + port + "!");
});
app.listen(port, function () {
    return console.log("server is listening on " + port);
});
