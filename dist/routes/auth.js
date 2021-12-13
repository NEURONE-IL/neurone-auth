"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = __importDefault(require("express"));
var bcrypt_1 = __importDefault(require("bcrypt"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var User = require('../models/user');
var router = express_1.default.Router();
var saltRounds = 15;
router.post("/signup", function (req, res, next) {
    if (req.body.email && req.body.password) {
        bcrypt_1.default.hash(req.body.password, saltRounds)
            .then(function (hash) {
            var user = new User({
                email: req.body.email,
                password: hash,
            });
            user.save()
                .then(function (result) {
                res.status(201).json({
                    message: "created",
                    result: result
                });
            })
                .catch(function (err) {
                res.status(500).json({
                    error: err
                });
            });
        });
    }
    else {
        res.status(500).json({
            message: "Error reding auth data sent."
        });
    }
});
router.post("/login", function (req, res, next) {
    var fetchedUser;
    User.findOne({ email: req.body.email }).then(function (user) {
        if (!user) {
            return res.status(401).json({ message: "Auth failed" });
        }
        fetchedUser = user;
        // compared sent password with password in data base
        return bcrypt_1.default.compare(req.body.password, user.password);
    })
        .then(function (result) {
        if (!result) {
            return res.status(401).json({
                message: "Auth Failed"
            });
        }
        // web token for authentication, only when the auth didn't fail
        var token = jsonwebtoken_1.default.sign({ email: fetchedUser.email, userId: fetchedUser._id }, global.secret, { expiresIn: "1h" });
        console.log("Login successful - " + fetchedUser.email + " - token: " + token);
        res.status(200).json({
            token: token,
            expiresIn: 3600,
            userId: fetchedUser._id
        });
    })
        .catch(function (err) {
        return res.status(401).json({
            meesage: "Auth Failed"
        });
    });
});
router.get("/login", function (req, res, next) {
    res.status(200).json({ message: "All is well" });
});
module.exports = router;
