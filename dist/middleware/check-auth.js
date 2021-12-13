"use strict";
var jwt = require("jsonwebtoken");
module.exports = function (req, res, next) {
    // pattern of the token in the header file: "Bearer <token here>"
    try {
        var token = req.headers.authorization.split(" ")[1];
        var decodedToken = jwt.verify(token, global.secret);
        req.userData = { email: decodedToken.email, userId: decodedToken.userId };
        next();
    }
    catch (error) {
        res.status(401).json({ message: "Auth failed [check-auth]" });
    }
};
