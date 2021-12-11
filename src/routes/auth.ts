import express, { application } from "express";
import mongoose from 'mongoose';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const User = require('../models/user');

const router = express.Router();

router.post("/signup", (req, res, next) => {

    if (req.body.email && req.body.password){

        bcrypt.hash(req.body.password, 11)
            .then( hash => {
                const user = new User({
                    email: req.body.email,
                    password: hash,
                });
                user.save()
                    .then((result: any) => {
                        res.status(201).json({
                            message: "created",
                            result: result
                        })
                    })
                    .catch( (err: any) => {
                        res.status(500).json({
                            error: err
                        })
                    })
            })
    } else {
        res.status(500).json({
            message: "Error reding auth data sent."
        })
    }

});

router.get("/login", (req, res, next) => {
    res.status(200).json({message: "All is well"});
});

module.exports = router;