import express, { application } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Error, Schema } from "mongoose";

const checkAuth = require("../middleware/check-auth");
const User = require('../models/user');
const LogUser = require("../models/log-users");

const useragent = require('useragent');

const router = express.Router();

const saltRounds = 15;
// TODO: refactor to use global 
const secret = "udmen3kdfov8n4d6h0kogkm3c469j0torjg3flno6957dfgfh044";

router.post("/signup", (req, res, next) => {
  if (req.body.username && req.body.password){

    bcrypt.hash(req.body.password, saltRounds)
      .then( hash => {
        const user = new User({
          username: req.body.username,
          email: req.body.email,
          password: hash,
        });
        user.save()
        .then((result: any) => {

          // create log data
          const userLog = new LogUser({
            userId: result._id,
            username: result.username,
            email: result.email,
            clientTimestamp: req.body.clientDate, // same as clientDate
            serverTimestamp: Date.now(),
            clientDate: req.body.clientDate,
            serverDate: Date.now(),
            type: "created account",
            userAgent: useragent.parse(req.headers['user-agent']).toString(),
            userAgentRaw: req.headers['user-agent']
          });

          // save log data
          userLog.save().then( (result: any) => {
            console.log("Log data of created user:");
            console.log(result);
          }).catch((err: Error) => {
            console.log("Error saving log data of the user:");
            console.log(userLog);
            console.error(err);
          });

          res.status(201).json({
            message: "Profile created",
            result: result
            })
          })
          .catch( (err: any) => {
            console.error(err);
            res.status(500).json({
              error: err
              })
            })
      })
  } else {
    res.status(500).json({
      message: "Error reding auth data sent."
    });
  }

});

router.post("/login", (req, res, next) => {

    if (!req.body.username || !req.body.password){
      console.error("No username or password provided");
      return res.status(401).json({
        message: "Auth Failed"
      });
    }

    let fetchedUser: any;
    User.findOne({ username: req.body.username }).then((user: any) => {
      if (!user) {
        console.error("No user found with this username");
        return res.status(401).json({message: "Auth failed"});
      }

      fetchedUser = user;
      console.log(user);
      // compared sent password with password in data base
      return bcrypt.compare(req.body.password, user.password)
    })
    .then((result: any) => {

      // no user found
      if (!fetchedUser) {
        return;
      }

      // compare failed
      if (!result) {
        console.error("Comparing password failed");
        return res.status(401).json({
          message: "Auth Failed"
        });
      }

      // web token for authentication, only when the auth didn't fail
      const token = jwt.sign({ username: fetchedUser.username, userId: fetchedUser._id }, /*global.*/secret, { expiresIn: "1h" });
      console.log("Login successful - " + fetchedUser.username + " - token: " + token);
      console.log("-----------\n" + fetchedUser + "\n-------------------");

      // create log data
      const userLog = new LogUser({
        userId: fetchedUser._id,
        username: fetchedUser.username,
        email: fetchedUser.email,
        clientTimestamp: req.body.clientDate, // same as clientDate
        serverTimestamp: Date.now(),
        clientDate: req.body.clientDate,
        serverDate: Date.now(),
        type: "login",
        userAgent: useragent.parse(req.headers['user-agent']).toString(),
        userAgentRaw: req.headers['user-agent']
      });

      // save log data
      userLog.save().then( (result: any) => {
        console.log("Log data of logged in user:");
        console.log(result);
      }).catch((err: Error) => {
        console.log("Error saving log data of the user:");
        console.log(userLog);
        console.error(err);
      });

      res.status(200).json({
        token: token,
        expiresIn: 3600, // seconds
        userId: fetchedUser._id,
        username: fetchedUser.username,
        email: fetchedUser.email
      })
    })
    .catch((err: any) => {
      console.error("Server error in login:\n" + err);
    })
});

router.post("/logout", (req, res) => {

  // find user in db to save their email
  User.findById(req.body.userId).then((result: any) => {

    // create log data
    const userLog = new LogUser({
      userId: req.body.userId,
      email: result.email,
      clientDate: req.body.clientDate,
      serverDate: Date.now(),
      type: "logout",
      userAgent: useragent.parse(req.headers['user-agent']).toString()
    });

    // save log data
    userLog.save().then( (result: any) => {

      console.log("Log data of logged out user:");
      console.log(result);
      res.status(200).json({ message: "Log data saved." });

    }).catch((err: Error) => {

      console.log("Error saving log data of the user:");
      console.log(userLog);
      console.error(err);
      res.status(500).json({ message: "Error saving log data." });

    });

  }).catch((error: any) => {
    if(!res.headersSent) {
      console.log(error);
      res.status(500).json({ message: "Error saving log data." });
    }
  })
});

// TODO: check how to help other components know the current user (probably the login info will be enough)
router.post("/checkauth", checkAuth, (req, res, next) => {
  res.status(200).json({ message: "OK" });
})

module.exports = router;