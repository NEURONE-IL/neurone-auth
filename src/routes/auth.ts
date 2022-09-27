import 'dotenv/config';
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const checkAuth = require("../middleware/check-auth");
import User from '../models/user';
import LogUser from "../models/log-users";

import useragent from 'useragent';

const router = express.Router();

router.post("/signup", async (req, res, next) => {

  // default salt rounds
  let saltRounds = 2;
  try {
    // check if there is a salt round variable in the env and try to parse it as int
    if (process.env.SALT_ROUNDS){
      const envSalt = parseInt(process.env.SALT_ROUNDS);
      if (!isNaN(envSalt)){
        saltRounds = envSalt;
      }
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({message: "Error while creating user."});
    return;
  }

  if (req.body.username && req.body.password){

    try {
      const hash = await bcrypt.hash(req.body.password, saltRounds);

      const user = new User({
        username: req.body.username,
        email: req.body.email,
        password: hash,
      });

      const result = await user.save();

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
      const resultLog = userLog.save();
      console.log("Log data of created user:");
      console.log(resultLog);

      res.status(201).json({
        message: "Profile created",
        result: result
      })

      
    } catch(err:any) {
      if (err.errors.username && err.errors.username.kind === 'unique'){
        console.log("Username is not unique:", err.errors.username.value);
        res.status(500).json({
          message: "Username already taken.",
          error: err
        });
        return;
      }

      console.error(err);
      res.status(500).json({
        message: "Error in server",
        error: err
      })
    }
  }

});

router.post("/login", async (req, res, next) => {

    if (!req.body.username || !req.body.password){
      console.error("No username or password provided");
      return res.status(401).json({
        message: "Auth Failed"
      });
    }

    let fetchedUser: any;
    try {
      const user = await User.findOne({ username: req.body.username });
      if (!user) {
        console.error("No user found with this username");
        return res.status(401).json({message: "Auth failed"});
      }

      fetchedUser = user;
      console.log(user);
      // no user found
      if (!fetchedUser) {
        return;
      }

      // compared sent password with password in data base
      const result = await bcrypt.compare(req.body.password, user.password);

      // compare failed
      if (!result) {
        console.error("Comparing password failed");
        return res.status(401).json({
          message: "Auth Failed"
        });
      }

      let secret_key: string;
      if (!process.env.SECRET_KEY){
        secret_key = '1234';
        console.warn("WARNING: No secret found. Please use the environment variable 'SECRET_KEY' to set it. Currently using '"+ secret_key +"'.");
      } else {
        secret_key = process.env.SECRET_KEY;
      }

      // get duration of the token in seconds from env or use the default 3600 seconds (1 hour)
      const DEFAULT_EXP_SECS = "3600";
      let expiration = parseInt(process.env.TOKEN_DURATION ? process.env.TOKEN_DURATION : DEFAULT_EXP_SECS);
      if (isNaN(expiration)) {
        console.log("Could not read number of seconds in env variable 'TOKEN_DURATION'. Using default 3600 seconds.");
        expiration = parseInt(DEFAULT_EXP_SECS);
      }


      // web token for authentication, only when the auth didn't fail
      const token = jwt.sign({ username: fetchedUser.username, userId: fetchedUser._id }, secret_key, { expiresIn: expiration + " seconds"});
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
      const resultLog = await userLog.save();
      console.log("Log data of logged in user:");
      console.log(resultLog);

      res.status(200).json({
        token: token,
        expiresIn: expiration, // seconds
        userId: fetchedUser._id,
        username: fetchedUser.username,
        email: fetchedUser.email
      });

    } catch (err) {
      console.error("Server error in login:\n" + err);
    }

});

router.post("/logout", async (req, res) => {

  try {
    // find user in db to save their email
    const result = await User.findById(req.body.userId);

    // create log data
    const userLog = new LogUser({
      userId: req.body.userId,
      email: result?.email ? result.email : "",
      clientDate: req.body.clientDate,
      serverDate: Date.now(),
      type: "logout",
      userAgent: useragent.parse(req.headers['user-agent']).toString()
    });

    // save log data
    const resultLog = await userLog.save();
    console.log("Log data of logged out user:");
    console.log(resultLog);
    res.status(200).json({ message: "Log data saved." });

  } catch (err) {
    console.log("Error saving log data of the user:");
    console.error(err);
    res.status(500).json({ message: "Error saving log data." });
  }

});

router.post("/checkauth", checkAuth, (req, res, next) => {
  res.status(200).json({ message: "OK" });
})

module.exports = router;