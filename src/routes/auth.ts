import 'dotenv/config';
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import checkAuth from "../middleware/check-auth";
import User from '../models/user';
import LogUser from "../models/log-users";

import useragent from 'useragent';

const router = express.Router();


/**
 * @swagger
 * components:
 *  schemas:
 *    UserCreated:
 *      type: object
 *      properties:
 *        message:
 *          type: string
 *          description: A message that provides general information about the request result
 *        result:
 *          type: object
 *          properties:
 *            username:
 *              type: string
 *              description: the username saved in the database
 *            email:
 *              type: string
 *              description: the email saved in the database
 *      required:
 *        - message
 *        - result
 *      example:
 *        message: User Created Successfully
 *        result: { "username": "john", "email": "john@asdf.com" }
 * 
 *    UserLoginData:
 *      type: object
 *      properties:
 *        token:
 *          type: string
 *          description: Token to be used in header as 
 *        expiresIn:
 *          type: number
 *          description: The ammounts of seconds that the token will be valid
 *        userId:
 *          type: string
 *          description: The ID of the user in the Mongo database
 *        username:
 *          type: string
 *          description: The account's username
 *        email:
 *          type: string
 *          description: The account's registered email
 * 
 *    UserCreateData:
 *      type: object
 *      properties:
 *        username:
 *          type: string
 *          description: The username to identify the account
 *        password:
 *          type: string
 *          description: The password to access the accound
 *        email:
 *          type: string
 *          description: The email for associated to the account (optional)
 *        
 *    UserAccessData:    
 *      type: object
 *      properties:
 *        username:
 *          type: string
 *          description: The username to identify the account
 *        password:
 *          type: string
 *          description: The password to access the accound
 */

/**
 * @swagger
 * tags:
 *  name: Auth
 *  description: User authentication management
 */

/**
 * @swagger
 * /auth/signup:
 *  post:
 *    summary: Create an user account
 *    tags: [Auth]
 *    requestBody:
 *      required: true
 *      content: 
 *        application/json:
 *          schema:
 *            $ref: '#/components/schemas/UserCreateData'
 *    responses:
 *      201:
 *        description: Created user successfully
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/UserCreated'
 *      409:
 *        description: Username is already taken
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: Message describing the error
 *            example:
 *              message: Username already taken.
 *      500:
 *        description: Error while creating user
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: A message that provides general information about the error
 *                error:
 *                  type: string
 *                  description: The error originated from the server
 *      
 */
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
      else {
        console.error(`Env salt rounds could not be parsed, using default value of ${saltRounds} instead.`);
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
      const resultLog = await userLog.save();
      console.log("Log data of created user:");
      console.log(resultLog);

      res.status(201).json({
        message: "Profile created",
        result: {
          username: result.username,
          email: result.username,
        }
      })

      
    } catch(err:any) {
      if (err.errors.username && err.errors.username.kind === 'unique'){
        console.error("Username is not unique:", err.errors.username.value);
        console.error(err);
        res.status(409).json({
          message: "Username already taken.",
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


/**
 * @swagger
 * /auth/login:
 *  post:
 *    summary: Log into an user account, receiving a jwt to validate the session
 *    tags: [Auth]
 *    requestBody:
 *      required: true
 *      content: 
 *        application/json:
 *          schema:
 *            $ref: '#/components/schemas/UserAccessData'
 *    responses:
 *      200:
 *        description: Logged in successfully
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/UserLoginData'
 *      401:
 *        description: The authentication credentials are not correct
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: A message that provides general information about the error
 *      500:
 *        description: Server error when accessing the user account
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: A message that provides general information about the error
 */
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
        return res.status(401).json({message: "Wrong username or password"});
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
          message: "Wrong username or password"
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
      res.status(500).json({ message: "Error accessing the user account." });
    }

});


/**
 * @swagger
 * /auth/logout:
 *  post:
 *    summary: Logout of account, used for log purposess since technically the jwt will be valid until the time expires
 *    tags: [Auth]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            properties:
 *              userId:
 *                type: string
 *                description: ID of the user in Mongo
 *              clientDate:
 *                type: number
 *                description: The epoch time when the user requested the logout from the client (with JS -> Date.now())
 *            example:
 *              userId: 6335af3bff8aac365c288d24
 *              clientDate: 1664485966750
 *    responses:
 *      200:
 *        description: Successfully logged user logging out
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: Message describing the operation
 *      500:
 *        description: Error while loggin the user logout
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: A message that provides general information about the error
 *  
 */
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


/**
 * @swagger
 * /auth/checkauth:
 *  post:
 *    summary: "Check if the user is logged in using the jwt in the header of the request. Add it like this in js: {Authorization: 'Bearer ' + authToken}"
 *    description: This can be used by other back-ends to check if the user session is still valid. Used heavily on the NEURONE framework by Neurone-Profile.
 *    tags: [Auth]
 *    responses:
 *      200:
 *        description: Session is valid (jwt token passed)
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: Message notifying the success
 *      401:
 *        description: "jwt could not be verified properly, please make sure it's set in the header properly like this: {Authorization: 'Bearer ' + authToken}"
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  description: Message notifying the failure
 */
router.post("/checkauth", checkAuth, (req, res, next) => {
  res.status(200).json({ message: "OK" });
})

module.exports = router;