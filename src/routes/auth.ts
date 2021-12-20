import express, { application } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const checkAuth = require("../middleware/check-auth");
const User = require('../models/user');

const router = express.Router();

const saltRounds = 15;
// TODO: refactor to use global 
const secret = "udmen3kdfov8n4d6h0kogkm3c469j0torjg3flno6957dfgfh044";

router.post("/signup", (req, res, next) => {
  if (req.body.email && req.body.password){

    bcrypt.hash(req.body.password, saltRounds)
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

router.post("/login", (req, res, next) => {

    if (!req.body.email || !req.body.password){
      return res.status(401).json({
        message: "Auth Failed"
      });
    }

    let fetchedUser: any;
    User.findOne({ email: req.body.email }).then((user: any) => {
      if (!user) {
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
        return res.status(401).json({
          message: "Auth Failed"
        });
      }

      // web token for authentication, only when the auth didn't fail
      const token = jwt.sign({email: fetchedUser.email, userId: fetchedUser._id}, /*global.*/secret, { expiresIn: "1h" });
      console.log("Login successful - " + fetchedUser.email + " - token: " + token);
      console.log("-----------\n" + fetchedUser + "\n-------------------");
      res.status(200).json({
        token: token,
        expiresIn: 3600, // seconds
        userId: fetchedUser._id
      })
    })
    .catch((err: any) => {
      console.error("Server error in login:\n" + err);
    })
});

// TODO: check how to help other components know the current user (probably the login info will be enough)
router.post("/checkauth", checkAuth, (req, res, next) => {
  res.status(200).json({ message: "OK" });
})

router.get("/login", (req, res, next) => {
  res.status(200).json({message: "All is well"});
});

module.exports = router;