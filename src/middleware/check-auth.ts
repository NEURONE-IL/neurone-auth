const jwt = require("jsonwebtoken");



export default (req:any, res:any, next:any) => {

  const secret = process.env.SECRET_KEY || '';
    
  // pattern of the token in the header file: "Bearer <token here>"
  try{
    // TODO: evaluate if we should always use the header for this
    //const token = req.headers.authorization.split(" ")[1];

    const token = req.body.jwt;
    const decodedToken = jwt.verify(token, secret);
    req.userData = { username: decodedToken.username, userId: decodedToken.userId }
    next();
  } catch (error) {
    res.status(401).json({message: "Auth failed [check-auth]"});
  }

}
