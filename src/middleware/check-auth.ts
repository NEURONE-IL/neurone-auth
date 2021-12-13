const jwt = require("jsonwebtoken");



module.exports = (req:any, res:any, next:any) => {
  // TODO: refactor to use global 
  const secret = "udmen3kdfov8n4d6h0kogkm3c469j0torjg3flno6957dfgfh044";
    
  // pattern of the token in the header file: "Bearer <token here>"
  try{
    const token = req.headers.authorization.split(" ")[1];
    const decodedToken = jwt.verify(token, /*global.*/secret);
    req.userData = { email: decodedToken.email, userId: decodedToken.userId }
    next();
  } catch (error) {
    res.status(401).json({message: "Auth failed [check-auth]"});
  }

}
