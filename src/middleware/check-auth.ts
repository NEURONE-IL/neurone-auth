import jwt from "jsonwebtoken";



export default (req:any, res:any, next:any) => {

  const secret = process.env.SECRET_KEY || '1234';
    
  // pattern of the token in the header file: "Bearer <token here>"
  try{
    const token = req.headers.authorization.split(" ")[1];

    const decodedToken: any = jwt.verify(token, secret);
    req.userData = { username: decodedToken.username, userId: decodedToken.userId }
    next();
  } catch (error) {
    res.status(401).json({message: "Auth failed [check-auth]"});
  }

}
