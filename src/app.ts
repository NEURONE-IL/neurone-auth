import 'dotenv/config';
import express from "express";
import mongoose from 'mongoose';

// Connect URL + db
const url = process.env.DB || 'mongodb://127.0.0.1:27017/test';


const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true})); // Parse URL-encoded bodies
const port = 3005;

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS" )
  next();
});


function connectToDB(){
  // Connect to MongoDB
  mongoose.connect(url, {}, (err) => {
      
    if (err) {
        console.log(err);
    } else {
      console.log(`MongoDB Connected: ${url}`);
    }
    
  });
}

mongoose.connection.on('error', err => {
  console.error(err);
  console.log("Retrying connection with database...");
  connectToDB();
});

connectToDB();

app.get('/', (req, res) => {
    res.send(`This is the neurone-auth backend on port ${port}!`);
});
app.listen(port, () => {
  return console.log(`server is listening on ${port}`);
});

app.use("/auth/", require('./routes/auth') );
