# About

Neurone-Auth is a node project that is part of the NEURONE Framewok. It serves as part of the back-end that provides a REST API for the end user's login, signup, account status check, using JWT. For more inforation see https://github.com/NEURONE-IL/neurone-core

To read the local API docs, check `http://localhost:3005/api-docs/` while the back-end is running, note that the port can be changed using env variables.

# Running the back-end

* Install the dependencies with `npm install`
* Run in dev mode with `npm run dev:server`
* Build in productin mode with `npm run build`
* Run in production mode with `npm run start`

# Env variables
```js
PORT: 3005 // port of the localhost
SECRET_KEY: a5bf6b766d6 // secret key for the jwt hash
SALT_ROUNDS: 10 // salt rounds for the password hash
TOKEN_DURATION: 7200, // seconds that the jwt will be valid
DB: "mongodb://127.0.0.1:27017/neurone" // link to the database
```