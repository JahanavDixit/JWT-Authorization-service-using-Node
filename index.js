//Configurations && Libraries
var express = require('express');
var crypt = require('crypto');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
require('dotenv').config();
var app = express();
app.use(bodyParser.json());
var users = [];
//Main Code
/*
This is middleware function used to proxy routes which cannot be accessed without authorization.
Users need to pass in authorization header with access token in order to access the proxy route.
*/
var authenticateToken = function (req, res, next) {
    var excludedPaths = ['/', '/doc', '/auth/login', '/auth/signup']; //excluded path doesnt require authorization header
    if (excludedPaths.includes(req.path))
        return next();
    var authHeader = req.headers['authorization'];
    var token = authHeader && authHeader.split(' ')[1]; // check authorization on HTTP header and extract token
    if (!token) {
        return res.status(401).send('Unauthorized');
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, decoded) {
        if (err) {
            return res.status(401).send('Unauthorized');
        }
        req.user = decoded;
        next();
    });
};
app.use(authenticateToken); //Middleware to proxy all routes except the specified routes 
//Sign up route
/*
auth/signup route-
Users can post requests without any authorization.
This route is for servicing new users into the system or database.
This route is currently implemented using an array but the user data can also be stored into a database.
Password field stored into the storage unit(database, local array) is enrypted using Crypt and the algorithm used for the following task is 256 bit sha.
*/
app.post('/auth/signup', function (req, res) {
    var _a = req.body, login = _a.login, password = _a.password;
    if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
        return res.status(400).send('Provided login or password is invalid');
    }
    password = crypt.createHash('sha256') //Password hashed using sha256
        .update(password)
        .digest('hex').toString();
    var user = { id: users.length + 1, login: login, password: password };
    users.push(user);
    return res.status(201).send("User Created Sucessfully");
});
//Login Route
/*
auth/login route-
Route used for logging in and providing authorization tokens to already registered users.
Users need to provide the username and password which they used while registering to obtain access tokens for authorization.
*/
app.post('/auth/login', function (req, res) {
    var _a = req.body, login = _a.login, password = _a.password;
    if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
        return res.status(400).send('Invalid login or password');
    }
    var user = users.find(function (u) { return u.login == login; });
    if (!user) {
        return res.status(403).send("No User with this login and password");
    }
    var accessToken = jwt.sign({ userId: user.id, login: user.login }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1800' });
    var refreshToken = jwt.sign({ userId: user.id, login: user.login }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '3600' });
    return res.status(200).send({ accessToken: accessToken, refreshToken: refreshToken });
});
//Refresh Route
/*
auth/refresh route-
Used to obtain new access and refresh tokens by providing current referesh tokens to replace expired tokens.
*/
app.post('/auth/refresh', function (req, res) {
    var refreshToken = req.body.refreshToken;
    if (!refreshToken)
        return res.status(401).send("No Refresh Token Provided");
    jwt.verify(refreshToken, process.env.REQUEST_TOKEN_SECRET, function (err, decoded) {
        if (err)
            return res.status(403).send("Invalid Refresh Token Provided or Refresh Token Expired");
        else {
            var accessToken = jwt.sign({ userId: decoded.id, login: decoded.login }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1800' });
            //new accessToken
            var requestToken = jwt.sign({ userId: decoded.id, login: decoded.login }, process.env.REQUEST_TOKEN_SECRET, { expiresIn: '3600' });
            //new requestToken
            return res.status(200).send({ accessToken: accessToken, requestToken: requestToken });
        }
    });
});
app.listen(3000, function () { console.log("Sever is running"); });
