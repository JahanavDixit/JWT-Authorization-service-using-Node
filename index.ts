//Configurations && Libraries
const express = require('express')

const crypt = require('crypto');
const bodyParser = require('body-parser');
const originalString = 'password123';
const jwt = require('jsonwebtoken')
require('dotenv').config()
const app = express()
app.use(bodyParser.json())

let users = []

//Main Code
const authenticateToken = (req, res, next) => {

	let excludedPaths =  ['/','/doc','/auth/login','/auth/signup']

	if(excludedPaths.includes(req.path)) return next()

	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];
	if (!token) {
	  return res.status(401).send('Unauthorized');
	}
	jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
	  if (err) {
		return res.status(401).send('Unauthorized');
	  }
	  req.user = decoded;
	  next();
	});
  };

app.use(authenticateToken)

app.post('/auth/signup',(req,res)=>{

	let { login, password } = req.body;
  if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
    return res.status(400).send('Provided login or password is invalid');
  }
	password = crypt.createHash('sha256')
	.update(password)
	.digest('hex').toString();

	const user = { id: users.length + 1, login, password: password };
	users.push(user);

	res.status(201).send("User Created Sucessfully");
})

app.post('/auth/login',(req,res)=>{

	const {login,password} = req.body;

	if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
		return res.status(400).send('Invalid login or password');
	  }

	const user = users.find((u)=>u.login == login)

	if(!user)
	{
		return res.status(403).send("No User with this login and password")
	}

	const accessToken = jwt.sign({ userId: user.id, login: user.login }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1800' });
	const refreshToken = jwt.sign({ userId: user.id, login: user.login }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '3600' });
	return res.status(200).send({ accessToken, refreshToken });
})

app.post('/auth/refresh',(req,res)=>{

	const {refreshToken} = req.body; 

	if(!refreshToken) return res.status(401).send("No Refresh Token Provided")

	jwt.verify(refreshToken,process.env.REQUEST_TOKEN_SECRET,(err,decoded)=>{
		if(err)
		return res.status(403).send("Invalid Refresh Token Provided or Refresh Token Expired")
		else
		{
			const accessToken = jwt.sign({userId:decoded.id,login:decoded.login},process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1800' });
			const requestToken = jwt.sign({userId:decoded.id,login:decoded.login},process.env.REQUEST_TOKEN_SECRET, { expiresIn: '3600' });
			return res.status(200).send({accessToken,requestToken});
		}
	})
})

app.listen(3000, ()=>{console.log("Sever is running")});