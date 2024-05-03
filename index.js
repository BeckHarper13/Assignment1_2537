
require("./utils.js");

const express = require('express');
require('dotenv').config();

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user =process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_database = process.env.MONGODB_DATABASE;

const Joi = require("joi");
const app = express();
const port = process.env.PORT || 3000;
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 12;




const MongoStore = require('connect-mongo');


var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})


var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

const expireTime = 24 * 60 * 60 * 1000;


app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}))



app.use(express.urlencoded({extended: false}));

var users = [];
app.get('/', (req, res) => {
    var logged = req.query.login;
    var name = req.session.username;
    if (logged){
        var html = `
        
        Welcome to our webpage, ${name}!
        <form action='/members' method='get'>
        <button>Go to Members</button>
        </form>
        <form action='/logout' method='get'>
        <button>Logout</button>
        </form>
        
        `

    } else {
        var html = `
        
        Welcome to our webpage
        <form action='/signup' method='get'>
        <button>SignUp</button>
        </form>
        <form action='/login' method='get'>
        <button>Login</button>
        </form>
        
    `;

    }
    
    res.send(html);
});


app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});






app.get('/signup', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'><br>
    <input name ='email' type = 'text' placeholder ='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    if (missingEmail){
        html += "<br>Email and password are required</br>";
    }
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;


    const schema = Joi.object(
		{
            email: Joi.string(),
			username: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup?missing=1");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Inserted user");

    res.redirect('/');
    return//res.redirect('/home');

    /*
    if (!username || !password || !email){
        res.redirect('/signup?missing=1')
    } else {

        var hashedPassword = bcrypt.hashSync(password, saltRounds);
        users.push({username: username, email: email, password: hashedPassword });
        res.redirect('/home');
    console.log(users);

    }*/
    
});

app.get('/login', (req,res) => {
    var error = req.query.error;
    var html = "";
    if(error){
        html += "Error. Login Failed";

    }
    html += `
    <br>log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>

    <form action='/' method='get'>
    <button>Back to Home</button>
    </form>
    `;
    res.send(html);
});


app.post('/loggingin', async (req,res) => {

    var username = req.body.username;
    var password = req.body.password;
    
    const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login?error=1");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/?login=1');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login?error=1");
		return;
	}

    /*
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    var usershtml = "";
    for(i = 0; i < users.length; i++){
        if (users[i].username ==username){
            if(bcrypt.compareSync(password, users[i].password)){
                res.redirect('/home?login=1')
                return;
            }
        }
    }

    res.redirect('/login?error=1');*/
});


app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/home');
    
});



app.get('/members', (req,res) => {
    if (req.session.authenticated){
        var name = req.session.username;
        let game = Math.floor(Math.random() * 3);
        console.log(game);
        var html = `
        Welcome to our webpage, ${name}!
        <br>
        `

        if (game == 0) {
        html += ("<img src='/mario.png' style='width:250px;'>");
        }
        else if (game == 1){
            html += ("<img src='/mike.png' style='width:250px;'>");
        } else {
            html += ("<img src='/burger.png' style='width:250px;'>");
        }
        res.send(html);

    } else {
        res.redirect('/');

    }
    
    
});

app.use(express.static(__dirname + "/public"));


app.get("*", (req,res) => {
    res.status(404);
    res.send("ERROR 404: Page Not Found");
})
app.listen(port, () => {
    console.log('Server running on port' + port);
});