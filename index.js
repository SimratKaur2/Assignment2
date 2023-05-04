require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = require("./databaseConnection.js");

const userCollection = database.db(mongodb_database).collection("users");

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
  collectionName: "sessions",
  ttl: expireTime / 1000,
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

/*functions */

function requireLogin(req, res, next) {
  if (req.session.authenticated) {
    //user is authenticated, so continue to the next middleware
    next();
  } else {
    //user is redirected to the login page
    console.log("you are not logged in");
    res.redirect("/");
  }
}

app.get("/", (req, res) => {
  const user = req.session.authenticated;

  if (!user) {
    //user is not logged in
    var html = `
        <ul>
          <li><a href="/signUp">Sign Up</a></li>
          <li><a href="/login">Login</a></li>
        </ul>
        `;
    res.send(html);
  } else {
    //user is logged in
    const html = `
      <style>
      ul {
        list-style: none; /* Remove bullet points */

      }
      button {
        display: block; /* Display the buttons on different lines */
      }
    </style>
      <h1>Hello, ${req.session.username}!</h1>
      <p>Welcome back to our website!</p>
      <ul>
        <li>
        <form action = "/members">
        <button type="submit">Go to Members Area</button>
        </form>
        </li>
        <li>
          <form action="/logout" method="post">
            <button type="submit">Log Out</button>
          </form>
        </li>
      </ul>
    `;
    res.send(html);
  }
});

app.get('/home', (req,res) => {
  res.render('home');
})

app.get('/contact', (req,res) => {
  var missingEmail = req.query.missing;

  res.render('contact', {missing: missingEmail});
})

app.post('/submitEmail', (req,res) => {
  var email = req.body.email;
  if(!email) {
    res.redirect('/contact?missing=1');
  } else {
    res.render('submitEmail', {email: email});
  }
})

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/signUp", (req, res) => {
  var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='name'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.get("/error", (req, res) => {
  const missingName = req.query.missingName;
  const missingEmail = req.query.missingEmail;
  const missingPassword = req.query.missingPassword;
  let errorMessage = "";

  if (missingName) {
    errorMessage += "Name is required.<br>";
  }
  if (missingEmail) {
    errorMessage += "Email is required.<br>";
  }
  if (missingPassword) {
    errorMessage += "Password is required.<br>";
  }

  const html = `
      <h1>Error</h1>
      <p>${errorMessage}</p>
      <a href="/signUp">Try Again</a>
    `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  // Check if any fields are empty and redirect to error page if necessary
  if (!username || !email || !password) {
    let redirectUrl = "/error?";
    if (!username) {
      redirectUrl += "missingName=1&";
    }
    if (!email) {
      redirectUrl += "missingEmail=1&";
    }
    if (!password) {
      redirectUrl += "missingPassword=1&";
    }
    res.redirect(redirectUrl);
    return;
  }

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signUp");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user");

  //create session for the new user
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = email;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

const path = require("path");

function randomImage() {
  const images = [
    "gif1.gif",
    "gif2.gif",
    "gif3.gif",
    "gif4.gif",
    "gif5.gif",
    "gif6.gif",
    "gif7.gif",
    "gif8.gif",
    "gif9.gif",
    "gif10.gif",
  ];
  const imageIndex = Math.floor(Math.random() * images.length);
  const randomImage = images[imageIndex];
  return randomImage;
}

app.get("/members", requireLogin, (req, res) => {
  user = req.session.username;
  const image = randomImage();
  var html = `
      <h1>Hello ${user},</h1>
      <img src='/${image}' style='width:250px;'><br>
      <form action='/logout' method='post'><br>
      <button>Sign Out</button>
      </form>
      `;
  res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("/login", (req, res) => {
  const emptyFields = req.query.emptyFields;

  var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
  if (emptyFields) {
    html +=
      "<span style='color:red;'>Email and password is required.</span><br>";
  }
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!email || !password) {
    res.redirect("/login?emptyFields=1");
    return;
  }

  const schema = Joi.string().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user email not found");
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    console.log("incorrect password");
    res.redirect("/loginSubmit");
    return;
  }
});

app.get("/loginSubmit", (req, res) => {
  var html = `
      Invalid email/password combination.<br>
      <a href="/login">Try Again</a>
      `;
  res.send(html);
});

app.post("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

module.exports = app;
