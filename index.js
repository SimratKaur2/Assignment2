require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const mongodb = require('mongodb');

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

app.set("view engine", "ejs");

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

// function requireLogin(req, res, next) {
//   if (req.session.authenticated) {
//     //user is authenticated, so continue to the next middleware
//     next();
//   } else {
//     //user is redirected to the login page
//     console.log("you are not logged in");
//     res.redirect("/");
//   }
// }

function isValidSession(req) {
  return req.session.authenticated;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  return req.session.user_type === 'admin';
}

function adminAuthorization(req, res, next) {
  if (!(isAdmin(req))) {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  } else {
    next();
  }
}

app.get("/", (req, res) => {
  const username = req.session.username;
  const user = req.session.authenticated;
  res.render("home", {user : user, username: username});
});


app.get("/about", function (req, res) {
  var color = req.query.color;
  res.render("about", { color: color });
});

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
  res.render("signup");
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

app.get("/members", sessionValidation, (req, res) => {
  const user = req.session.username;
  res.render("members", { user: user });
});

app.use(express.static(__dirname + "/public"));

app.get("/login", (req, res) => {
  const emptyFields = req.query.emptyFields;
  res.render("login", { emptyFields: emptyFields });
});


app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ username: 1, _id: 1, user_type: 1 });
  const users = await result.toArray();
  // console.log(users);
  res.render("admin", { users: users });
});

//promoting a user to admin
app.get("/promote/:id",sessionValidation,adminAuthorization,async(req,res) => {
  const userId = req.params.id;
  await userCollection.updateOne({_id: new mongodb.ObjectId(userId)}, {$set: {user_type: "admin"}});
  res.redirect("/admin");
})

//demoting an admin to a user 
app.get("/demote/:id",sessionValidation,adminAuthorization,async(req,res) => {
  const userId = req.params.id;
  await userCollection.updateOne({_id: new mongodb.ObjectId(userId)}, {$set: {user_type: "user"}});
  res.redirect("/admin");
})


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
    .project({ username: 1, email: 1, password: 1, _id: 1, user_type: 1 })
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
    req.session.user_type = result[0].user_type; // set user_type in session
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
  res.render("invalidEmail");
});

app.post("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

module.exports = app;
