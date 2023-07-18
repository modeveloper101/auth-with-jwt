require("dotenv").config();

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

app.use(express.json());
//to store users
const users = [];

const blogs = [
  {
    author: "Moe",
    title: "Benefits of using JWT for authentication",
  },
  {
    author: "Joe",
    title: "10 Reasons to start coding",
  },
];

let refreshTokens = [];

//a route to get all the stored users
app.get("/users", (req, res) => {
  res.json(users);
});
//a route to create a user and store them
app.post("/users", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10); //this method will hash the password and add salt to it
    const user = { username: req.body.username, password: hashedPassword }; //store the our created user with the hashed password
    users.push(user);
    res.status(201).send({ message: "User created successfully!" });
  } catch {
    res.status(500).send({ error: "Failed to create a user" });
  }
});
//TODO: move to authServer
//a route to create a new token
app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.SECRET_REFRESH_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ username: user.username });
    res.json({ accessToken: accessToken });
  });
});
//TODO: move to authServer
//a route to authenticate user
app.post("/login", async (req, res) => {
  const user = users.find((user) => user.username === req.body.username);
  if (user == null) {
    return res.status(400).send({ error: "User not found" });
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      //using compare method will exclude the salt from the hashed password and compare the two passwords
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user, process.env.SECRET_REFRESH_TOKEN);
      refreshTokens.push(refreshToken);
      res.json({
        accessToken: accessToken,
        refreshToken: refreshToken,
        message: "Logged in successfully!",
      });
    } else {
      res.send({ message: "Wrong username or password. Please try again!" });
    }
  } catch {
    res.status(500).send({ error: "Failed to login" });
  }
});
//TODO: move to authServer
//a function to generate access token
function generateAccessToken(user) {
  return jwt.sign(user, process.env.SECRET_ACCESS_TOKEN, { expiresIn: "20s" });
}
//a route to get blogs
app.get("/blogs", authenticateToken, (req, res) => {
  //calling middleware to authenticate the token before access resources
  res.json(blogs.filter((blog) => blog.author === req.user.username));
});
//middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.SECRET_ACCESS_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(3000);
