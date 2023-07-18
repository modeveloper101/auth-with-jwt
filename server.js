const express = require("express");
const app = express();
//a library for hashing passwords
const bcrypt = require("bcrypt");
//to allow app to accept json content
app.use(express.json());
//to store users
const users = [];

//a route to get all the stored users
app.get("/users", (req, res) => {
  res.json(users);
});
//a route to create a user and store them
app.post("/users", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);//this method will hash the password and add salt to it
    const user = { name: req.body.name, password: hashedPassword };//store the our created user with the hashed password
    users.push(user);
    res.status(201).send({message: "User created successfully!"});
  } catch {
    res.status(500).send({error: "Failed to create a user"});
  }
});
//a route to authenticate user
app.post("/login", async (req, res) => {
  const user = users.find((user) => user.name === req.body.name);
  if (user == null) {
    return res.status(400).send({error: "User not found"});
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) { //using compare method will exclude the salt from the hashed password and compare the two passwords
      res.send({message:"Logged in successfully"});
    } else {
      res.send({message:"Wrong username or password. Please try again!"});
    }
  } catch {
    res.status(500).send({error: "Failed to login"});
  }
});

app.listen(3000);
