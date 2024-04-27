const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const secretKey = "secretKey";

const sql = require("mssql");
const { get } = require("http");
const getConnection = require("../connection/config");

/**
 * @swagger
 * /user:
 *   get:
 *     summary: Retrieve a list of user
 *     description: Endpoint to get information about all user. Requires JWT authentication.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of user
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/user'
 *       401:
 *         description: Unauthorized access - No token provided or token is invalid
 */

app.get("/users", async (req, res) => {
  try {
    // Check if token is valid
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).send("No token provided");
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, secretKey); // Verify the token synchronously

    // Get user from database
    const request = new sql.Request();
    const result = await request.query("SELECT * FROM [dbo].[user]");
    console.log(result.recordset);
    res.send(result.recordset); // Send the result
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).send("Invalid token");
    }
    console.error(err);
    return res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /signup:
 *   post:
 *     summary: Sign up a new user
 *     description: Allows a new user to sign up by providing a username, password, and email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *               - email
 *             properties:
 *               username:
 *                 type: string
 *                 description: Unique username for the user
 *               password:
 *                 type: string
 *                 description: Password for the user account
 *               email:
 *                 type: string
 *                 description: Email address of the user
 *     responses:
 *       200:
 *         description: User successfully signed up and JWT token generated
 *       400:
 *         description: Username or email already taken
 *       500:
 *         description: Internal Server Error
 */
//signup
//signup
app.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;
    console.log(req.body);
    const request = new sql.Request();

    // Check if username exists
    let result = await request
      .input("username", sql.VarChar, username)
      .query(`SELECT * FROM [dbo].[user] WHERE username = @username`);
    if (result.recordset.length > 0) {
      return res.status(400).send("Username is already taken");
    }

    // Check if email exists
    result = await request
      .input("email", sql.VarChar, email)
      .query(`SELECT * FROM [dbo].[user] WHERE email = @email`);
    if (result.recordset.length > 0) {
      return res.status(400).send("Email is already taken");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await request.query(
      `INSERT INTO [dbo].[user] (firstName, lastName, username, password, email) 
       VALUES ('${firstName}', '${lastName}', '${username}', '${hashedPassword}', '${email}')`
    );

    // Generate JWT token
    const token = jwt.sign({ username }, secretKey, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in a user
 *     description: Allows a user to log in by providing a username and password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: Username of the user
 *               password:
 *                 type: string
 *                 description: Password of the user
 *     responses:
 *       200:
 *         description: User successfully logged in and JWT token generated
 *       400:
 *         description: Username or password is incorrect
 *       500:
 *         description: Internal Server Error
 */
//login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const request = new sql.Request();
    request.input("username", sql.VarChar, username);

    const result = await request.query(
      `SELECT * FROM [dbo].[user] WHERE username = @username`
    );
    if (result.recordset.length === 0) {
      return res.status(400).send("Username or password is incorrect");
    }

    // Compare hashed password
    const validPassword = await bcrypt.compare(
      password,
      result.recordset[0].password
    );
    if (!validPassword) {
      return res.status(400).send("Username or password is incorrect");
    }

    // Generate JWT token
    const token = jwt.sign({ username }, secretKey, { expiresIn: "1h" });

    // Send the token as a response
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

module.exports = app;
