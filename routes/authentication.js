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

const studentsApi = "http://localhost:5001/student/getStudents"; // Ensure correct scheme and path

const checkIfStudentExists = async (firstName, lastName, email) => {
  try {
    const response = await fetch(
      `${studentsApi}?firstName=${firstName}&lastName=${lastName}&email=${email}`
    );

    // Check for successful HTTP response
    if (!response.ok) {
      console.error("Failed to fetch student data:", response.statusText);
      return false;
    }

    const data = await response.json(); // Attempt to parse as JSON
    return data.length > 0; // Return true if at least one matching student is found
  } catch (err) {
    console.error("Error during checkIfStudentExists:", err);
    return false; // Return false in case of error
  }
};


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
 *     description: Allows a new user to sign up by providing a  password, and email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *               - email
 *             properties:
 *                 type: string
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
 *         description: or email already taken
 *       500:
 *         description: Internal Server Error
 */
//signup
//signup
app.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    const connection = await getConnection(); // Ensure you have a valid connection
    const request = new sql.Request(connection); // Create a new request with the connection

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Define input parameters for the query
    request.input("firstName", sql.NVARCHAR(50), firstName);
    request.input("lastName", sql.NVARCHAR(50), lastName);
    request.input("email", sql.NVARCHAR(100), email);
    request.input("password", sql.NVARCHAR(255), hashedPassword);

    // Insert the new user into the database with parameterized queries
    await request.query(
      `INSERT INTO [dbo].[User] (firstName, lastName, email, password) 
       VALUES (@firstName, @lastName, @email, @password)`
    );

    // Generate JWT token
    const token = jwt.sign({ email }, secretKey, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).send("Internal Server Error");
  }
});


/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in a user
 *     description: Allows a user to log in by providing and password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *             properties:
 *               password:
 *                 type: string
 *                 description: Password of the user
 *     responses:
 *       200:
 *         description: User successfully logged in and JWT token generated
 *       400:
 *       500:
 *         description: Internal Server Error
 */
//login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const connection = await getConnection(); // Ensure you have a valid connection
    const request = new sql.Request(connection); // Create a new request with the connection

    // Get the user from the database
    const result = await request.query(
      `SELECT * FROM [dbo].[User] WHERE email = '${email}'`
    );

    if (result.recordset.length === 0) {
      return res.status(400).send("User not found");
    }

    const user = result.recordset[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).send("Invalid password");
    }

    // Generate JWT token
    const token = jwt.sign({ email }, secretKey, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).send("Internal Server Error");
  }
});

module.exports = app;
