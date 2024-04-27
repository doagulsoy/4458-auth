const sql = require("mssql");

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

async function getConnection() {
  try {
    console.log("Connected to the Azure SQL database");
    return await sql.connect(config);
  } catch (err) {
    console.error("Failed to connect to the database:", err);
  }
}

module.exports = getConnection;
