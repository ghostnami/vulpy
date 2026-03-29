const db = require('../db');

// Helper 1: Just passes data through
function processInput(data) {
  const sanitized = data.trim(); // Not enough sanitization
  return transformData(sanitized);
}

// Helper 2: Renames and passes
function transformData(input) {
  const queryPart = input;
  return executeQuery(queryPart);
}

// Sink: Executes query
async function executeQuery(filter) {
  // Serena should trace 'filter' back to 'req.query.id'
  const sql = "SELECT * FROM items WHERE id = " + filter; 
  return await db.run(sql);
}

// Entry point
exports.handleRequest = async (req, res) => {
  const userInput = req.query.id;
  const result = await processInput(userInput);
  res.json(result);
};
