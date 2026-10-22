const { words } = require("./words.js");
exports.snakeCase = (input) => words(input).map((w) => w.toLowerCase()).join("_");
