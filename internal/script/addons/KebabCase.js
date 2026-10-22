const { words } = require("./words.js");
exports.kebabCase = (input) => words(input).map((w) => w.toLowerCase()).join("-");
