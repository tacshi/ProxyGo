const { words } = require("./words.js");
exports.startCase = (input) => words(input).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
