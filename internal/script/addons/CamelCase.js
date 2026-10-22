const { words } = require("./words.js");
exports.camelCase = (input) =>
  words(input)
    .map((w, i) => (i === 0 ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()))
    .join("");
