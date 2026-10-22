exports.formatJSON = (input) => JSON.stringify(typeof input === "string" ? JSON.parse(input) : input, null, 2);
