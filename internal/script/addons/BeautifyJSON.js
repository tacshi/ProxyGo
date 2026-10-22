exports.beautifyJSON = (input) => {
  try {
    return JSON.stringify(typeof input === "string" ? JSON.parse(input) : input, null, 2);
  } catch (e) {
    console.error("Invalid JSON");
    return input;
  }
};
