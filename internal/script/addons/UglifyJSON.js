exports.uglifyJSON = (input) => {
  try {
    return JSON.stringify(typeof input === "string" ? JSON.parse(input) : input);
  } catch (e) {
    console.error("Invalid JSON");
    return input;
  }
};
