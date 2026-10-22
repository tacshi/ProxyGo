exports.validateJSON = (input) => {
  try {
    JSON.parse(input);
    return true;
  } catch (e) {
    console.log("Invalid JSON");
    return false;
  }
};
