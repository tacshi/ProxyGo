exports.dateToTimestamp = (input) => {
  const t = Date.parse(input);
  if (isNaN(t)) {
    console.log("Invalid Date");
    return 0;
  }
  return t;
};
