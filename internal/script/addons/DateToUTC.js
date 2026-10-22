exports.dateToUTC = (input) => {
  const numeric = typeof input === "number" || /^\s*-?\d+(\.\d+)?\s*$/.test(String(input));
  const date = numeric ? new Date(Number(input) * 1000) : new Date(Date.parse(input));
  const out = date.toUTCString();
  if (out === "Invalid Date") {
    console.log(out);
    return undefined;
  }
  return out;
};
