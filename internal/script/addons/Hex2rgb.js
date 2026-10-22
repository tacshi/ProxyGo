exports.hexToRGB = (input) => {
  const hex = String(input).replace(/^#/, "").slice(0, 6);
  return [0, 2, 4].map((i) => parseInt(hex.substring(i, i + 2), 16)).join(",");
};
