function toQuery(obj, prefix) {
  const parts = [];
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const name = prefix ? prefix + "[" + key + "]" : key;
    if (value !== null && typeof value === "object") {
      parts.push(toQuery(value, name));
    } else {
      parts.push(encodeURIComponent(name) + "=" + encodeURIComponent(value === null ? "" : value));
    }
  }
  return parts.filter((p) => p !== "").join("&");
}
exports.jsonToQuery = (input) => toQuery(typeof input === "string" ? JSON.parse(input) : input);
