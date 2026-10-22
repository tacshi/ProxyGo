exports.queryToJSON = (input) => {
  const query = String(input).replace(/^[^?]*\?/, "");
  const out = {};
  for (const part of query.split("&")) {
    if (part === "") continue;
    const i = part.indexOf("=");
    const key = decodeURIComponent((i < 0 ? part : part.slice(0, i)).replace(/\+/g, " "));
    const value = i < 0 ? "" : decodeURIComponent(part.slice(i + 1).replace(/\+/g, " "));
    if (key in out) {
      out[key] = [].concat(out[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
};
