exports.jwtDecode = (input) => {
  const parts = String(input).trim().split(".");
  if (parts.length !== 3) {
    console.error("A JWT has three parts, this one " + parts.length);
    return undefined;
  }
  try {
    return {
      header: JSON.parse(__proxygo.base64URLDecode(parts[0])),
      payload: JSON.parse(__proxygo.base64URLDecode(parts[1])),
      signature: parts[2],
    };
  } catch (e) {
    console.error("Invalid JWT: " + e);
    return undefined;
  }
};
