exports.btoa = (input) => {
  if (input instanceof ArrayBuffer || ArrayBuffer.isView(input)) {
    return __proxygo.base64Bytes(input);
  }
  return btoa(input);
};
exports.atob = (input) => atob(input);
exports.base64Encode = (input) => __proxygo.base64Encode(String(input));
exports.base64Decode = (input) => __proxygo.base64Decode(String(input));
