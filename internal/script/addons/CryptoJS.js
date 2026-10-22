exports.encryptAES = (input, password) => __proxygo.aesEncrypt(String(input), String(password));
exports.decryptAES = (input, password) => __proxygo.aesDecrypt(String(input), String(password));
exports.HmacSHA256 = (input, secret) => __proxygo.hmac("sha256", String(input), String(secret));
