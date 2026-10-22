exports.deflate = (input) => __proxygo.compress("zlib", String(input));
exports.inflate = (input) => __proxygo.decompress("zlib", String(input));
exports.gzip = (input) => __proxygo.compress("gzip", String(input));
exports.ungzip = (input) => __proxygo.decompress("gzip", String(input));
