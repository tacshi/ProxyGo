package script

import "strings"

func Reference() string {
	return strings.ReplaceAll(reference, "{{addons}}", strings.Join(Addons(), ", "))
}

const reference = `# ProxyGo scripting

A script is JavaScript that ProxyGo runs for the requests matching its rule. It defines any of:

` + "```js" + `
async function onRequest(context, url, request) {
  // before the request goes to the server
  return request;
}

async function onResponse(context, url, request, response) {
  // before the response reaches the client
  return response;
}

function onWebsocket(context, url, request, response, message) {
  // after each WebSocket message went on; it cannot change the message
}
` + "```" + `

The arguments are positional: keep them all, in this order. Return the object you changed. Scripts run one at a time, for at most 30 seconds each.

## request

method, scheme, host, port, path (with the query), queries (an object of the query's parameters), headers (an object), body, rawBody, comment, color.
A JSON or form body arrives as an object; setting body to an object sends it as JSON. Changing queries rewrites the path's query.

## response

statusCode, statusPhrase, headers, body, rawBody, and bodyFilePath: a file whose content becomes the body, as "~/Desktop/mock.json".

## context

scriptName, matchingRule, matchingMethod, isEnableOnRequest, isEnableOnResponse, isMockResponse, flow (id, clientName, clientPath, clientPid, clientIpAddress, serverIpAddress and their ports), and abort(), which answers 403 without sending the request. $abort() does the same.

## message (onWebsocket)

type (text, binary, ping, pong or close), from (client or server), data, rawData (a Uint8Array of a binary message), closeCode, time.

## Globals

console.log, info, debug, warn and error; sharedState, an object every script shares; sleep(ms); readFromFile(path) and writeToFile(content, path); btoa and atob; $http.get(url) and $http.post(url, body); require; and, when Scripting may read the environment, $NAME for each of the shell's variables, with _reloadEnv() to read them again.

## require

Modules are CommonJS (module.exports, exports):

- require("@users/name.js") or "@users/data.json": a file in the scripts' users folder
- require("@libs/name.js"): a file in the libs folder
- require("@addons/Name.js"): an addon ProxyGo ships: {{addons}}
- require("package"): an npm package installed in the scripts folder's node_modules (npm install there)
- require("./name.js"): beside the module that requires it

Node.js's own modules, ES modules and native add-ons are not available, and nothing outside the scripts folder is read.

## Run as Mock API

With Mock API on, the request goes to no server: onResponse gets an empty 200 response to fill.
`
