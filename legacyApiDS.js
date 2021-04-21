var https = require('follow-redirects').https;
var fs = require('fs');

var options = {
  'method': 'GET',
  'hostname': 'app.deepsecurity.trendmicro.com',
  'port': 443,
  'path': '/rest/events/antimalware?sID=2DD4C7E0-55CD-9839-3206-F945F0B013EF_85A2C05E202DD68C08FD6935C7513FBC',
  'headers': {
    'api-version': 'v1',
    'Content-Type': 'application/json'
  },
  'maxRedirects': 20
};

var req = https.request(options, function (res) {
  var chunks = [];

  res.on("data", function (chunk) {
    chunks.push(chunk);
  });

  res.on("end", function (chunk) {
    var body = Buffer.concat(chunks);
    console.log(body.toString());
  });

  res.on("error", function (error) {
    console.error(error);
  });
});

req.end();