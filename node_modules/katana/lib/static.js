var Path = require('path');

var server  = new (require('node-static').Server)('./');
var options = App.Config().static;

options.error_log = options.error_log || false;

App.on('connection', function(request, response, callback) {
  var url = Path.resolve(decodeURI(request.url));

  if (url === '/favicon.ico') {
    url = '/'+ options.path + 'favicon.ico';
  }

  if (!options.enabled || url.indexOf('/'+ options.path)!==0) {
    return callback();
  }

  request.url = url;

  server.serve(request, response, function(error, res) {
    if (error) {
      response.writeHead(error.status, error.headers);
      response.end(error.message);
    }

    callback(true);
  });
});
