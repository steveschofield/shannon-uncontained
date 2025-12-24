var Formidable   = require('formidable');
var EventEmitter = require('events').EventEmitter;

var config = require('./config')().multipart;

module.exports.parse = function(request, response, callback) {
  var methods = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];
  var needParse = methods.indexOf(request.method) === -1;
  
  request.form = null;
  
  if (!needParse) {
    return callback();
  }
  
  var Form = new Formidable.IncomingForm();
  Form.data = {};
  Form.files = {};

  request.form = Form;

  for (key in config) {
    Form[key] = config[key];
  }

  Form.on('field', function(name, value) {
    onData(name, value, Form.data);
  });

  Form.on('file', function(name, value) {
    onData(name, value, Form.files);
  });

  Form.on('error', function(error) {
    config.wait_end && callback(error);
  });

  Form.on('end', function() {
    config.wait_end && callback();
  });

  Form.parse(request);
  
  !config.wait_end && callback();
}

function onData(name, value, data) {
  if (Array.isArray(data[name])) {
    data[name].push(value);
  } else if (data[name]) {
    data[name] = [data[name], value];
  } else {
    data[name] = value;
  }
}
