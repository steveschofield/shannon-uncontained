var Path = require('path');

var consolidate = require('./consolidate');

var options = require('./config')().view;
var merge   = require('./utils').merge;

var engine = require(options.engine);

function resolve(path) {
  var self = this;

  path = path.replace('.', '/');

  var module = 'application';
  var exp;

  if (exp = path.match(/(.*)\:(.*)/i)) {
    module = 'modules'+ Path.sep + exp[1];
    path = exp[2];
  }

  return (root + module +'/views/'+ path + (options.extension || ''));
}

engine.resolve = resolve;

module.exports = {
  engine: engine,
  data: options,

  render: function(path, data, callback) {
    if (typeof(data) === 'function') {
      callback = data;
      data = {};
    }

    var data = merge(this.data, data);

    path = data.resolve !== false ? resolve(path) : path;

    consolidate[data.engine](path, data, callback);
  },

  set: function(key, value) {
    if (typeof(key) === 'object') {
      return this.data = merge(this.data, key);
    }

    this.data[key] = value;
  }
}
