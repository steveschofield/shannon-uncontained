var Http  = require('http');
var Https = require('https');
var Path  = require('path');
var Fs    = require('fs');
var Async = require('async');

var EventEmitter = require('events').EventEmitter;

global.mod_root = Path.normalize(__dirname + '/../');
global.root     = Path.dirname(process.mainModule.filename) + Path.sep;
global.env      = process.env.NODE_ENV || 'development';

require('joose');

require('./bootstrap');

var Config = require('./config');
var config = Config();
var routing = Config('routing');

var View   = require('./view');
var Model  = require('./model');
var Multiparser = require('./multiparser');

var Log = require('winston');

var load = require('./utils').load;

Class('Katana', {
  meta: Joose.Meta.Class,
	
  isa: EventEmitter,
	
  have: {
	info: {},
	server: null,
	controllers: []
  },
	
  methods: {
	initialize: function() {
	  var App = this;
			
	  App.info = require(root +'package.json');
		
	  process.nextTick(function() {
		App.boot();
	  });
	},
		
	run: function() {
	  App.series('run', function(error, results) {
	    if (error instanceof Error) { throw error; }
				
		if (config.ssl.enabled) {
		  var options = {
		    key: Fs.readFileSync(config.ssl.key),
			cert: Fs.readFileSync(config.ssl.cert)
		  };

		  App.server = Https.Server(options);
	    } else {
		  App.server = Http.Server();
		}
				
		App.server.on('request', function(request, response) {
			Multiparser.parse(request, response, function() {
        App.series('connection', function(error, results) {
			    if (error instanceof Error) {
				  App.series('request.error_connection', function(err, res) {
				    if ((err instanceof Error) || err !== true) {
					  response.writeHead(500, { 'Content-Type': 'text/html' });
					  response.end('Error occured while handling request, please try again.');
					}
				  }, error, request, response);
				} else if (error !== true) {
				  App.handle_connection(request, response);
				}
			  }, request, response);
			});
		});
				
		App.server.listen(config.port, config.host);
				
		Log.info('['+ process.pid +'] Listen at: '+ config.host +':'+ config.port);
				
		App.parallel('ready', function(error, results) {
		  if (error) { throw error; }
		});
	  });
	},
		
	handle_connection: function(request, response) {
	  var Request  = new Katana.Core.Request(request, response);
	  var Response = new Katana.Core.Response(response, Request);
			
	  App.series('request', function(error, results) {
	    if (Request.module) {
		  var Module = require('./module');
					
		  if (Module(Request.module) != undefined) {
			  Module.run_uri(Request.module, Request.routed_uri, [Response, Request], Request.method);
		  } else {
		    if (App.controllers[routing.controller_404] && typeof(App.controllers[routing.controller_404][routing.action_404]) == 'function') {
			  App.controllers[routing.controller_404][routing.action_404](Response, Request);
			} else {
			  Response.error(404);
			}
		  }
		} else {
		  var Controller = App.controllers[Request.directory + Request.controller];

		  if (Controller != undefined) {
		    if (typeof(Controller[Request.action]) == 'function') {
			  Controller[Request.action](Response, Request);
			} else {
			  if (typeof(Controller[routing.action_404]) == 'function') {
			    Controller[routing.action_404](Response, Request);
			  } else if (App.controllers[routing.controller_404] && typeof(App.controllers[routing.controller_404][routing.action_404]) == 'function') {
			    App.controllers[routing.controller_404][routing.action_404](Response, Request);
			  } else {
			    Response.error(404);
			  }
			}
		  } else {
		    if (App.controllers[routing.controller_404] && typeof(App.controllers[routing.controller_404][routing.action_404]) == 'function') {
		      App.controllers[routing.controller_404][routing.action_404](Response, Request);
		    } else {
		      Response.error(404);
		    }
		  }
		}
	  }, Request, Response);
	},
		
	boot: function() {
	  Async.series({
	    config: function(callback) {
		    App.series('boot.config', callback);
		  },
		  stores: function(callback) {
		    App.series('boot.stores', callback);
		  },
		  models: function(callback) {
		    Model.load(null, function() {
			    App.series('boot.models', callback);
		    });
		  },
		  modules: function(callback) {
		    App.series('boot.modules', callback);
		  },
		  controllers: function(callback) {
		    load(root + 'application/controllers', function(error, controllers) {
			    App.controllers = controllers;

			    App.series('boot.controllers', callback);
		    });
		  }
	  },
	  function(error, results) {
			if (error) {
			  throw error;
			} else {
			  App.run();
			}
	  });
	  }
  }
});

global.App = module.exports = new Katana;

module.exports.Log         = Log;
module.exports.Utils       = require('./utils');
module.exports.Config      = require('./config');
module.exports.Store       = require('./store');
module.exports.View        = require('./view');
module.exports.Router      = require('./router');
module.exports.Static      = require('./static');
//module.exports.Multiparser = require('./multiparser');
module.exports.Request     = require('./request');
module.exports.Response    = require('./response');
module.exports.Model       = require('./model');
module.exports.Module      = require('./module');
module.exports.Controller  = require('./controller');

if (config.cookie.enabled)  module.exports.Cookie  = require('./cookie');
if (config.session.enabled) module.exports.Session = require('./session');
