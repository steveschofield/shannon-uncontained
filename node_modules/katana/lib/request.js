var Url = require('url');
var QS  = require('qs');

var sanitize = App.Utils.sanitize;
var check    = App.Utils.check;

var Log    = App.Log;
var Router = require('./router');

var routing = require('./config')('routing');

Class('Katana.Core.Request', {
  have: {
	request: null, response: null,
	method: 'get', url: null, uri: '/', routed_uri: '',
	module: '', directory: '', controller: '', action: '', arguments: [], params: {},
	client: {}, form: null, data: {}, files: {}, query: {}, cookie: {}, session: {}
  },
	
  methods: {
	BUILD: function(Request, Response) {
	  return {
		request: Request,
		response: Response,
		form: Request.form
	  }
	},
		
	initialize: function() {
	  var Request = this;
		
	  Request.method = Request.request.method.toLowerCase();
	  Request.request.url = decodeURI(Request.request.url);
	  Request.url    = Url.parse(Request.request.url);
	  Request.uri    = sanitize(Request.url.pathname).trim('\\s\/');
	  Request.query  = Request.url.query ? QS.parse(Request.url.query) : {};
	  Request.ajax   = Request.is_ajax = (Request.request.headers['x-requested-with'] && Request.request.headers['x-requested-with'] == 'XMLHttpRequest');
	
	  if (Request.request.form) {
	    Request.data = Request.request.form.data;
	    Request.files = Request.request.form.files;
	  }
	
	  Request.client = {
	    ip: Request.request.connection.remoteAddress
	  }
	
	  var route = Router.route(Request.uri, Request.method, routing, null, true);
	
	  Request.module     = route.module;
	  Request.directory  = route.directory;
	  Request.controller = route.controller;
	  Request.action     = route.action;
	  Request.arguments  = route.arguments;
	  Request.params     = route.params;
	  Request.routed_uri = route.routed;
	}
  }
});

module.exports = Katana.Core.Request;
