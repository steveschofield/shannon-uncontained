var sanitize = require('./utils').sanitize;
var check    = require('./utils').check;

var methods = '\\*|all|options|get|post|put|delete|trace|connect|propfind|proppatch|mkcol|copy|move|lock|unlock|version-control|report|checkout|checkin|uncheckout|mkworkspace|update|label|merge|baseline-control|mkactivity|orderpatch|acl|search|patch';

Class('Katana.Core.Router', {
  have: {
    routes: {},
	cache: {}
  },
	
  methods: {
    initialize: function() {
	  var Router = this;
		
	  Router.SUPER();
		
	  Router.prepare(App.Config('routing').routes);
		
	  App.on('run', function(callback) {
        for (var module in App.info.katana.modules) {
          if (App.info.katana.modules[module].enabled) {
            Router.prepare(App.Config(module +':routing').routes || {}, module);
          }
        }
			
		callback();
	  });
	},
		
	prepare: function(routes, module) {
	  var Router = this;
			
	  module = module || 'app';
			
	  if (Array.isArray(routes)) {
	    for (var i=0; i<routes.length; i++) {
		  var exp     = routes[i][0];
		  var path    = routes[i][1];
		  var method  = 'all';
					
		  var m;
					
		  if (exp !== '*' && (m = exp.match(new RegExp('^('+ methods +') (.*)$', 'i')))) {
		    method = m[1] == '*' ? 'all' : m[1];
			exp    = m[2];
		  }
					
		  exp === '*' && (exp = 'all');
					
		  var keys   = [];
		  var regexp = Router.normalize(exp, keys);
				
		  if (!Router.routes[module]) { Router.routes[module] = {}; }
		  if (!Router.routes[module][method]) { Router.routes[module][method] = []; }

		  Router.routes[module][method].push({
		    regexp: regexp,
		    path: sanitize(path).trim('\\s\/'),
		    keys: keys
		  });
		}
	  } else {
	    for (method in routes) {
		  for (var i=0; i<routes[method].length; i++) {
		    var exp     = routes[method][i][0];
			var path    = routes[method][i][1];

			var keys   = [];
			var regexp = Router.normalize(exp, keys);

			if (!Router.routes[module]) { Router.routes[module] = {}; }
			if (!Router.routes[module][method]) { Router.routes[module][method] = []; }

			Router.routes[module][method].push({
			  regexp: regexp,
			  path: sanitize(path).trim('\\s\/'),
			  keys: keys
			});
		  }
		}
	  }
	},
		
	normalize: function(path, keys, sensitive) {
	  var i = 0;
			
	  if (path instanceof RegExp) {
	    var k = path.source.match(/\(.*?\)/g);
				
		for (i; i<k.length;) {
		  keys.push({ name: ++i });
		}
				
		return path;
	  }
			
	  path = path
	    .replace(/\/\(/g, '(?:/')
		.replace(/(\/)?(\.)?:(\w*)(?:(\(.*?\)))?(\?)?/g, function(_, slash, format, key, capture, optional){
		  keys.push({ name: key || ++i, optional: !! optional });
		  slash = slash || '';
		    return ''
		      + (optional ? '' : slash)
		      + '(?:'
		      + (optional ? slash : '')
		      + (format || '') + (capture || (format && '([^/.]+?)' || '([^/]+?)')) + ')'
		      + (optional || '');
		  })
		.replace(/([\/.])/g, '\\$1')
		.replace(/\*/g, '(.*)');
		  
	  return new RegExp('^'+ path +'$', sensitive ? '' : 'i');
	},
		
	route: function(uri, method, config, module, use_routes) {
	  var Router = this;
			
	  var routed = uri;
	  var mod;
			
	  var route = {
		module:     module || '',
		directory:  config.route.directory || '',
		controller: config.route.controller || (module || 'home'),
		action:     config.route.action || 'index',
		arguments:  config.route.arguments || [],
		params:     config.params || {},
		routed:     routed
	  };
			
	  use_routes = !!use_routes;
			
	  if (!uri || (config.allowed_characters && uri.match(new RegExp('^['+ config.allowed_characters +']+$', 'i')) === null)) {
		return route;
	  }
			
	  var methods = [method, 'all'];
	  var matched = false;
			
	  methods.forEach(function(method) {
	    if (!matched) {
		  if (use_routes && Router.routes[route.module || 'app'] && Router.routes[route.module || 'app'][method]) {
		    for (var i=0; i<Router.routes[route.module || 'app'][method].length; i++) {
			  var r = Router.routes[route.module || 'app'][method][i];

			  if (match = uri.match(r.regexp)) {
			    matched = true;
								
				match = match.slice(1);

				routed = r.path;

				for (var j=0; j<match.length; j++) {
				  var key = r.keys[j];

		          if (key) {
			        route.params[key.name] = match[j];

					routed = routed.replace(':'+key.name, match[j] || '');
		          } else {
	                route.params[j+1] = match[j];

					routed = routed.replace(':'+(j+1), match[j] || '');
		          }
				}

				if (!route.module) {
				  mod = routed[0] == '#';
				  if (mod) {
				    routed = routed.substr(1);
				  }
				}

				routed = routed.replace(/\[(.*)\](\/)?/, function(_, dir) {
				  route.directory = sanitize(dir.toLowerCase()).trim('\\s\/') + '/';

				  return '';
				});

			    route.routed = routed;
			
				break;
			  }
			}
		  }
		}
	  });
			
	  var segments = routed.indexOf('/')!=-1 ? routed.split('/') : (routed!='' ? [routed] : {});

      if (segments.length > 0 && mod && !route.module) { 
	    route.module = segments.shift().toLowerCase();
	
	    route.routed = route.routed.replace(new RegExp('^'+ route.module +'[\/]?', 'i'), '');
	  }
	
	  if (segments.length > 0) { route.controller = segments.shift().toLowerCase(); }
	  if (segments.length > 0) { route.action = segments.shift().toLowerCase(); }
	  if (segments.length > 0) { route.arguments = segments; }
		
	  return route;
	}
  }
});

module.exports = new Katana.Core.Router;
