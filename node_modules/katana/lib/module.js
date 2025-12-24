var Router = require('./router');

var load  = App.Utils.load;
var merge = App.Utils.merge;

var modules = {};

Class('Katana.Core.Module', {
  have: {
    name: 'Katana.Module',
    controllers: {}
  },

  methods: {
    run: function(uri) {
      return Module._run(this.name, uri, [].slice.call(arguments, 1), false);
    },

    run_uri: function(uri, args, method) {
      return Module._run(this.name, uri, args, true, method);
    }
  }
});

function Module(module) {
  if (module === '*') {
    var mods = {};

    for(var m in modules) {
      mods[m] = modules[m].module;
    }

    return mods;
  } else if (module) {
    return modules[module].module;
  }
  
  return Katana.Core.Module;
}

Module.run = function(name, uri) {
  return Module._run(name, uri, [].slice.call(arguments, 2), false);
}

Module.run_uri = function(name, uri, args, method) {
  return Module._run(name, uri, args, true, method);
}

Module._run = function(name, uri, args, routes, method) {
  uri = uri || '';
  method = method || 'get';

  if (!routes) {
    uri = uri.replace('.', '/').replace(/^([a-z]+):/, function(_, action) {
      method = action;

      return '';
    });
  }

  var routing = merge({}, App.Config(name + ':routing'));

  if (!routes) { routing.routes = []; }
  if (!routing.route) { routing.route = {}; }

  var route = Router.route(uri, method, routing, name, routes);

  route.arguments = args.concat(route.arguments);

  if (!modules[name]) {
    throw new Error('Undefined module '+ name);
  }

  var controller = modules[name].controllers[route.directory + route.controller];

  if (controller !== undefined) {
    if (typeof(controller[route.action]) === 'function') {
      return controller[route.action].apply(controller, route.arguments);
    } else {
      throw new Error('Could not find action '+ route.action +' for controller '+ route.controller +' in module '+ name);
    }
  } else {
    throw new Error('Could not find controller '+ route.controller +' for module '+ name);
  }
}

module.exports = Module;

var info = require(root +'package');

for (var module in info.katana.modules) {
  if (info.katana.modules[module].enabled) {
    modules[module] = { module: module, controllers: [] };
  }
}

App.on('boot.config', function(callback) {
  for (module in modules) {
	  App.Config.load(module);
  }
	
  callback();
});

App.on('boot.models', function(callback) {
  var pending = Object.keys(modules).length;
	
  if (!pending) { callback(); }
	
  for (module in modules) {
  	App.Model.load(module, function() {
    	  if (!--pending) { return callback(); }
  	});
  }
});

App.on('boot.modules', function(callback) {	
  for (module in modules) {
	  modules[module].module = require(root +'modules/'+ module);
    modules[module].module.name = module;
  }
	
  callback();
});

App.on('boot.controllers', function(callback) {
  var pending = Object.keys(modules).length;
	
  if (!pending) { return callback(); }
	
  Object.keys(modules).forEach(function(module) {
  	load(root +'modules/'+ module +'/controllers', function(error, controllers) {
  	  if (error) { throw error; }
  			
  	  modules[module].controllers = controllers;
  			
  	  if (!--pending) { callback(); }
  	});
  });
});
