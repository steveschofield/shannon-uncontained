var EventEmitter = require('events').EventEmitter;
var Async        = require('async');

EventEmitter.prototype.emitParallel = EventEmitter.prototype.parallel = function(event, callback) {
  emit.call(this, event, callback, Array.prototype.slice.call(arguments, 2), 'parallel');
}

EventEmitter.prototype.emitSeries = EventEmitter.prototype.series = function(event, callback) {
  emit.call(this, event, callback, Array.prototype.slice.call(arguments, 2), 'series');
}

var fn = function(listener, args) {	
  return function(callback) {
	  args = args.concat(callback);
		
	  listener.apply(listener, args);
  }
}

function emit(event, callback, args, type) {
  var listeners = this.listeners(event);
	
  var list = [];
	
  if (args.length) {
	  for (var i=0; i<listeners.length; i++) {
	    var f = fn(listeners[i], args);
			
	    list.push(f);
 	  }
  } else {
	  list = listeners;
  }
	
  var method = type === 'parallel' ? Async.parallel : Async.series;
	
  method(list, callback || function(error, results) {
	  if (error) { throw error; }
  });
}

Joose.Managed.Builder.meta.addMethod('call', function(targetMeta, info) {
  targetMeta.addMethodModifier('initialize', function() {
    var methods = {};
    var around = {};

    this.meta.getMethods().eachOwn(function(fn, name) {
	    methods[name] = fn;
    });

    Joose.O.each(info, function (value, name) {
      for (method in methods) {
	      if (new RegExp(name).test(method)) {
	        around[method] = value;
	      }
      }
    });

    this.meta.extend({ around: around });
  }, Joose.Managed.Property.MethodModifier.Before);
});
