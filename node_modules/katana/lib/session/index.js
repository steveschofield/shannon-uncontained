var Log = App.Log;

var config = App.Config().session;
var store_type = App.Config('stores')[config.store].type;

var Session = {
  type: store_type,
  config: config,
  store: null,

  create: function(session_id, callback) {
	  new Session.store(session_id, function(sess) {
	    callback(sess);
	  });
  }
};

var Store;

App.on('run', function(callback) {
  Store = require('./' + store_type);

  Session.store = Store;

  callback();
});

App.on('request', function(Request, Response, callback) {
  new Store(Request.cookie.get(config.key_name), function(Session) {
	  Request.session = Session;
		
	  callback();
  });
});

App.on('cookie.send', function(Response, Request, callback) {
  Request.session.save(function(error) {
	  if (error) { Log.error('Error saving session: ' + Request.session.id); return callback(); }
		
	  Request.cookie.set(config.key_name, Request.session.id, { lifetime: config.lifetime });
		
	  callback();
  });
});

module.exports = Session;
