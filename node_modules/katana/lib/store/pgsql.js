var Log = App.Log;

var PgSQL = require('pg');

module.exports = function(store, config, callback) {
  var client = new PgSQL.Client({
	host: config.host,
	port: config.port,
	user: config.user,
	password: config.password,
	database: config.database
  });

  client.connect();

  client.on('error', function(error) {
	Log.error('PgSQL error:\n' + error);
  });
	
  Log.debug('PgSQL['+ store +'] connected');
	
  callback(store, client);
}