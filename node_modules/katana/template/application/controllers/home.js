var HomeController = Class({
  isa: App.Controller,
	
  methods: {
  	index: function(Response, Request) {
  	  Response.render('index', { title: 'Katana - Easy to use, modular web framework for any Node.js samurai.' });
  	}
  }
});

module.exports = new HomeController;
