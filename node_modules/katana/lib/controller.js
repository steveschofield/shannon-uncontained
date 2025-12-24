var View = App.View;

var extend = require('./utils').extend;

Class('Katana.Core.Controller', {
  have: {
	  data: []
  },
	
  methods: {
		set: function(name, value) {
		  if (typeof(name) === 'object') {
			  return this.data = extend(this.data, name);
		  }
			
			this.data[name] = value;
		},
			
		render: function(template, data, callback) {
		  View.render(template, extend(this.data, data), callback);
		}
  }
});

module.exports = Katana.Core.Controller;
