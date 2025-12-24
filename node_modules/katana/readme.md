<a href="https://github.com/Shogun147/Katana"><img src="https://raw.github.com/Shogun147/Katana/master/katana.jpg"/></a>

Easy to use, modular web framework for any Node.js samurai, focuses on simplicity, maintainability and performance.

## Contents

* [Features](#features)
* [Installation](#installation)
* [Quick start](#quick-start)
* [Routing](#routing)
* [Modules](#modules)
* [Controllers](#controllers)
  * [Hooks](#hooks)
* [Models](#models)
* [Views](#views)
* [Events](#events)
* [Sessions](#sessions)
* [Logging](#logging)
* [Examples](#examples)
* [Contributing](#contributing)
* [License](#license)

## Features

* Powerful, flexible classical router
* Scalable through HMVC architecture 
* Environment based configuration
* Application quick generators
* Cookies and Session support
* Templating, partials support
* Fully non-blocking
* …

## Installation

Fastest way to get Katana is to install it with NPM:

```bash
$ npm install -g katana
```

## Quick start

The quickest way to start is to utilize the Katana executable to generate an application:

```bash
$ katana create app
$ cd app
$ npm install
```

The app path is optional and is relative to current path.

Then you are ready to start the server:

```bash
$ node app
```

### Basic application layout after creation will look like this:
    .
    ├── app.js
    ├── application
    │   ├── config
    │   │   ├── development
    │   │   │   ├── application.js
    │   │   │   ├── routing.js
    │   │   │   └── stores.js
    │   │   └── production
    │   ├── controllers
    │   │   └── home.js
    │   ├── models
    │   └── views
    │       └── index.html
    ├── modules
    ├── public
    │   ├── images
    │   ├── scripts
    │   └── css
    └── temp

## Routing

Classical routing is one the most powerful futures of Katana framework. It uses uri segments to determine the controller and action for a requested URI.<br>
So unlike in other Node.js framework you may just add controllers and actions without the need to create routing rules, but also let you write your own rules which may change the path.<br>
Without any rules, uri path will be treated as: http://katana:8000/`controller`/`action`/`arg1`/../`argN`

So if uri path is: `http://katana:8000/account/login`<br>
Then `controller=account` and `action=login`.

If there no uri segments then default path will be used, `home` as controller and `index` as action.

You can also rewrite path by set the routing rule, for example to view user profile:

```javascript
routes: {
  // each request method may have it's own routes
  get: [
    ['user/:user_id', 'users/profile']
  ]

  // also you can set routes for all methods
  all: [
    // if routes will not match for requested method then will try this routes
  ]
}
```

or you may set request method as route prefix:


```javascript
routes: [
  ['get user/:user_id', 'users/profile'], // will route this for get method
  ['* user/:user_id', 'users/profile'] // all methods
  ['user/:user_id', 'users/profile'] // if not set then will check all methods
]
```


This will set `controller=users` and `action=profile` and user_id will be available as `Request.params.user_id`.

Or you may pass this request to mvc module:

```javascript
routes: {
  get: [
    ['user/:user_id', '#auth/users/profile']
  ]
}
```

The `#` symbol meen that this request will pass to `auth` module, `controller=users` and `action=profile`.

You could also set format for user_id like so:

```javascript
routes: {
  get: [
    ['user/:user_id([0-9]+)', '#auth/users/profile']
  ]
}
```

`!important:` mvc modules may have their own routing rules.

We may also have controllers in subdirectories. Just set the directory path in square brackets.<br>
For example there is an `users` controller in `controllers/api` directory. The routing will look like:
```javascript
routes: [
  ['api/users/*', '[api]/users/:1'] // the slash after closing ] is optional
]
```

RESTful routes:
```javascript
  routes: [
    ['get api/:resource',          '[api]:resource/index'],
    ['get api/:resource/new',      '[api]:resource/new'],
    ['post api/:resource',         '[api]:resource/create'],
    ['get api/:resource/:id',      '[api]:resource/show'],
    ['get api/:resource/:id/edit', '[api]:resource/edit'],
    ['put api/:resource/:id',      '[api]:resource/update'],
    ['delete api/:resource/:id',   '[api]:resource/remove']
  ]
```
This means in `api` directory you could have a controller for each resource with methods `index`, `new`, `create`, `show`, `edit`, `update` and `remove`.<br>
If you use such HTTP methods as `put` or `delete` you must have some middleware which will rewrite the method. You could install [methodOverride](https://github.com/Shogun147/Katana-methodOverride) module with `katana module install methodOverride` command in your app root. Don't forget to enable it with `katana module enable methodOverride`.<br>
On the client side, set desired method in hidden field with `_method` name:
```html
<form action="/api" method="post">
  <input type="hidden" name="_method" value="put">
</form>
```
Field name could be changed in the main module file.

More examples:
  
```javascript
['news/:category/rss.:format(xml|json)?', 'news/rss'] will allow:
 news/any_category/rss
 news/any_category/rss.xml
 news/any_category/rss.json

 and News controller:

 methods: {
   rss: function(Response, Request) {
     // Now we can use Request.params.category and Request.params.format
     var format = Request.params.format || 'xml'; // default xml

     ...
   }
 }
```


## Modules

In Katana modules can be used as mvc part or your application or as middleware.

For mvc modules you can use routing the same way as for main mvc.<br>
Also you can run them as widgets by calling run method: 

```javascript
Module('auth').run('users/list');
```

This will run `list` action of `users` controller from `auth` module.

Middleware modules can listen specific application events and interact as they need.

For example auth module can look like this:

```javascript
var User = App.Model('auth:user'); // get user model of auth module

// listen new request event
App.on('request', function(Request, Response, callback) {
  Request.user = new User(Request.session);

  callback(); // callback when we're done here, required for application to continue
});
```

and then in our controller we can access user object as `Request.user`.

### Sharing modules

[Katana](https://github.com/Shogun147/Katana) comes with an basic modules sharing system which allow to download public modules and install them for application.

Katana binary has few new commands for interacting with modules:

* `katana modules` - list all available modules.
* `katana module search <str>` - search modules that contain `str` in name or description.
* `katana module update` - update modules list and their info.
* `katana module install <name> [url]` - install or reinstall app module.
  * `name` or `name@version` - module name
  * `url` or `username:repository` or `username:repository@version` - optional url or github username:repository combination.

  If only `name` is provided then download url will be builded from module data contained in modules registry file. The name could also be followed by an version tag.<br>
  If second argument is an url then module will be downloaded from that url.<br>
  If second argument is an combination of `username:repository@version` then the url will be: `https://github.com/:username/:repository/tarball/:version`.<br>
  If no `version` provided then requested one will be last available version for module in registry. If no valid version will be detected then `master` brunch will be requested.<br>
  For custom download url modules still must be gzipped tarballs.<br>
  Examples of install:
    * `katana module install auth`
    * `katana module install auth@0.1.0`
    * `katana module install auth Shogun147:Katana-auth`
    * `katana module install auth Shogun147:Katana-auth@0.1.0`
    * `katana module install auth https://github.com/Shogun147/Katana-auth/tarball/master`
    * `katana module install auth http://my-site.com/downloads/module/v1.0.5`

* `katana module uninstall <name>` - uninstall and remove module
* `katana module enable <name>` - enable module
* `katana module disable <name>` - disable module

For each of this actions [`install`, `uninstall`, `enable`, `disable`] modules could have their hooks which would be called. The hooks are stored in hooks directory of module.<br>
The hooks are useful when there is a need to do something unique on this actions. For ex the `install` hook (modules/:name/hooks/install.js) could create new tables in the database or copy modules assets to public directory…

The module registry is downloaded from `https://raw.github.com/Shogun147/Katana/master/modules.json`. To add new modules to the list just fork this file and send an pull request. This will make your module listed on `katana modules` command and on search.

## Controllers

Controllers are almost most important part of any application, they handle incoming requests and send responses.

A simple controller looks like this:

```javascript
// define our controller Class
Class('Home_Controller', {
  isa: App.Controller, // extend Katana Core Controller

  methods: {
    index: function(Response, Request) {
      Response.send('Hello World!');
    }
  }
});

module.exports = new Home_Controller;

// to not expose this class as a global, create it as anonymous
var HomeController = Class({ ... }); module.exports = new HomeController;

```

And now we can access this `index` action by opening http://katana:8000/, without any uri path this will use default controller and action from config which are `home` and `index`. Also we can access them directly by opening http://katana:8000/`home`/ with `index` as default action or http://katana:8000/`home`/`index`.

### Hooks

Due the power of Joose [Method Modifiers](http://joose.github.com/Joose/doc/html/Joose/Manual/MethodModifiers.html) (`before`, `after`, `override` and `around`) we may change the way class methods are called, actions that may happen before or after method call or even modify results that they could return.

For example let's restrict index method only for logged in users:

```javascript
Class('Home_Controller', {
  isa: App.Controller,

  methods: {
    index: function(Response, Request) {
      Response.send('Hello World!');
    }
  },

  around: {
    // the same name for the method we want to wrap
    index: function(method, Response, Request) {
      var User = Request.user;

      // if the user is not logged in then redirect to login page
      if (!User.logged_in()) {
        return Response.redirect('/login');
      }

      // else we call original method
      method(Response, Request);
    }
  }
});
```

The `call` modifier allow as to use regular expressions and apply that hook to all methods that matches the condition.

For example let's restrict access for all methods:

```javascript
Class('Home_Controller', {
  isa: App.Controller,

  methods: {
    index: function(Response, Request) {
      Response.send('Hello World!');
    }
  },

  call: {
    // use regexp instead of methods name
    // this will apply to all controller methods calls
   '.*': function(method, Response, Request) {
      var User = Request.user;

      // if the user is not logged in then redirect to login page
      if (!User.logged_in()) {
        return Response.redirect('/login');
      }

      // else we call original method
      method(Response, Request);
    }
  }
});
```


## Models

Katana did not limit the developer to define a model in some way or to use a specific module. It just autoload all from the models directory of application or a module and store them in a local registry.

You can access them like this:<br>

```javascript
var News = App.Model('news'); // get model object
```

To get a model from module you need to separate module name and model path with colon `:`, for example to get `user` model of `auth` module call: `App.Model('auth:user')`.

Model file can look like this:

```javascript
var Mongoose = App.Store('mongoose'); // get mongoose connection, look at stores config file
var Schema = require('mongoose').Schema;

var User = new Schema({
  username: String,
  password: String,
  email: String,
  signed_at: Date,
  roles: ['user', 'moderator', 'administrator']
});

module.exports = Mongoose.model('User', User);
```

## Views

To render a view you can use a few methods:

```javascript
var View = App.View;

Class('Home_Controller', {
  isa: App.Controller,

  methods: {
    index: function(Response, Request) {
      // directly render and send a view content
      Response.render('index', { title: 'Hello World' }); // this will render index.html file from views

      // get rendered content
      View.render('index', { title: 'Hello World' }, function(error, content) {
        // and latter send response
        Response.send(content);
      });

      // render a view from module
      Users.find({}, function(error, users) {
        if (error) { return Response.send('Error! Blablabla'); }

        // again module name separated by colon, and then path to the view
        View.render('auth:list', users, function(error, list) {
          Response.render('index', { users: list });
        });
      });
    }
  }
});
```

Controllers can also have their global data, which will be passed for the this.render calls:
  
```javascript
Class('Home_Controller', {
  isa: App.Controller,

  have: {
    // set global controller data
    data: {
      title: 'This is title for all pages for this controller',
      total_requests: 0
    }
  },

  methods: {
    index: function(Response) {
      // you can also set global controller data from actions
      this.set('copyright', 'blablabla');
      // or
      this.data.total_requests++;
    
      // by render the view with this.render method, the controller data will pass to this view
      this.render('index', ...); // <?-title?>, <?-total_requests?>
    
      // we may also rewrite globals by set them on render
      this.render('index', { title: 'This is rewritted title', foo: 'bar' }, function(error, content) {
        Response.send(content);
      });
    }
  }
});
```

## Events

Katana application emit specific events for different steps.
Few of them are available for middlewares, the others are for bootstrap control flow.

* `run` - on app initialization, but after bootstrapping
* `ready` - app is ready and started listening requests
* `connection` - emits just after the server get a new http.request.
  the listener will get 3 arguments:
  - `request` is a `http.IncomingMessage`
  - `response` is a `http.ServerResponse`
  - `next` callback so app flow will continue. If is not called then we must send response manually, also no other listeners or controller methods will be runned.
* `request` - emits after request route is resolve and request data is prepared
  - `request` is a `Katana.Core.Request`
  - `response` is a `Katana.Core.Response`
  - `next` callback
  `request` and `response` in and after this event are the same as controller methods gets as arguments.

This events could be used to write some middlewares, same as in Express framework.
```javascript
// in express
App.use(function(req, res, next){
  console.log(req.method, req.url);
  next();
});

// in katana
App.on('request', function(req, res, next) {
  console.log(req.method, req.uri);
  next();
})
```

For example, `auth` module can listen `request` event to assign a user model for request (see Modules).

Or a `chat` module which need application server to create a socket.io server.

```javascript
var socket_io = require('socket.io');
var io;

// waiting app ready
App.on('ready', function(callback) {
  io = socket_io.listen(App.server);
    
  io.sockets.on('connection', function (socket) {
    // …
  });
    
  callback();
});
```

## Sessions

Katana has build in module for supporting sessions.
This gives you a way to associate data with each particular visitor of your app and have that data persist between requests.

### Data stores
For now Katana support only 2 session data stores (more to come):

* **Memory** (by default): useful for development. Session data is saved in memory at worker-process level, which means this will not work with cluster. Also, all sessions disappear when app is restarted.

* **Redis**: Sessions are saved in a redis noSQL database and persist across app restarts. Requires a Redis server or clusters.

### Using sessions

First of all you need to enable sessions in application config file.
The default session config look like this:

```javascript
session: {
  // enable or disable session support
  enabled: true,

  // session identifier name for cookie of
  key_name: 'session_id',

  // session id length
  key_length: 32,

  // lifetime before delete inactive session
  lifetime: 1000 * 60 * 60 * 24 * 7,

  // session store, one from config/stores.js
  store: 'redis',
            
  // default data for new sessions
  defaults: {
  
  }
}
```

Once you enable sessions, the session object will be assigned to each request and data will be loaded automatically from the session store.
Then this object could be accessed as `Request.session`.
For now available public methods are `set`, `get` and `remove`.

Example counter of user requests:

```javascript
index: function(Response, Request) {
  var Session = Request.session;

  // get current requests count, default 0
  var counter = Session.get('requests', 0);

  counter++;

  // set new value
  Session.set('requests', counter);

  // Session data will be automatically saved in store before sending response
  // Also will save session id in the cookie with key_name from config
  Response.send('You have visited this page '+ counter +' times');
}
```

## Logging

Katana uses [winston](https://github.com/flatiron/winston) module to log.
Available as `App.Log` you could add more transports or options to it. Check official docs for this.

## Examples

* [TodoMVC](https://github.com/Shogun147/TodoMVC) - AngularJS MVC app with RESTful API on backend
* [ToDo](https://github.com/Shogun147/Katana-ToDo) - Simple todo application

## Contributing
Anyone interested or who like the framework idea can contribute by sending new ideas, issues or pull requests. Any help would be appreciated.

## License
The MIT License

Copyright © 2013 D.G. Shogun <Shogun147@gmail.com>
