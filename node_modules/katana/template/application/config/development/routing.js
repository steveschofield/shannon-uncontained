module.exports = {
  // Default routing
  route: {
    directory: '',
    controller: 'home',
    action: 'index',
    arguments: []
  },

  // RegExp routes
  routes: [
    // RESTful api routes example
    // ['get api/:resource',          '[api]:resource/index'],
    // ['get api/:resource/new',      '[api]:resource/new'],
    // ['post api/:resource',         '[api]:resource/create'],
    // ['get api/:resource/:id',      '[api]:resource/show'],
    // ['get api/:resource/:id/edit', '[api]:resource/edit'],
    // ['put api/:resource/:id',      '[api]:resource/update'],
    // ['delete api/:resource/:id',   '[api]:resource/remove']
    [':method', 'home/:method'] // by default redirect all to home controller
  ],

  // 404 requests will be redirected to this controller and action if they exists
  controller_404: 'home',
  action_404: '_404',
  
  // Allowed characters in uri
  // If uri not match them then default routing is used
  allowed_characters: '-_:~%.\/a-zа-я0-9'
}
