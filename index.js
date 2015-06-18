var _ = require('lodash'),
    authenticate = require('./lib/authenticate'),
    injectModel = require('./lib/injectmodel'),
    Waterline = require('sails/node_modules/waterline'),
    $LOGIN_REDIRECT_URL$ = '$loginRedirectUrl$';

module.exports = function userlogin(sails) {
    sails.log.info('loading userlogin' );
    return _.merge({
        __configKey__: {
            local: true,
            userModel: 'User',
            loginCallback: function(err, user, provider, req, res) {
                if (err || !user) {
                    sails.log.info(provider + ' authentication failed');
                    return res.notFound('No user found');
                }
                req.logIn(user, function (err) {
                    if (err)
                      return res.send(err)

                    var url = req.session[$LOGIN_REDIRECT_URL$];
                    if (!url)
                        url = '/';
                    sails.log.info('redirecting to ' + url + '...')
                    return url ? res.redirect(url) : res.ok();
                });
            }
        },

        routes: {
            before: {
                'POST /login': function(req, res, next) {
                    return sails.hooks.userlogin.localLogin(req, res, next);
                },

                '/google/*': function(req, res, next) {
                    return sails.hooks.userlogin.googleLogin(req, res, next);
                },

                '/facebook/*': function(req, res, next) {
                    return sails.hooks.userlogin.facebookLogin(req, res, next);
                },

                '/twitter/*': function(req, res, next) {
                    return sails.hooks.userlogin.twitterLogin(req, res, next);
                },

                '/github/*': function(req, res, next) {
                    return sails.hooks.userlogin.githubLogin(req, res, next);
                },

                '/loggeduser': function(req, res) {
                  return sails.hooks.userlogin.loggedUser(req, res);
                },

                '/logout': function (req, res, next) {
                    return sails.hooks.userlogin.logout(req, res);
                }
            }
        },

        configure: function() {
            sails.log.info('configuring userlogin');
            sails.config[this.configKey] = sails.config[this.configKey] || {};
            _.defaults(sails.config[this.configKey], this.__configKey__);
        },

        initialize: function(cb) {
            var self = this;
            sails.on('hook:orm:loaded', function() {
                sails.log.info('initializing userlogin');

                // Check if the User model already exists
                if (self.getUserModel())
                    return self.initPassport(cb);

                // Inject a user model otherwise
                var userModel = {
                    globalId: sails.config[self.configKey].userModel,
                    attributes: {
                        toJSON: function() {
                            var obj = this.toObject();
                            // There is no valid reason to ever return a password
                            if ('password' in obj)
                                delete obj.password;
                            return obj;
                        }
                    },
                    beforeCreate: function(user, cb) {
                        this.hashPassword(user, cb);
                    },
                    hashPassword: function(user, cb) {
                        // If user has password, store hash instead
                        if ('password' in user) {
                            bcrypt.genSalt(10, function(err, salt) {
                                bcrypt.hash(user.password, salt, function(err, hash) {
                                    if (err) {
                                        cb(err);
                                    }
                                    else {
                                        user.password = hash;
                                        cb(null, user);
                                    }
                                });
                            });
                        }
                        else
                          cb(null, user);
                    }
                };
                sails.log.info('injecting ' + userModel.globalId + ' model');
                injectModel(sails, userModel, function () {
                    return self.initPassport(cb);
                });
            });
        },

        getUserModel: function() {
            var userModel = sails.config[this.configKey].userModel;
            if (userModel.toLowerCase() in sails.models)
                return sails.models[userModel.toLowerCase()];
            return null;
        },

        processRedirectUrl: function(req, res) {
            var redirectUrl = req.param('redirecturl');
            if (redirectUrl)
              req.session[$LOGIN_REDIRECT_URL$] = redirectUrl;
        },

        localLogin: function(req, res, next) {
            this.authenticate(req, res, 'local', {
            }, sails.config.userlogin.loginCallback, next);
        },

        googleLogin: function(req, res, next) {
            this.processRedirectUrl(req, res);
            this.authenticate(req, res, 'google', {
                scope: ['https://www.googleapis.com/auth/plus.login', 'email']
            }, sails.config.userlogin.loginCallback, next);
        },

        facebookLogin: function(req, res, next) {
            this.processRedirectUrl(req, res);
            this.authenticate(req, res, 'facebook', {
                scope: ['email']
            }, sails.config.userlogin.loginCallback, next);
        },

        twitterLogin: function(req, res, next) {
            this.processRedirectUrl(req, res);
            this.authenticate(req, res, 'twitter', {
            }, sails.config.userlogin.loginCallback, next);
        },

        githubLogin: function(req, res, next) {
            this.processRedirectUrl(req, res);
            this.authenticate(req, res, 'github', {
            }, sails.config.userlogin.loginCallback, next);
        },

        loggedUser: function(req, res) {
          if (req.isAuthenticated())
              return res.json(req.user);

          return res.notFound('No user logged in');
        },

        logout: function(req, res) {
            delete req.session.redirectUrl;
            req.logout();
            res.redirect('/');
        }
    }, authenticate);
};
