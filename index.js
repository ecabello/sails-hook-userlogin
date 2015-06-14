var _ = require('lodash'),
    authenticate = require('./lib/authenticate'),
    injectModel = require('./lib/injectmodel'),
    Waterline = require('sails/node_modules/waterline');


module.exports = function userlogin(sails) {
    sails.log.info('loading userlogin' );

    return _.extend({
        __configKey__: {
            local: true,
            userModel: 'User',
            loginCallback: function (err, user, provider, req, res) {
                if (err || !user) {
                    sails.log.info(provider + ' authentication failed');
                    return res.notFound('No user found');
                }
                req.logIn(user, function (err) {
                    return err ? res.send(err) : res.json(user);
                });
            }
        },

        routes: {
            before: {
                'POST /login': function (req, res, next) {
                    return sails.hooks.userlogin.localLogin(req, res);
                },

                '/google/*': function (req, res, next) {
                    return sails.hooks.userlogin.googleLogin(req, res);
                },

                  '/facebook/*': function (req, res, next) {
                    return sails.hooks.userlogin.facebookLogin(req, res);
                },

                '/twitter/*': function (req, res, next) {
                    return sails.hooks.userlogin.twitterLogin(req, res);
                },

                '/logout': function (req, res, next) {
                    return sails.hooks.userlogin.logout(req, res);
                }
            }
        },

        configure: function () {
            sails.log.info('configuring userlogin');
            sails.config[this.configKey] = sails.config[this.configKey] || {};
            _.defaults(sails.config[this.configKey], this.__configKey__);
        },

        initialize: function (cb) {
            var self = this;
            sails.on('hook:orm:loaded', function () {
                sails.log.info('initializing userlogin');

                // Check if the User model already exists
                if (self.getUserModel())
                    return self.initPassport(cb);

                // Inject a user model otherwise
                var userModel = {
                    globalId: sails.config[self.configKey].userModel,
                    attributes: {
                        provider: {
                            type: 'string',
                            required: true
                        },
                        toJSON: function () {
                            var obj = this.toObject();
                            // There is no valid reason to ever return a password
                            if ('password' in obj)
                                delete obj.password;
                            return obj;
                        }
                    },
                    beforeCreate: function (user, cb) {
                        this.hashPassword(user, cb);
                    },
                    hashPassword: function (user, cb) {
                        // If user has password, store hash instead
                        if ('password' in user) {
                            bcrypt.genSalt(10, function (err, salt) {
                                bcrypt.hash(user.password, salt, function (err, hash) {
                                    if (err) {
                                        console.log(err);
                                        cb(err);
                                    } else {
                                        user.password = hash;
                                        cb(null, user);
                                    }
                                });
                            });
                        } else cb(null, user);
                    }
                };
                sails.log.info('injecting ' + userModel.globalId + ' model');
                injectModel(sails, userModel, function () {
                    return self.initPassport(cb);
                });
            });
        },

        getUserModel: function () {
            var userModel = sails.config[this.configKey].userModel;
            if (userModel.toLowerCase() in sails.models)
                return sails.models[userModel.toLowerCase()];
            return null;
        },

        localLogin: function (req, res) {
            this.authenticate(req, res, 'local', {}, sails.config.userlogin.loginCallback);
        },

        githubLogin: function (req, res) {
            this.authenticate(req, res, 'github', {}, sails.config.userlogin.loginCallback);
        },

        googleLogin: function (req, res) {
            this.authenticate(req, res, 'google', {
                scope: ['https://www.googleapis.com/auth/plus.login', 'email']
            }, sails.config.userlogin.loginCallback);
        },

        facebookLogin: function (req, res) {
            this.authenticate(req, res, 'facebook', {
                scope: ['email']
            }, sails.config.userlogin.loginCallback);
        },

        twitterLogin: function (req, res) {
            this.authenticate(req, res, 'twitter', {}, sails.config.userlogin.loginCallback);
        },

        logout: function (req, res) {
            req.logout();
            res.redirect('/');
        }
    }, authenticate);
};
