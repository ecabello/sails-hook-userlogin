var _ = require('lodash'),
async = require('async'),
bcrypt = require('bcryptjs'),
passport = require('passport'),
LocalStrategy = require('passport-local').Strategy,
GitHubStrategy = require('passport-github').Strategy,
FacebookStrategy = require('passport-facebook').Strategy,
GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
TwitterStrategy = require('passport-twitter').Strategy,
Waterline = require("../sails/node_modules/waterline"),
_addResViewMethod = require("../sails/lib/hooks/views/res.view.js");


module.exports = function userlogin(sails) {
  sails.log.info('loading userlogin');

  function injectModel(sails, model, cb) {
    var loadUserModules = require('sails/lib/hooks/orm/load-user-modules')(sails);
    var normalizeModel = require('sails/lib/hooks/orm/normalize-model')(sails);

    async.auto({
      load: loadUserModules,

      // normalize model definition
      normalize: [ 'load', function(cb) {
        var modelDef = _.defaults({
          globalId: model.globalId,
          identity: model.globalId.toLowerCase(),
          connection: model.connection || sails.config.models.connection
        }, model);
        normalizeModel(modelDef, model.globalId.toLowerCase());
        cb();
      }],

      instantiateCollections: ['normalize', function(cb) {
        // reload orm
        sails.hooks.orm.reload();
        cb();
      }]
    }, cb);
  }

  return {
    __configKey__: {
      local: true,
      userModel: 'User',
      loginCallback: function(err, user, network, req, res) {
        if (err || !user) {
            sails.log.info(network + ' authentication failed');
            return res.notFound('No user found');
        }
        req.logIn(user, function(err) {
            if (err)
              return res.send(err);

            return res.json(user);
        });
      }
    },

    routes: {
      before: {
        'POST /login': function(req,res,next) {
          return sails.hooks.userlogin.localLogin(req,res);
        },

        '/google/*': function(req,res,next) {
          return sails.hooks.userlogin.googleLogin(req,res);
        },

        '/facebook/*': function(req,res,next) {
          return sails.hooks.userlogin.facebookLogin(req,res);
        },

        '/twitter/*': function(req,res,next) {
          return sails.hooks.userlogin.twitterLogin(req,res);
        },

        '/logout': function(req,res,next) {
          return sails.hooks.userlogin.logout(req,res);
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

        // Inject a user model
        var userModel = {
          globalId: sails.config[self.configKey].userModel,
          attributes: {
            provider: {
              type: 'string',
              required: true
            },
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
                    console.log(err);
                    cb(err);
                  }
                  else{
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
        injectModel(sails, userModel, function() {
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

    initPassport: function(cb) {
      var self = this;
      passport.serializeUser(function (user, done) {
        done(null, user.id);
      });
      passport.deserializeUser(function (id, done) {
        self.getUserModel().findOne(id, function (err, user) {
          if (err)
            return done(null, null);
          return done(null, user);
        });
      });

      passport.initStrategies=function() {
        // if local was requested
        if (sails.config[self.configKey].local) {
          // Use the LocalStrategy within Passport.
          // Strategies in passport require a `verify` function, which accept
          // credentials (in this case, a username and password), and invoke a callback
          // with a user object.
          passport.use(new LocalStrategy(
            function (username, password, done) {
              // locate user in the db
              self.getUserModel().findOne({ username: username }, function (err, user) {
                if (err)
                  return done(err);
                // Couldnt locate user
                if (!user)
                  return done(null, false, { message: 'Unknown user ' + username });
                // Hash compare
                bcrypt.compare(password, user.password, function(err, res) {
                  if (!res)
                    return done(null, false, {message: 'Invalid Password'});
                  // Hash matched
                  return done(null, user, {message: 'Logged In Successfully'});
                });
              });
            }
          ));
        }

        // Verify function for all social networks
        var socialVerify = function(token, tokenSecret, profile, done) {
          self.getUserModel().findOne({uid: profile.id}, function(err, user) {
            if (err)
              return done(err);

            // If the user is found, return it.
            if (user)
              return done(null, user, {message: 'Logged In Successfully'});

            // Not found, create one
            var data = {
              provider: profile.provider,
              uid: profile.id,
              name: profile.displayName
            };

            if (profile.emails && profile.emails[0] && profile.emails[0].value)
              data.email = profile.emails[0].value;

            if (profile.name && profile.name.givenName)
              data.firstname = profile.name.givenName;
            if (profile.name && profile.name.familyName)
              data.lastname = profile.name.familyName;

            self.getUserModel().create(data, function(err, user) {
              sails.log.info(user.name + ', a ' + user.provider + ' user was created');
              return done(err, user);
            });
          });
        };
        // if github was requested
        if (sails.config[self.configKey].github) {
          passport.use(new GitHubStrategy({
            clientID: sails.config[self.configKey].github.clientID,
            clientSecret: sails.config[self.configKey].github.clientSecret,
            callbackURL: sails.config[self.configKey].github.callbackURL
          }, socialVerify));
        }
        // if facebook was requested
        if (sails.config[self.configKey].facebook) {
          passport.use(new FacebookStrategy({
            clientID: sails.config[self.configKey].facebook.clientID,
            clientSecret: sails.config[self.configKey].facebook.clientSecret,
            callbackURL: sails.config[self.configKey].facebook.callbackURL
          }, socialVerify));
        }
        // if google was requested
        if (sails.config[self.configKey].google) {
          passport.use(new GoogleStrategy({
            clientID: sails.config[self.configKey].google.clientID,
            clientSecret: sails.config[self.configKey].google.clientSecret,
            callbackURL: sails.config[self.configKey].google.callbackURL
          }, socialVerify));
        }
        // if twitter was requested
        if (sails.config[self.configKey].twitter) {
          passport.use(new TwitterStrategy({
            consumerKey: sails.config[self.configKey].twitter.consumerKey,
            consumerSecret: sails.config[self.configKey].twitter.consumerSecret,
            callbackURL: sails.config[self.configKey].twitter.callbackURL
          }, socialVerify));
        }
      };
      return cb();
    },

    middleware: function(req,res, next) {
      passport.initialize()(req, res, function() {
        passport.session()(req, res, function() {
          passport.initStrategies();
          return next();
        });
      });
    },

    localLogin: function(req, res) {
      this.authenticate(req, res, 'local', {}, sails.config.userlogin.loginCallback);
    },

    githubLogin: function(req, res) {
      this.authenticate(req, res, 'github', {}, sails.config.userlogin.loginCallback);
    },

    googleLogin: function(req, res) {
      this.authenticate(req, res, 'google', {
        scope: ['https://www.googleapis.com/auth/plus.login', 'email']
      }, sails.config.userlogin.loginCallback);
    },

    facebookLogin: function(req, res) {
      this.authenticate(req, res, 'facebook', {scope: ['email']}, sails.config.userlogin.loginCallback);
    },

    twitterLogin: function(req, res) {
      this.authenticate(req, res, 'twitter', {}, sails.config.userlogin.loginCallback);
    },

    authenticate: function(req, res, strategy, options, callback) {
      if (!sails.config.userlogin[strategy]) {
        _addResViewMethod(req, res, function() {
          return res.notFound(strategy + ' login not configured');
        });
      }
      else
        passport.authenticate(strategy, options, function(err, user) {
            return callback(err, user, strategy, req, res);
        })(req, res);
    },

    logout: function(req, res) {
        req.logout();
        res.redirect('/');
    },
  };
};
