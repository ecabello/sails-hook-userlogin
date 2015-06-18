'use strict';

var bcrypt = require('bcryptjs'),
    passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    GitHubStrategy = require('passport-github').Strategy,
    FacebookStrategy = require('passport-facebook').Strategy,
    GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
    TwitterStrategy = require('passport-twitter').Strategy,
    _addResViewMethod = require('sails/lib/hooks/views/res.view.js');

module.exports={

  initPassport: function(cb) {
      var self = this;
      passport.serializeUser(function (user, done) {
          done(null, user.id);
      });
      passport.deserializeUser(function (id, done) {
          self.getUserModel().findOne(id, function (err, user) {
              return err ? done(null, null) : done(null, user);
          });
      });

      passport.initStrategies = function() {
          // if local was requested
          if (sails.config[self.configKey].local) {
              passport.use(new LocalStrategy(function(username, password, done) {
                  // locate user in the db
                  self.getUserModel().findOne({
                      username: username
                  }, function(err, user) {
                      if (err)
                          return done(err);
                      // Couldnt locate user
                      if (!user)
                          return done(null, false, {
                              message: 'Unknown user ' + username
                          });
                      // Hash compare
                      bcrypt.compare(password, user.password, function(err, res) {
                          if (!res)
                              return done(null, false, {
                                  message: 'Invalid Password'
                              });
                          // Hash matched
                          return done(null, user, {
                              message: 'Logged In Successfully'
                          });
                      });
                  });
              }));
          }

          // Verify function for all social networks
          var socialVerify = function(token, tokenSecret, profile, done) {
              var data = {};
              data[profile.provider + 'id'] = profile.id

              self.getUserModel().findOne(data, function (err, user) {
                  if (err)
                      return done(err);
                  // If the user is found, return it.
                  if (user)
                    return done(null, user, {
                        message: 'Logged In Successfully'
                    });
                  // Not found, create one
                  data.name = profile.displayName;

                  if (profile.emails && profile.emails[0] && profile.emails[0].value)
                      data.email = profile.emails[0].value;
                  if (profile.name && profile.name.givenName)
                      data.firstname = profile.name.givenName;
                  if (profile.name && profile.name.familyName)
                      data.lastname = profile.name.familyName;
                  // Create
                  self.getUserModel().create(data, function(err, user) {
                      sails.log.info(user.name + ', a ' + profile.provider + ' user was created');
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
                  consumerKey: sails.config[self.configKey].twitter.clientID,
                  consumerSecret: sails.config[self.configKey].twitter.clientSecret,
                  callbackURL: sails.config[self.configKey].twitter.callbackURL
              }, socialVerify));
          }
      };
      return cb();
  },

  authenticate: function(req, res, strategy, options, callback, next) {
      if (!sails.config.userlogin[strategy]) {
          _addResViewMethod(req, res, function () {
              return res.notFound(strategy + ' login not configured');
          });
      }
      else {
        passport.authenticate(strategy, options, function (err, user) {
          return callback(err, user, strategy, req, res);
        })(req, res, next);
      }
  },

  middleware: function(req, res, next) {
      passport.initialize()(req, res, function () {
          passport.session()(req, res, function () {
              passport.initStrategies();
              return next();
          });
      });
  }
};
