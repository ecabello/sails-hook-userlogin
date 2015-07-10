'use strict';

var bcrypt = require('bcryptjs'),
    passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    GitHubStrategy = require('passport-github').Strategy,
    FacebookStrategy = require('passport-facebook').Strategy,
    GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
    TwitterStrategy = require('passport-twitter').Strategy,
    enhanceResponse = require('sails/lib/hooks/views/res.view.js');

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
            if (sails.config.userlogin.local) {
                passport.use(new LocalStrategy(function(username, password, done) {
                    // locate user in the db by matching username or email
                    self.getUserModel().findOne({
                        or: [{username: username}, {email: username}]
                    }, function(err, user) {
                        if (err)
                            return done(err);
                        // Couldnt locate user
                        if (!user || !('password' in user))
                            return done(null, false, {message: 'Unknown user ' + username});

                        if (!sails.config.userlogin.canUserLogin(user))
                            return done(null, false, {message: 'User cannot log in'});
                        // Hash compare
                        bcrypt.compare(password, user.password, function(err, res) {
                            if (!res)
                                return done(null, false, {message: 'Invalid Password'});
                            // Hash matched
                            user.lastLogonAt = new Date();
                            self.getUserModel().update({id: user.id}, user).exec(function(err, users) {
                                return done(null, users[0], {message: 'Logged In Successfully'});
                            });
                        });
                    });
                }));
            }

            // Verify function for all social networks
            var socialVerify = function(token, tokenSecret, profile, done) {
                var criteria = [{}];
                // Macth profile.id
                criteria[0][profile.provider+'Id'] = profile.id;
                // or email
                if (profile.emails && profile.emails[0] && profile.emails[0].value)
                    criteria.push({email: profile.emails[0].value});

                self.getUserModel().findOne({
                  or: criteria
                }, function (err, user) {
                    if (err)
                        return done(err);

                    // Not found, create one
                    if (!user)
                        user = {};

                    return self.updateSocialProfile(user, profile, function(err, user) {
                        // check if user can log in
                        if (!sails.config.userlogin.canUserLogin(user))
                            return done(null, false, {message: 'User cannot log in'});

                        user.lastLogonAt = new Date();
                        if (user.id) {
                            // user already existed, just update it
                            self.getUserModel().update({id: user.id}, user).exec(function(err, users) {
                              return done(null, users[0], {message: 'Logged In Successfully'});
                            });
                        }
                        else {
                            //  new user
                            self.getUserModel().create(user, function(err, user) {
                                if (err)
                                    return done(err, null);
                                sails.log.info(user.displayName + ', a ' + profile.provider + ' user was created');
                                return done(null, user, {message: 'Logged In Successfully'});
                            });
                        }
                    });
                });
            };
            // if github was requested
            if (sails.config.userlogin.github) {
                passport.use(new GitHubStrategy({
                    clientID: sails.config[self.configKey].github.clientID,
                    clientSecret: sails.config[self.configKey].github.clientSecret,
                    callbackURL: sails.config[self.configKey].github.callbackURL
                }, socialVerify));
            }
            // if facebook was requested
            if (sails.config.userlogin.facebook) {
                passport.use(new FacebookStrategy({
                    clientID: sails.config[self.configKey].facebook.clientID,
                    clientSecret: sails.config[self.configKey].facebook.clientSecret,
                    callbackURL: sails.config[self.configKey].facebook.callbackURL,
                    profileFields: ['id', 'displayName',
                    'last_name', 'first_name', 'middle_name',
                    'photos', 'emails']
                }, socialVerify));
            }
            // if google was requested
            if (sails.config.userlogin.google) {
                passport.use(new GoogleStrategy({
                    clientID: sails.config[self.configKey].google.clientID,
                    clientSecret: sails.config[self.configKey].google.clientSecret,
                    callbackURL: sails.config[self.configKey].google.callbackURL
                }, socialVerify));
            }
            // if twitter was requested
            if (sails.config.userlogin.twitter) {
                passport.use(new TwitterStrategy({
                    consumerKey: sails.config[self.configKey].twitter.clientID,
                    consumerSecret: sails.config[self.configKey].twitter.clientSecret,
                    callbackURL: sails.config[self.configKey].twitter.callbackURL
                }, socialVerify));
            }
        };
        return cb();
    },

    updateSocialProfile: function(user, profile, callback) {
        sails.config.userlogin.updateSocialProfile.call(this, user, profile, function(err, user) {
          if (err)
              return callback(err, null);
          return callback(null, user);
        }.bind(this));
    },

    authenticate: function(req, res, strategy, options, callback, next) {
        if (!sails.config.userlogin[strategy]) {
            return enhanceResponse(req, res, function () {
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
