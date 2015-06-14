# sails-hook-userlogin

Basic User login functionality hook for sails.

It uses passports and a variety of Passport Strategies to allow login using several Social networks

# Passport Strategies

* Local
* Google
* Twitter
* Facebook
* Github


# Routes

The Hook intalls and handle the following routes

* POST /login
* /google/*
* /twitter/*
* /facebook/*
* /github/*
* /logout


# Configuration

By default the Hook will provide local Strategy login. It would use a user model
called User and the default login callback will send a json representation of
the user upon success.

All these can be changed and Social Network login can be enabled by adding a
userlogin.js file under your sails config directory.

For example to configure login for google and twitter social networks the config
would look like this.

module.exports.userlogin = {  
    google: {  
    clientID: 'YOUR-GOOGLE-CLIENTID',  
    clientSecret: 'PdgdRaq8VJC6EZjS5-Epf9RF',  
    callbackURL: 'http://localhost:1337/google/return'  
  },  
  twitter: {  
    clientID: 'YOUR-TWITTER-CONSUMER-KEY',  
    clientSecret: 'YOUR-TWITTER-CONSUMER_SECRET',  
    callbackURL: "https//localhost:1337/twitter/return"  
  }  
};  

The user model name can be changed by using the 'userModel' setting.

module.exports.userlogin = {  
  userModel: 'Customer'  
};

The Hook will check is the model exists. If it doesnt, the Hook will inject it.

Local login functionality can be suppressed by setting local to false.

module.exports.userlogin = {  
  local: false  
};
