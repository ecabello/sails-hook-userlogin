'use strict';

var async = require('async');

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


module.exports = injectModel;
