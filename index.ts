/// <reference path="./typings/node/node.d.ts"/>
/// <reference path="./typings/passport/passport.d.ts"/>

/**
 * Created by Dominic Böttger on 10.06.2015
 * INSPIRATIONlabs GmbH
 * http://www.inspirationlabs.com
 */
var wsfedsaml2 = require('passport-wsfed-saml2').Strategy;
var _ = require('lodash');

var molecuel;

class mlcl_auth_saml2 {
  molecuel:any;
  mlcl_user:any;
  usermodel:any;
  passport:any;
  jwt:any;
  app:any;

  constructor() {
    this.molecuel = molecuel;
    this.molecuel.on('mlcl::user::init:post', (usermodule:any) => {
      this.mlcl_user = usermodule;
      this.usermodel = usermodule.model;
      this.passport = usermodule.passport;
      this.jwt = usermodule.jwt;
      this.registerPassportfunction();
    });
  }
  registerPassportfunction() {
    if(this.molecuel.config.user.authtypes && this.molecuel.config.user.authtypes.saml2) {
      var conf = this.molecuel.config.user;
      this.passport.use(new wsfedsaml2(
      {
        path: '/login/saml2/callback',
        realm: conf.authtypes.saml2.realm,
        identityProviderUrl: conf.authtypes.saml2.identityProviderUrl,
        protocol: 'samlp',
        cert: conf.authtypes.saml2.cert
      },(profile, done) => {
        let unamefield = 'username';
        if(conf.authtypes.saml2.fieldmappings && conf.authtypes.saml2.fieldmappings.username) {
          unamefield = conf.authtypes.saml2.fieldmappings.username;
        }
        let susername = profile[unamefield];
        this.usermodel.findOne({ username: susername}, (err, doc) => {
          let userfieldmapping = (user) => {
            if(conf.authtypes.saml2.fieldmappings) {
              let reverseMappings = {};
              _.each(Object.keys(conf.authtypes.saml2.fieldmappings), (fieldname) => {
                reverseMappings[conf.authtypes.saml2.fieldmappings[fieldname]] = fieldname;
              });
              _.each(reverseMappings, (fieldname) => {
                this.molecuel.log.debug("mlcl_auth_saml2", fieldname + " " + conf.authtypes.saml2.fieldmappings[fieldname] + " " + profile[conf.authtypes.saml2.fieldmappings[fieldname]]);
                _.set(user, fieldname, profile[conf.authtypes.saml2.fieldmappings[fieldname]]);
              });
            } else {
              // use predefined fieldmappings (this possibly fails)
              user.username = profile.username;
              user.name.first = profile.firstname;
              user.name.last = profile.lastname;
              user.email = profile.email;
            }
            user.lastlogin = new Date();
          }
          if(doc) {
            userfieldmapping(doc);
            doc.save(function(err) {
              if(err) {
                molecuel.log.error('mlcl_auth_saml2', err.message, err);
              }
              done(err, doc.toObject());
            });
          } else {
            let user = new this.usermodel();
            user.authtype = 'saml2';
            userfieldmapping(user);
            user.save(function(err) {
              if(err) {
                molecuel.log.error('mlcl_auth_saml2', err.message, err);
              }
              done(err, user.toObject());
            });
          }
        });
      }));
    }
  }

  middleware(config, app) {
    let usermodule = molecuel.modules.user.module;
    let passport = usermodule.passport;
    app.get('/login/saml2',
      passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: false, session: false }),
      function(req, res) {
        res.redirect('/');
      }
    );
    app.post('/login/saml2/callback',
      passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: false, session: false }),
      function(req, res) {
        usermodule.getUserObjectFromRequest(req, function(err, userObject) {
          molecuel.log.info('mlcl_user', 'authenticated', {username: userObject.name, _id: userObject._id, method: 'saml2'});
          molecuel.log.info('mlcl_auth_saml2', 'authenticated', {username: userObject.name, _id: userObject._id, method: 'saml2'});
          res.status(200).send('\
            <html> \
              <head></head> \
              <body> \
                <script> \
                  localStorage.setItem(\'userData\', \''+ JSON.stringify(userObject) + '\'); \
                  console.log(localStorage.getItem(\'userData\')); \
                </script> \
              </body> \
            </html>');
        });
      }
    );
  }
}


/* ************************************************************************
 SINGLETON CLASS DEFINITION
 ************************************************************************ */
var instance = null;

var getInstance = function(){
  return instance || (instance = new mlcl_auth_saml2());
};

var init = function (m) {
  molecuel = m;
  // store molecuel instance
  return getInstance();
};

module.exports = init;
