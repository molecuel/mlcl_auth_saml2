/// <reference path="./typings/node/node.d.ts"/>
/// <reference path="./typings/passport/passport.d.ts"/>
var wsfedsaml2 = require('passport-wsfed-saml2').Strategy;
var _ = require('lodash');
var molecuel;
var mlcl_auth_saml2 = (function () {
    function mlcl_auth_saml2() {
        var _this = this;
        this.molecuel = molecuel;
        this.molecuel.on('mlcl::user::init:post', function (usermodule) {
            _this.mlcl_user = usermodule;
            _this.usermodel = usermodule.model;
            _this.passport = usermodule.passport;
            _this.jwt = usermodule.jwt;
            _this.registerPassportfunction();
        });
    }
    mlcl_auth_saml2.prototype.registerPassportfunction = function () {
        var _this = this;
        if (this.molecuel.config.user.authtypes && this.molecuel.config.user.authtypes.saml2) {
            var conf = this.molecuel.config.user;
            this.passport.use(new wsfedsaml2({
                path: '/login/saml2/callback',
                realm: conf.authtypes.saml2.realm,
                identityProviderUrl: conf.authtypes.saml2.identityProviderUrl,
                protocol: 'samlp',
                cert: conf.authtypes.saml2.cert
            }, function (profile, done) {
                var unamefield = 'username';
                if (conf.authtypes.saml2.fieldmappings && conf.authtypes.saml2.fieldmappings.username) {
                    unamefield = conf.authtypes.saml2.fieldmappings.username;
                }
                var susername = profile[unamefield];
                _this.usermodel.findOne({ username: susername }, function (err, doc) {
                    var userfieldmapping = function (user) {
                        if (conf.authtypes.saml2.fieldmappings) {
                            var reverseMappings = {};
                            _.each(Object.keys(conf.authtypes.saml2.fieldmappings), function (fieldname) {
                                reverseMappings[conf.authtypes.saml2.fieldmappings[fieldname]] = fieldname;
                            });
                            _.each(reverseMappings, function (fieldname) {
                                _.set(user, fieldname, profile[conf.authtypes.saml2.fieldmappings[fieldname]]);
                            });
                        }
                        else {
                            user.username = profile.username;
                            user.name.first = profile.firstname;
                            user.name.last = profile.lastname;
                            user.email = profile.email;
                        }
                    };
                    if (doc) {
                        userfieldmapping(doc);
                        console.log(doc);
                        doc.save(function (err) {
                            done(err, doc);
                        });
                    }
                    else {
                        var user = new _this.usermodel();
                        user.authtype = 'saml2';
                        userfieldmapping(user);
                        console.log(user);
                        user.save(function (err) {
                            done(err, user);
                        });
                    }
                });
            }));
        }
    };
    mlcl_auth_saml2.prototype.middleware = function (config, app, mod) {
        var usermodule = molecuel.modules.user.module;
        var passport = usermodule.passport;
        app.get('/login/saml2', passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: false }), function (req, res) {
            res.redirect('/');
        });
        app.post('/login/saml2/callback', passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: false }), function (req, res) {
            res.status(200).send('\
          <html> \
            <head></head> \
            <body> \
              <script> \
                localStorage.setItem(\'userdata\', \'' + JSON.stringify(usermodule.getUserObjectFromRequest(req)) + '\') \
                console.log(localStorage.getItem(\'userdata\')); \
              </script> \
            </body> \
          </html>');
        });
    };
    return mlcl_auth_saml2;
})();
var instance = null;
var getInstance = function () {
    return instance || (instance = new mlcl_auth_saml2());
};
var init = function (m) {
    molecuel = m;
    return getInstance();
};
module.exports = init;
