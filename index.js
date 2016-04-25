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
                            var reverseMappings_1 = {};
                            _.each(Object.keys(conf.authtypes.saml2.fieldmappings), function (fieldname) {
                                reverseMappings_1[conf.authtypes.saml2.fieldmappings[fieldname]] = fieldname;
                            });
                            _.each(reverseMappings_1, function (fieldname) {
                                _this.molecuel.log.debug("mlcl_auth_saml2", fieldname + " " + conf.authtypes.saml2.fieldmappings[fieldname] + " " + profile[conf.authtypes.saml2.fieldmappings[fieldname]]);
                                _.set(user, fieldname, profile[conf.authtypes.saml2.fieldmappings[fieldname]]);
                            });
                        }
                        else {
                            user.username = profile.username;
                            user.name.first = profile.firstname;
                            user.name.last = profile.lastname;
                            user.email = profile.email;
                        }
                        user.lastlogin = new Date();
                    };
                    if (doc) {
                        userfieldmapping(doc);
                        doc.save(function (err) {
                            if (err) {
                                molecuel.log.error('mlcl_auth_saml2', err.message, err);
                            }
                            done(err, doc.toObject());
                        });
                    }
                    else {
                        var user_1 = new _this.usermodel();
                        user_1.authtype = 'saml2';
                        userfieldmapping(user_1);
                        user_1.save(function (err) {
                            if (err) {
                                molecuel.log.error('mlcl_auth_saml2', err.message, err);
                            }
                            done(err, user_1.toObject());
                        });
                    }
                });
            }));
        }
    };
    mlcl_auth_saml2.prototype.middleware = function (config, app) {
        var usermodule = molecuel.modules.user.module;
        var passport = usermodule.passport;
        app.get('/login/saml2', passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: false, session: false }), function (req, res) {
            res.redirect('/');
        });
        app.post('/login/saml2/callback', passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: false, session: false }), function (req, res) {
            usermodule.getUserObjectFromRequest(req, function (err, userObject) {
                molecuel.log.info('mlcl_user', 'authenticated', { username: userObject.name, _id: userObject._id, method: 'saml2' });
                molecuel.log.info('mlcl_auth_saml2', 'authenticated', { username: userObject.name, _id: userObject._id, method: 'saml2' });
                res.status(200).send('\
            <html> \
              <head></head> \
              <body> \
                <script> \
                  localStorage.setItem(\'userData\', \'' + JSON.stringify(userObject) + '\'); \
                  console.log(localStorage.getItem(\'userData\')); \
                </script> \
              </body> \
            </html>');
            });
        });
    };
    return mlcl_auth_saml2;
}());
var instance = null;
var getInstance = function () {
    return instance || (instance = new mlcl_auth_saml2());
};
var init = function (m) {
    molecuel = m;
    return getInstance();
};
module.exports = init;
