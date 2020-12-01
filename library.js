'use strict';

(function (module) {
	const User = require.main.require('./src/user');
	const Groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');

	const async = require('async');
	const axios = require('axios');
	const unirest = require('unirest');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	const constants = Object.freeze({
		type: nconf.get('oauth_plugin:type'),
		name: nconf.get('oauth_plugin:name'),
		oauth2: {
			authorizationURL: nconf.get('oauth_plugin:authorizationURL'),
			tokenURL: nconf.get('oauth_plugin:tokenURL'),
			clientID: nconf.get('oauth_plugin:clientID'),
			clientSecret: nconf.get('oauth_plugin:clientSecret'),
		},
		userRoute: nconf.get('oauth_plugin:userRoute'),
		scope: nconf.get('oauth_plugin:scope'),
		allowedEntitlement: nconf.get('oauth_plugin:allowedEntitlement'),
	});

	const OAuth = {};
	let configOk = false;
	let passportOAuth;
	let opts;

	if (!constants.name) {
		winston.error('[sso-oauth] --> Please specify a name for your OAuth provider (library.js:32)');
	} 	else if (!constants.type || constants.type !== 'oauth2') {
		winston.error('[sso-oauth] --> Please specify an OAuth strategy to utilise (library.js:31)');
	} else if (!constants.userRoute) 	{
		winston.error('[sso-oauth] --> User Route required (library.js:31)');
	} else {
		configOk = true;
		winston.info('[sso-oauth] --> Config is OK');
	}

	OAuth.getStrategy = function (strategies, callback) {
		winston.verbose('[sso-oauth] --> OAuth.getStrategy');
		if (configOk) {
			passportOAuth = require('passport-oauth2');

			passportOAuth.Strategy.prototype.userProfile = function (accessToken, done) {
				if (!accessToken) {
					done(new Error('Missing token, cannot call the userinfo endpoint without it.'));
				}
				this._oauth2.useAuthorizationHeaderforGET(true);
				this._oauth2.get(constants.userRoute, accessToken, function (err, body, res) {
					if (err) {
						console.error(err);
						return done(new Error('Failed to get user info. Exception was previously logged.'));
					}

					if (res.statusCode < 200 || res.statusCode > 299) {
						return done(new Error('Unexpected response from userInfo. [' + res.statusCode + '] [' + body + ']'));
					}

					try {
						var json = JSON.parse(body);
						OAuth.parseUserReturn(json, function (err, profile) {
							if (err) { return done(err); }

							profile.provider = constants.name;
							profile.isAdmin = false;
							console.log(profile);
							done(null, profile);
						});
					} catch (e) {
						done(e);
					}
				});
			};

			opts = constants.oauth2;
			opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';
			opts.passReqToCallback = true;

			winston.verbose('[sso-oauth] --> Options:');
			console.log(opts);

			passport.use(constants.name, new passportOAuth(opts, function (req, token, secret, profile, done) {
				OAuth.validateEntitlement(token, constants.allowedEntitlement, function (err, isOK) {
					if (err) {
						return done(err);
					}

					OAuth.login({
						oAuthid: profile.id,
						handle: profile.displayName,
						email: profile.emails[0].value,
						isAdmin: profile.isAdmin,
						isAllowed: isOK,
					}, function (err, user) {
						if (err) {
							return done(err);
						}

						authenticationController.onSuccessfulLogin(req, user.uid);
						done(null, user);
					});
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-check-square',
				scope: (constants.scope || '').split(','),
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.validateEntitlement = function (token, entitlement, callback)	{
		winston.verbose('[sso-auth] --> OAuth.validateEntitlement');

		unirest('GET', 'https://id-dev.villa.maxon.net/authz/.json?' + entitlement.toString() + '&doConsume=false')
			.headers({
				Authorization: 'Bearer ' + token.toString(),
			})
			.end(function (res) {
				if (res.error) { throw new Error(res.error); }
				var json = JSON.parse(res.raw_body);
				var isOK = json[entitlement.toString()];
				callback(null, isOK);
			});
	};

	OAuth.validateEntitlement2 = function (token, entitlement, callback) {
		winston.verbose('[sso-auth] --> OAuth.validateEntitlement');

		var config = {
			method: 'get',
			url: 'https://id-dev.villa.maxon.net/authz/.json?' + entitlement.toString() + '&doConsume=false',
			headers: {
				Authorization: 'Bearer ' + token.toString(),
			},
		};

		axios(config)
			.then(function (response) {
				var isOK = response.data[entitlement.toString()];
				callback(null, isOK);
			})
			.catch(function (error) {
				console.log(error);
			});
	};

	OAuth.parseUserReturn = function (data, callback) {
		winston.verbose('[sso-auth] --> OAuth.parseUserReturn');

		var profile = {};
		profile.id = data.sub;
		profile.displayName = data.email.split('@')[0];
		profile.emails = [{ value: data.email }];

		// eslint-disable-next-line
		callback(null, profile);
	};

	OAuth.login = function (payload, callback) {
		winston.verbose('[sso-auth] --> OAuth.login');
		console.log(payload);

		OAuth.getUidByOAuthid(payload.oAuthid, function (err, uid) {
			if (err) { return callback(err); }

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid,
				});
			} else {
				// New User
				var success = function (uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function (err) {
							callback(err, {
								uid: uid,
							});
						});
					} else {
						callback(null, {
							uid: uid,
						});
					}
				};

				User.getUidByEmail(payload.email, function (err, uid) {
					if (err) {
						return callback(err);
					}

					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email,
						}, function (err, uid) {
							if (err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function (oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function (err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function (data, callback) {
		winston.verbose('[sso-auth] --> OAuth.deleteUserData');
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			function (oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			},
		], function (err) {
			if (err) {
				winston.error('[sso-oauth] --> Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	OAuth.whitelistFields = function (params, callback) {
		winston.verbose('[sso-auth] --> OAuth.whitelistFields');
		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	OAuth.redirectLogout = function (payload, callback) {
		winston.verbose('[sso-auth] --> OAuth.redirectLogout');
		const settings = constants.pluginSettings.getWrapper();

		if (settings.logoutEndpoint) {
			winston.verbose('Changing logout to OpenID logout');
			let separator;
			if (settings.logoutEndpoint.indexOf('?') === -1) {
				separator = '?';
			} else {
				separator = '&';
			}
			payload.next = settings.logoutEndpoint + separator + 'client_id=' + settings.clientId;
		}

		return callback(null, payload);
	};

	module.exports = OAuth;
}(module));
