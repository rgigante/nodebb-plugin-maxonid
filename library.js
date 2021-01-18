'use strict';

(function (module) {
	const User = require.main.require('./src/user');
	const Groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');

	const async = require('async');

	// modules to execute HTTP requests
	const axios = require('axios');
	const unirest = require('unirest');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	const constants = Object.freeze({
		name: nconf.get('oauth_plugin:name'),
		oauth2: {
			authorizationURL: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:authorizationURL'),
			tokenURL: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:tokenURL'),
			logoutURL: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:logoutURL'),
			clientID: nconf.get('oauth_plugin:clientID'),
			clientSecret: nconf.get('oauth_plugin:clientSecret'),
		},
		userRoute: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:userRoute'),
		scope: nconf.get('oauth_plugin:scope'),
		allowedEntitlement: nconf.get('oauth_plugin:allowedEntitlement'),
	});

	winston.verbose('[maxonID] --> Constants');
	console.log(constants);

	let configOk = false;
	if (!constants.name) {
		winston.error('[maxonID] --> Please specify a name for your OAuth provider');
	} else if (!constants.userRoute) 	{
		winston.error('[maxonID] --> User Route required');
	} else {
		configOk = true;
		winston.info('[maxonID] --> Config is OK');
	}

	const OAuth = { userMaxonIDIsEmpty: true };
	const opts = constants.oauth2;
	opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';
	opts.passReqToCallback = true;
	let passportOAuth;

	// debug options
	winston.verbose('[maxonID] --> Options:');
	console.log(opts);

	OAuth.getStrategy = function (strategies, callback) {
		winston.verbose('[maxonID] --> OAuth.getStrategy');
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

					OAuth.validateEntitlement(accessToken, constants.allowedEntitlement, function (err, accessAllowed) {
						if (err) {
							return done(err);
						}

						if (!accessAllowed) {
							// Need to find a way to gracefully notify the user and point back to login page
							return done(new Error('Forum access is not granted. Please contact your Maxon representative.'));
						}

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function (err, profile) {
								if (err) { return done(err); }

								profile.provider = constants.name;
								profile.isAdmin = false;

								winston.verbose('[maxonID] --> Profile:');
								console.log(profile);
								done(null, profile);
							});
						} catch (e) {
							done(e);
						}
					});
				});
			};

			passport.use(constants.name, new passportOAuth(opts, function (req, token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.displayName,
					email: profile.emails[0].value,
					isAdmin: profile.isAdmin,
					name: profile.givenName,
					surname: profile.familyName,
				}, function (err, user) {
					if (err) {
						return done(err);
					}

					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-lock',
				scope: (constants.scope || '').split(','),
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	// uses unirest API
	OAuth.validateEntitlement = function (token, entitlement, callback)	{
		winston.verbose('[maxonID] --> OAuth.validateEntitlement');

		unirest('GET', nconf.get('oauth_plugin:idserver') + '/authz/.json?' + entitlement.toString() + '&doConsume=false')
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

	// uses Axios API
	OAuth.validateEntitlement2 = function (token, entitlement, callback) {
		winston.verbose('[maxonID] --> OAuth.validateEntitlement');

		var config = {
			method: 'get',
			url: nconf.get('oauth_plugin:idserver') + '/authz/.json?' + entitlement.toString() + '&doConsume=false',
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
		winston.verbose('[maxonID] --> OAuth.parseUserReturn');
		console.log(data);

		var profile = {};
		profile.id = data.sub;
		profile.givenName = data.given_name;
		profile.familyName = data.family_name;
		profile.displayName = data.email.split('@')[0];
		profile.emails = [{ value: data.email }];

		// eslint-disable-next-line
		callback(null, profile);
	};

	OAuth.login = function (payload, callback) {
		winston.verbose('[maxonID] --> OAuth.login');
		winston.verbose('[maxonID] --> Payload:');
		console.log(payload);

		OAuth.getUidByOAuthid(payload.oAuthid, function (err, uid) {
			winston.verbose('[maxonID] --> OAuth.getUidByOAuthid');
			if (err) { return callback(err); }

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid,
				});
			} else {
				// New User
				var success = function (uid) {
					// save provider-specific information to the user
					// save oAuthID
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);
					// save name and surname
					User.setUserField(uid, 'fullname', payload.name + ' ' + payload.surname);
					db.setObjectField('fullname', payload.name + ' ' + payload.surname, uid);

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
		winston.verbose('[maxonID] --> OAuth.getUidByOAuthid');
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function (err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.getOAuthidByUid = function (uid, callback) {
		winston.verbose('[maxonID] --> OAuth.getOAuthidByUid');
		db.getObjectField('uid', uid, function (err, oAuthid) {
			if (err) {
				return callback(err);
			}
			callback(null, oAuthid);
		});
	};

	OAuth.deleteUserData = function (data, callback) {
		winston.verbose('[maxonID] --> OAuth.deleteUserData');
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			function (oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			},
		], function (err) {
			if (err) {
				winston.error('[maxonID] --> Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	OAuth.whitelistFields = function (params, callback) {
		winston.verbose('[maxonID] --> OAuth.whitelistFields');
		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	OAuth.redirectLogout = function (payload, callback) {
		winston.verbose('[maxonID] --> OAuth.redirectLogout');

		console.log('userMaxonIDIsEmpty: ', OAuth.userMaxonIDIsEmpty);
		if (constants.oauth2.logoutURL && !OAuth.userMaxonIDIsEmpty) {
			winston.verbose('Changing logout to Maxon ID logout');
			let separator;
			if (constants.oauth2.logoutURL.indexOf('?') === -1) {
				separator = '?';
			} else {
				separator = '&';
			}
			// define the right logout redirect
			payload.next = constants.oauth2.logoutURL + separator + 'triggerSingleSignout=true';

			// reset the property to the true state
			OAuth.userMaxonIDIsEmpty = true;
		}
		console.log(payload.next);

		return callback(null, payload);
	};

	OAuth.userLoggedOut = function (params, callback) {
		winston.verbose('[maxonID] --> OAuth.userLoggedOut');
		User.getUserData(params.uid, function (err, data) {
			if (err) {
				winston.error('[maxonID] --> Could not find data for uid ' + params.uid + '. Error: ' + err);
				return callback(err);
			}
			if (data[constants.name + 'Id'] != null && data[constants.name + 'Id'].length !== 0) {
				// set property to false to make redirectLogout to redirect only Maxon ID(s)
				OAuth.userMaxonIDIsEmpty = false;
			}
			callback(null, params);
		});
	};

	module.exports = OAuth;
}(module));
