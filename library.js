'use strict';

(function (module) {
	const user = require.main.require('./src/user');
	const groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');

	const async = require('async');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	// use Unirest API or Request API for making https requests
	const useUnirestAPI = true;

	// create constants object
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
		allowedEntitlementsList: nconf.get('oauth_plugin:allowedEntitlements').split(','),
		setFullname: nconf.get('oauth_plugin:setFullname'),
		debugOutput: nconf.get('oauth_plugin:enableDebugOutput'),
	});

	if (constants.debugOutput !== undefined && constants.debugOutput) {
		winston.verbose('[maxonID] Configuration');
		console.log(constants);
	}

	// check the contants object for contain data
	let configOk = false;
	if (constants.name === undefined || constants.name === '') {
		winston.error('[maxonID] Please specify a name for your OAuth provider');
	} else if (constants.oauth2.clientID === undefined || constants.oauth2.clientID === '') {
		winston.error('[maxonID] ClientID required');
	} else if (constants.oauth2.clientSecret === undefined || constants.oauth2.clientSecret === '') {
		winston.error('[maxonID] Client Secret required');
	} else if (constants.oauth2.authorizationURL === undefined || constants.oauth2.authorizationURL === '') {
		winston.error('[maxonID] Authorization URL required');
	} else if (constants.oauth2.tokenURL === undefined || constants.oauth2.tokenURL === '') {
		winston.error('[maxonID] Token URL required');
	} else if (constants.scope === undefined || constants.scope === '') {
		winston.error('[maxonID] Scope required');
	} else if (constants.userRoute === undefined || constants.userRoute === '') {
		winston.error('[maxonID] User Route required');
	} else if (constants.allowedEntitlementsList === undefined || constants.allowedEntitlementsList === '') {
		winston.error('[maxonID] Allowed entitlements list required');
	} else if (constants.setFullname === undefined) {
		winston.error('[maxonID] Set fullname flag required');
	} else {
		configOk = true;
		winston.info('[maxonID] Config is OK');
	}

	// add member variable userMaxonIDIsEmpty to identify if a user is authenticated with Maxon ID
	const OAuth = { userMaxonIDIsEmpty: true };
	const oauthOptions = constants.oauth2;
	oauthOptions.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';
	oauthOptions.passReqToCallback = true;

	OAuth.getStrategy = function (strategies, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.getStrategy'); }

		let passportOAuth;
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

					// validate the user permissions given the current access token and the list of allowed entitlements
					OAuth.validateEntitlementsList(accessToken, constants.allowedEntitlementsList, function (err, accessAllowed) {
						if (constants.debugOutput !== undefined && constants.debugOutput) {
							winston.verbose('[maxonID] OAuth.validateEntitlementsList');
							console.log('validateEntitlementsList result:', accessAllowed);
						}

						if (err) {
							return done(err);
						}

						if (!accessAllowed) {
							// Need to find a way to gracefully notify the user and point back to login page
							return done(new Error('Forum access is not granted. Please contact your Maxon representative.'));
						}

						try {
							const parsedBody = JSON.parse(body);
							OAuth.parseUserReturn(parsedBody, function (err, profile) {
								if (err) {
									return done(err);
								}

								profile.provider = constants.name;
								profile.isAdmin = false;

								if (constants.debugOutput !== undefined && constants.debugOutput) {
									winston.verbose('[maxonID] Profile:');
									console.log(profile);
								}

								done(null, profile);
							});
						} catch (e) {
							done(e);
						}
					});
				});
			};

			passport.use(constants.name, new passportOAuth(oauthOptions, function (req, token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.handle,
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

	OAuth.validateEntitlementsList = function (token, entitlementsList, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.validateEntitlementsList'); }
		let completed_requests = 0; // count the number of requests completed
		let isAllowed = false; // store (sums via or) the entitlements allowance
		// loop through all the entitlements set in nodebb config.json
		for (var i = 0; i < entitlementsList.length; i += 1) {
			// prepare the input data to check if the user own the specific entitlement
			const item = [token.toString(), entitlementsList[i]];
			OAuth.checkEntitlement(item, function (response) {
				// sum the allowance
				isAllowed = isAllowed || response;
				completed_requests += 1;

				if (completed_requests === entitlementsList.length) {
					// return only all the requests have been completed
					callback(null, isAllowed);
				}
			});
		}
	};

	OAuth.checkEntitlement = function (inputData, callback) {
		const checkURL = nconf.get('oauth_plugin:idserver') + '/authz/.json?' + inputData[1] + '&doConsume=false';
		if (constants.debugOutput !== undefined && constants.debugOutput) winston.verbose('[maxonID] OAuth.checkEntitlement');
		if (useUnirestAPI) {
			const unirest = require('unirest');
			unirest('GET', checkURL)
				.headers({
					Authorization: 'Bearer ' + inputData[0],
				})
				.end(function (response) {
					if (response.error) throw new Error(response.error);

					const parsedBody = JSON.parse(response.raw_body);
					if (constants.debugOutput !== undefined && constants.debugOutput) console.log(parsedBody);
					if (typeof parsedBody[inputData[1]] !== 'undefined') {
						if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], parsedBody[inputData[1]]);
						return (callback(parsedBody[inputData[1]]));
					}
					if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], false);
					return (callback(false));
				});
		} else {
			const request = require('request');
			const requestOptions = {
				method: 'GET',
				url: checkURL,
				headers: {
					Authorization: 'Bearer ' + inputData[0],
				},
			};
			request(requestOptions, function (error, response) {
				if (error) { throw new Error(error); }

				const parsedBody = JSON.parse(response.body);
				if (constants.debugOutput !== undefined && constants.debugOutput) console.log(parsedBody);
				if (typeof parsedBody[inputData[1]] !== 'undefined') {
					if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], parsedBody[inputData[1]]);
					return (callback(parsedBody[inputData[1]]));
				}
				if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], false);
				return (callback(false));
			});
		}
	};

	OAuth.parseUserReturn = function (data, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) {
			winston.verbose('[maxonID] OAuth.parseUserReturn');
			console.log(data);
		}

		const profile = {};
		profile.id = data.sub;
		profile.givenName = data.given_name;
		profile.familyName = data.family_name;
		profile.emails = [{ value: data.email }];

		if (data.nickname === undefined || data.nickname === '') {
			profile.handle = data.email.split('@')[0];
		} else {
			profile.handle = data.nickname;
		}

		callback(null, profile);
	};

	OAuth.login = function (payload, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) {
			winston.verbose('[maxonID] OAuth.login');
			console.log(payload);
		}

		OAuth.getUidByOAuthid(payload.oAuthid, function (err, uid) {
			if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.getUidByOAuthid'); }

			if (err) { return callback(err); }

			if (uid !== null) {
				// Existing user
				callback(null, {
					uid: uid,
				});
			} else {
				// New user
				const success = function (uid) {
					// store oAuthID information
					user.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					// check given_name and family_name to generate a proper username (aka displayName)
					if (constants.setFullname && payload.name !== undefined && payload.name !== '' && payload.surname !== undefined && payload.surname !== '') {
						// set fullname
						user.setUserField(uid, 'fullname', payload.name + ' ' + payload.surname);
						db.setObjectField('fullname', payload.name + ' ' + payload.surname, uid);
					}

					// add user to "Maxon" group if registered email address belongs to "maxon.net" domain
					const domain = payload.email.split('@')[1];
					if (domain === 'maxon.net' || domain === 'redgiant.com' || domain === 'external.team' || domain === 'maxon.de') {
						groups.join('Maxon', uid, function (err) {
							callback(err, { uid: uid });
						});
					}

					// add user to administrator group
					if (payload.isAdmin) {
						groups.join('administrators', uid, function (err) {
							callback(err, { uid: uid });
						});
					}

					callback(null, { uid: uid });
				};

				user.getUidByEmail(payload.email, function (err, uid) {
					if (err) { return callback(err); }

					if (!uid) {
						user.create({
							username: payload.handle,
							email: payload.email,
						}, function (err, uid) {
							if (err) return callback(err);

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
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.getUidByOAuthid'); }
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function (err, uid) {
			if (err) return callback(err);

			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function (data, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.deleteUserData'); }

		async.waterfall([
			async.apply(user.getUserField, data.uid, constants.name + 'Id'),
			function (oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			},
		], function (err) {
			if (err) {
				winston.error('[maxonID] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	OAuth.whitelistFields = function (params, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.whitelistFields'); }

		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	OAuth.redirectLogout = function (payload, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) {
			winston.verbose('[maxonID] OAuth.redirectLogout');
			console.log('userMaxonIDIsEmpty: ', OAuth.userMaxonIDIsEmpty);
		}

		if (constants.oauth2.logoutURL && !OAuth.userMaxonIDIsEmpty) {
			winston.info('[maxonID] Changing logout to Maxon ID logout');
			let separator;

			if (constants.oauth2.logoutURL.indexOf('?') === -1) { separator = '?'; } else separator = '&';

			// define the right logout redirect
			payload.next = constants.oauth2.logoutURL + separator + 'triggerSingleSignout=true';

			// reset the property to the true state
			OAuth.userMaxonIDIsEmpty = true;
		}
		return callback(null, payload);
	};

	OAuth.userLoggedOut = function (params, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.userLoggedOut'); }

		user.getUserData(params.uid, function (err, data) {
			if (err) {
				winston.error('[maxonID] Could not find data for uid ' + params.uid + '. Error: ' + err);
				return callback(err);
			}

			// set property to false to make redirectLogout to redirect only Maxon ID(s)
			if (data[constants.name + 'Id'] != null && data[constants.name + 'Id'].length !== 0) { OAuth.userMaxonIDIsEmpty = false; }

			callback(null, params);
		});
	};

	module.exports = OAuth;
}(module));
