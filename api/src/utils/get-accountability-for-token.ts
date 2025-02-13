import { InvalidCredentialsError } from '@directus/errors';
import getDatabase from '../database/index.js';
import { fetchRolesTree } from '../permissions/lib/fetch-roles-tree.js';
import { fetchGlobalAccess } from '../permissions/modules/fetch-global-access/fetch-global-access.js';
import { createDefaultAccountability } from '../permissions/utils/create-default-accountability.js';
import { getSecret } from './get-secret.js';
import isDirectusJWT from './is-directus-jwt.js';
import { verifyAccessJWT } from './jwt.js';
import { verifySessionJWT } from './verify-session-jwt.js';
import { useEnv } from '@directus/env';
import axios from 'axios';

const env = useEnv();
const isKeyCloakProvider = env["AUTH_PROVIDERS"] === "keycloak";

const verifyKeycloakToken = async (token: string) => {
	console.log("Verify token: " + token);
	return new Promise((resolve, reject) => {
		const clientId = env["AUTH_KEYCLOAK_CLIENT_ID"];
		const clientSecret = env["AUTH_KEYCLOAK_CLIENT_SECRET"];
		const data = `token=${token}&client_id=${clientId}&client_secret=${clientSecret}`;

		const config = {
			method: 'post',
			maxBodyLength: Infinity,
			url: `${env["AUTH_KEYCLOAK_ISSUER"]}/protocol/openid-connect/token/introspect`,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			data: data
		};

		axios.request(config)
			.then((response) => {
				const data = response.data;
				console.log("Check token: ", data);

				if (data && data.active) {
					resolve(data);
				}
				else {
					reject(new Error("Token not valid"));
				}
			})
			.catch((error) => {
				console.log("Error verify keycloak token", error);
				reject(error);
			});
	});
};

export async function getAccountabilityForToken(token: string, accountability: any) {
	if (!accountability) {
		accountability = createDefaultAccountability();
	}

	// Try finding the user with the provided token
	const database = getDatabase();

	if (token) {
		if (isDirectusJWT(token)) {
			const payload = verifyAccessJWT(token, getSecret());

			if ('session' in payload) {
				await verifySessionJWT(payload);
			}

			if (payload.share)
				accountability.share = payload.share;
			if (payload.id)
				accountability.user = payload.id;
			accountability.role = payload.role;
			accountability.roles = await fetchRolesTree(payload.role, database);
			const { admin, app } = await fetchGlobalAccess(accountability, database);
			accountability.admin = admin;
			accountability.app = app;
		}
		else {
			let user = await database
				.select('directus_users.id', 'directus_users.role')
				.from('directus_users')
				.where({
					'directus_users.token': token,
					status: 'active',
				})
				.first();

			if (!user) {
				try {
					if (isKeyCloakProvider) {
						const decoded: any = await verifyKeycloakToken(token);

						if (decoded) {
							user = await database
								.select('directus_users.id', 'directus_users.role')
								.from('directus_users')
								.where({
									'directus_users.email': decoded?.email,
									status: 'active'
								})
								.first();

							if (!user) {
								throw new InvalidCredentialsError();
							}
						}
					}
					else {
						throw new InvalidCredentialsError();
					}
				}
				catch (err) {
					throw new InvalidCredentialsError();
				}
			}

			accountability.user = user.id;
			accountability.role = user.role;
			accountability.roles = await fetchRolesTree(user.role, database);
			const { admin, app } = await fetchGlobalAccess(accountability, database);
			accountability.admin = admin;
			accountability.app = app;
		}
	}

	return accountability;
}