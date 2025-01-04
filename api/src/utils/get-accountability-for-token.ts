import { InvalidCredentialsError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import getDatabase from '../database/index.js';
import { fetchRolesTree } from '../permissions/lib/fetch-roles-tree.js';
import { fetchGlobalAccess } from '../permissions/modules/fetch-global-access/fetch-global-access.js';
import { createDefaultAccountability } from '../permissions/utils/create-default-accountability.js';
import { getSecret } from './get-secret.js';
import isDirectusJWT from './is-directus-jwt.js';
import { verifyAccessJWT } from './jwt.js';
import { verifySessionJWT } from './verify-session-jwt.js';
import jwt, { type JwtPayload, type SigningKeyCallback, type VerifyErrors } from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { useEnv } from '@directus/env';

const env = useEnv();

const isKeyCloakProvider = env["AUTH_PROVIDER"] === "keycloak";

const jksClient = jwksClient({
	jwksUri: `${env["AUTH_KEYCLOAK_ISSUER"]}/protocol/openid-connect/certs`, // Replace with your Keycloak JWKS URI
});

// Function to retrieve the signing key from Keycloak
const getKeycloakPublicKey = (header: jwt.JwtHeader, callback: SigningKeyCallback): void => {
	jksClient.getSigningKey(header.kid, (err, key) => {
		if (err) {
			callback(err);
			return;
		}

		const signingKey = key?.getPublicKey();
		callback(null, signingKey);
	});
};

// Function to verify the JWT
const verifyKeycloakToken = async (token: string): Promise<JwtPayload | string> => {
	return new Promise((resolve, reject) => {
		jwt.verify(
			token,
			getKeycloakPublicKey,
			{
				algorithms: ["RS256"], // Ensure this matches the algorithm configured in Keycloak
				// audience: "crs_client", // Replace with your Keycloak client ID
				issuer: env["AUTH_KEYCLOAK_ISSUER"] as string, // Replace with your Keycloak realm issuer

			},
			(err: VerifyErrors | null, decoded: JwtPayload | string | undefined) => {
				if (err) {
					reject(err);
				} else {
					resolve(decoded!);
				}
			}
		);
	});
};

export async function getAccountabilityForToken(
	token?: string | null,
	accountability?: Accountability,
): Promise<Accountability> {
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

			if (payload.share) accountability.share = payload.share;

			if (payload.id) accountability.user = payload.id;

			accountability.role = payload.role;
			accountability.roles = await fetchRolesTree(payload.role, database);

			const { admin, app } = await fetchGlobalAccess(accountability, database);

			accountability.admin = admin;
			accountability.app = app;
		} else {
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
						const decoded = await verifyKeycloakToken(token);

						if (decoded) {
							user = await database
								.select('directus_users.id', 'directus_users.role')
								.from('directus_users')
								.where({
									status: 'active'
								})
								.first();

							if (!user) {
								throw new InvalidCredentialsError();
							}
						}
					} else {
						throw new InvalidCredentialsError();
					}
				} catch (err) {
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
