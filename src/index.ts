import { cors } from '@elysiajs/cors';
import Elysia, { t } from 'elysia';
import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify } from 'jose';

export interface Env {
	FIREBASE_SERVICE_ACCOUNT_JSON: string;
}

const issuer = 'https://creatorsgarten.org';
const keySetUrl = new URL('https://creatorsgarten.org/.well-known/jwks');
const clientId = 'https://github.com/showdownspace/codeinthewind-editor-shell';
const keySet = createRemoteJWKSet(keySetUrl);

function validateAuthgartenIdToken(jwt: string) {
	// https://creatorsgarten.org/wiki/Authgarten#manual-integration
	return jwtVerify(jwt, keySet, { issuer, audience: clientId });
}

const envMap = new WeakMap<Request, Env>();
const app = new Elysia({ aot: false })
	.use(cors())
	.get('/', async () => {
		return { message: 'Welcome.' };
	})
	.post(
		'/firebase',
		async ({ body, request }) => {
			const result = await validateAuthgartenIdToken(body.idToken);
			console.log(result);

			// https://firebase.google.com/docs/auth/admin/create-custom-tokens
			const serviceAccount = JSON.parse(envMap.get(request)!.FIREBASE_SERVICE_ACCOUNT_JSON);
			const uid = `authgarten-${result.payload.sub}`;
			const payload = {
				uid,
				name: result.payload.name,
				claims: {
					name: result.payload.name,
					picture: result.payload.picture,
				},
			};
			const privateKey = await importPKCS8(serviceAccount.private_key, 'RS256');
			const customToken = await new SignJWT(payload)
				.setProtectedHeader({ alg: 'RS256' })
				.setIssuer(serviceAccount.client_email)
				.setSubject(serviceAccount.client_email)
				.setAudience('https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit')
				.setIssuedAt()
				.setExpirationTime('1h')
				.sign(privateKey);

			return { customToken };
		},
		{
			body: t.Object({
				idToken: t.String(),
			}),
		}
	);

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		envMap.set(request, env);
		return app.fetch(request);
	},
};
