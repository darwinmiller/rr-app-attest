import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { sign } from 'hono/jwt';
import { AttestationService } from '../services/attestationService';
import { SessionService } from '../services/sessionService';
import { DeviceService } from '../services/deviceService';
import { AccountService } from '../services/accountService';
import { AppleService } from '../services/appleService';
import { Env } from '../types';
import { arrayBufferToBase64, base64ToArrayBuffer, sha256, concatArrayBuffers, verifyEcdsaSignatureFlexible } from '../utils/crypto';
import { cborgDecode } from '../utils/cborg';
import { authMiddleware } from '../middleware/auth';
import { UserService } from '../services/userService';

const registerDeviceSchema = z.object({
    keyId: z.string(),
    attestationObject: z.string(),
    challenge: z.string(),
    userAgent: z.string().optional(),
});

const refreshAssertionSchema = z.object({
    keyId: z.string(),
    challenge: z.string(), // base64
    assertion: z.string(), // base64
});

const appleVerifySchema = z.object({
    identityToken: z.string(),
    authorizationCode: z.string().optional(),
    fullName: z.string().optional(),
});

// moved profile update schemas/endpoints to profile route

// Add Apple Team ID and App Bundle ID to Cloudflare Worker environment variables/secrets.
// For local development, you can use a .dev.vars file.
interface AuthEnv extends Env {
    APPLE_TEAM_ID: string;
    APPLE_BUNDLE_ID: string;
    JWT_SECRET: string;
}

// Create a new Hono router instance for authentication-related endpoints.
const auth = new Hono<{ Bindings: AuthEnv }>();

/**
 * Endpoint to generate a new attestation challenge.
 * The iOS app calls this as the first step in the attestation process.
 * The challenge should be unique and single-use to prevent replay attacks.
 */
auth.get('/challenge', async (c) => {
    const attestationService = new AttestationService(c.env.DB, c.env.APPLE_TEAM_ID, c.env.APPLE_BUNDLE_ID, c.env.JWT_SECRET);
    const challenge = await attestationService.generateChallenge();

    return c.json({ challenge });
});

auth.post('/register-device', zValidator('json', registerDeviceSchema), async (c) => {
    const { keyId, attestationObject, challenge, userAgent } = c.req.valid('json');
    const attestationService = new AttestationService(c.env.DB, c.env.APPLE_TEAM_ID, c.env.APPLE_BUNDLE_ID, c.env.JWT_SECRET);
    const deviceService = new DeviceService(c.env.DB);
    const sessionService = new SessionService(c.env.DB, c.env.JWT_SECRET);

    const attestationResult = await attestationService.verifyAttestation(keyId, attestationObject, challenge);

    if (!attestationResult.success || !attestationResult.data) {
        return c.json({ status: 'error', message: 'Failed to attest device.' }, 400);
    }

    // Device is genuine. Create a device record.
    const device = await deviceService.createDevice({
        platform: 'ios', // Assuming iOS for now
        attestKeyId: keyId,
        publicKey: arrayBufferToBase64(attestationResult.data.publicKey),
        counter: attestationResult.data.counter,
        userAgent: userAgent || c.req.header('X-Device-Name') || c.req.header('User-Agent') || undefined,
    });

    console.log('[register-device] device created', { deviceId: device.id, attestKeyId: keyId });

    // Create a guest session for the new device.
    const { token } = await sessionService.createSession({ deviceId: device.id });

    return c.json({ status: 'ok', token });
});

auth.post('/signout', authMiddleware, async (c) => {
    // const session = c.get('session');
    // const sessionService = new SessionService(c.env.DB, c.env.JWT_SECRET);
    // In a stateful model, we would delete the session from the DB.
    // await sessionService.deleteSession(session.sessionId);
    // For stateless JWT, logout is handled client-side by deleting the token.
    // We can add the token to a blacklist if we need immediate revocation.
    return c.json({ status: 'ok', message: 'Signed out successfully.' });
});



/**
 * Exchanges a still-valid JWT for a fresh one with a renewed expiry.
 * This endpoint is protected; clients should proactively call it before expiry.
 */
auth.post('/refresh', authMiddleware, async (c) => {
    const session = c.get('session');
    const sessionService = new SessionService(c.env.DB, c.env.JWT_SECRET);

    console.log('[refresh] issuing new token', { deviceId: session.deviceId, userId: session.userId });

    const { token } = await sessionService.createSession({
        deviceId: session.deviceId,
        userId: session.userId,
    });

    return c.json({ token });
});

/**
 * Returns a short-lived refresh challenge bound to time.
 */
auth.get('/refresh-challenge', async (c) => {
    const attestationService = new AttestationService(c.env.DB, c.env.APPLE_TEAM_ID, c.env.APPLE_BUNDLE_ID, c.env.JWT_SECRET);
    const challenge = await attestationService.generateChallenge();
    return c.json({ challenge });
});

/**
 * Verifies a DCAppAttest assertion and issues a refreshed JWT.
 */
auth.post('/refresh-assertion', zValidator('json', refreshAssertionSchema), async (c) => {
    const { keyId, challenge, assertion } = c.req.valid('json');
    const deviceService = new DeviceService(c.env.DB);
    const sessionService = new SessionService(c.env.DB, c.env.JWT_SECRET);

    // Load device by keyId
    const device = await deviceService.getByAttestKeyId(keyId);
    if (!device) {
        return c.json({ status: 'error', message: 'Unknown device' }, 400);
    }

    console.log('[refresh-assertion] using device', { deviceId: device.id, attestKeyId: device.attestKeyId });

    // Verify challenge freshness and signature
    const attestationService = new AttestationService(c.env.DB, c.env.APPLE_TEAM_ID, c.env.APPLE_BUNDLE_ID, c.env.JWT_SECRET);
    const challengeOk = await attestationService.verifyChallenge(challenge);
    if (!challengeOk) {
        return c.json({ status: 'error', message: 'Invalid challenge' }, 400);
    }

    // Build clientDataHash as in Apple's guideline
    const challengeBuffer = base64ToArrayBuffer(challenge);
    const bundleIdBuffer = new TextEncoder().encode(c.env.APPLE_BUNDLE_ID);
    const clientData = concatArrayBuffers(challengeBuffer, bundleIdBuffer);
    const clientDataHash = await sha256(clientData);

    console.log('[refresh-assertion] verification details', {
        keyId,
        bundleId: c.env.APPLE_BUNDLE_ID,
        challenge,
        clientDataHash: arrayBufferToBase64(clientDataHash),
    });

    // Apple App Attest assertion structure (CBOR): authenticatorData (or authData), signature (or sig)
    // Recompute signature over (authenticatorData || clientDataHash)
    const decoded = cborgDecode(base64ToArrayBuffer(assertion)) as Map<any, any>;
    const authData: ArrayBuffer = decoded.get('authenticatorData') || decoded.get('authData') || decoded.get(1);
    const signature: ArrayBuffer = decoded.get('signature') || decoded.get('sig') || decoded.get(2);

    if (!authData || !signature) {
        const keys: any[] = [];
        if (decoded && typeof (decoded as any).forEach === 'function') {
            (decoded as Map<any, any>).forEach((v, k) => keys.push(k));
        }
        console.warn('[refresh-assertion] malformed assertion', { keyId, keys });
        return c.json({ status: 'error', message: 'Malformed assertion' }, 400);
    }

    // Verify that the RP ID hash in authData matches our app ID.
    const receivedRpIdHash = authData.slice(0, 32);
    const expectedRpIdHash = await sha256(new TextEncoder().encode(c.env.APPLE_TEAM_ID + '.' + c.env.APPLE_BUNDLE_ID));
    const rpIdHashMatch = arrayBufferToBase64(receivedRpIdHash) === arrayBufferToBase64(expectedRpIdHash);

    if (!rpIdHashMatch) {
        console.warn('[refresh-assertion] RP ID hash mismatch', {
            keyId,
            received: arrayBufferToBase64(receivedRpIdHash),
            expected: arrayBufferToBase64(expectedRpIdHash),
        });
        return c.json({ status: 'error', message: 'App ID mismatch in assertion' }, 400);
    }

    if ((authData as ArrayBuffer).byteLength < 37) {
        console.warn('[refresh-assertion] authenticatorData too short', { keyId, length: (authData as ArrayBuffer).byteLength });
        return c.json({ status: 'error', message: 'Malformed assertion' }, 400);
    }

    // Verify signature using stored public key
    const pubKeySpki = base64ToArrayBuffer(device.publicKey);
    const preimage = concatArrayBuffers(authData, clientDataHash);
    const nonce = await sha256(preimage);

    const ok = await verifyEcdsaSignatureFlexible(signature, nonce, pubKeySpki);

    if (!ok) {
        console.warn('[refresh-assertion] invalid signature', {
            keyId,
            authDataLen: (authData as ArrayBuffer).byteLength,
            sigLen: (signature as ArrayBuffer).byteLength,
        });
        return c.json({ status: 'error', message: 'Invalid assertion signature' }, 400);
    }

    // Parse counter from authData (bytes 33..37 as in attestation)
    // Parse counter from authenticatorData: flags at byte 32, signCount at bytes 33..36 (big-endian)
    const dv = new DataView(authData);
    const counter = dv.getUint32(33, false);
    if (counter <= device.counter) {
        console.warn('[refresh-assertion] replay detected', { keyId, deviceCounter: device.counter, receivedCounter: counter });
        return c.json({ status: 'error', message: 'Replay detected' }, 400);
    }

    await deviceService.updateCounter(device.id, counter);

    // All good: issue refreshed token, preserve linked user if present
    const { token } = await sessionService.createSession({ deviceId: device.id, userId: device.userId });
    console.log('[refresh-assertion] success', { keyId, deviceId: device.id });
    return c.json({ token });
});

// Link Apple account to the current device session and rotate JWT
auth.post('/apple/verify', authMiddleware, zValidator('json', appleVerifySchema), async (c) => {
    const session = c.get('session'); // device session
    const { identityToken, authorizationCode, fullName } = c.req.valid('json');

    const apple = new AppleService();
    const claims: any = await apple.verifyIdentityToken(identityToken, c.env.APPLE_BUNDLE_ID);
    // claims.sub is stable Apple user identifier

    const accountSvc = new AccountService(c.env.DB);
    const userSvc = new UserService(c.env.DB);
    const deviceSvc = new DeviceService(c.env.DB);
    const sessionSvc = new SessionService(c.env.DB, c.env.JWT_SECRET);

    let userId: string;
    const existing = await accountSvc.findByProviderAndAccountId('apple', claims.sub);
    if (existing) {
        userId = existing.userId;
    } else {
        const user = await userSvc.createUser(fullName ?? 'Apple User');
        await accountSvc.create({
            id: crypto.randomUUID(),
            userId: user.id,
            type: 'oauth-apple',
            provider: 'apple',
            providerAccountId: claims.sub,
            id_token: identityToken,
            access_token: null,
            refresh_token: null,
            token_type: null,
            scope: null,
            session_state: null,
        });
        userId = user.id;
    }

    await deviceSvc.updateUser(session.deviceId, userId);
    console.log('[apple/verify] linked device to user', { deviceId: session.deviceId, userId });

    const { token } = await sessionSvc.createSession({ deviceId: session.deviceId, userId });
    return c.json({ token });
});


export default auth;
