import { D1Database } from '@cloudflare/workers-types';
import { Certificate, CertificateChainValidationEngine } from 'pkijs';
import { fromBER } from 'asn1js';
import { cborgDecode } from '../utils/cborg';
import { arrayBufferToBase64, base64ToArrayBuffer, sha256, APPLE_ROOT_CA_G3, sign, verify } from '../utils/crypto';

export interface VerifiedAttestationData {
    publicKey: ArrayBuffer;
    counter: number;
}

/**
 * The OID for the App Attest extension in the attestation certificate.
 * This proves the certificate is intended for App Attest.
 */
const APP_ATTEST_OID = '1.2.840.113635.100.8.2';

// --- Main Service Class ---

/**
 * A service class to handle App Attest verification logic.
 */
export class AttestationService {
    private db: D1Database;
    private teamId: string;
    private bundleId: string;
    private jwtSecret: string;

    constructor(db: D1Database, teamId: string, bundleId: string, jwtSecret: string) {
        this.db = db;
        this.teamId = teamId;
        this.bundleId = bundleId;
        this.jwtSecret = jwtSecret;
    }

    /**
     * Generates a challenge containing a signed timestamp.
     * The format is `timestamp.signature_base64`.
     * @returns {Promise<string>} A challenge string.
     */
    async generateChallenge(): Promise<string> {
        const timestamp = Date.now().toString();
        const signature = await sign(timestamp, this.jwtSecret);
        const signatureB64 = arrayBufferToBase64(signature);
        const challenge = `${timestamp}.${signatureB64}`;
        return arrayBufferToBase64(new TextEncoder().encode(challenge));
    }

    /**
     * Verifies that the challenge is a valid signed timestamp from the server.
     * @param challenge The challenge string from the client.
     * @returns {Promise<boolean>} True if the challenge is valid and recent.
     */
    async verifyChallenge(challengeB64: string): Promise<boolean> {
        let challenge: string;
        try {
            challenge = new TextDecoder().decode(base64ToArrayBuffer(challengeB64));
        } catch (e) {
            console.error("Failed to decode base64 challenge", e);
            return false;
        }

        const parts = challenge.split('.');
        if (parts.length !== 2) {
            console.error("Invalid challenge format");
            return false;
        }
        const [timestampStr, signatureB64] = parts;
        const timestamp = parseInt(timestampStr, 10);

        // Verify timestamp is recent (e.g., within 30 seconds)
        const thirtySeconds = 30 * 1000;
        if (Date.now() - timestamp > thirtySeconds) {
            console.error("Challenge timestamp expired");
            return false;
        }

        const signature = base64ToArrayBuffer(signatureB64);
        const isValid = await verify(signature, timestampStr, this.jwtSecret);
        if (!isValid) {
            console.error("Invalid challenge signature");
        }
        return isValid;
    }


    /**
     * Verifies an attestation object from an iOS client according to Apple's security checks.
     *
     * @param {string} keyId - The key identifier from the client.
     * @param {string} attestationObjectBase64 - The base64 encoded attestation object from the client.
     * @param {string} challenge - The original challenge that was sent to the client.
     * @returns {Promise<{ success: boolean; data?: VerifiedAttestationData }>} - A promise that resolves to true if verification is successful.
     */
    async verifyAttestation(keyId: string, attestationObjectBase64: string, challenge: string): Promise<{ success: boolean; data?: VerifiedAttestationData }> {
        try {
            // 0. Verify the challenge itself first
            const isChallengeValid = await this.verifyChallenge(challenge);
            if (!isChallengeValid) {
                throw new Error("Invalid or expired challenge.");
            }
            const attestationObject = base64ToArrayBuffer(attestationObjectBase64);
            const decodedAttestation = cborgDecode(attestationObject) as Map<string, any>;

            if (decodedAttestation.get('fmt') !== 'apple-appattest') {
                throw new Error("Invalid attestation format");
            }

            // 1. Verify the challenge
            const clientDataHash = await sha256(base64ToArrayBuffer(challenge));

            // 2. Verify the certificate chain first. This is a prerequisite for all other checks.
            const attStmt = decodedAttestation.get('attStmt');
            const certs = attStmt.get('x5c').map((cert: ArrayBuffer) => {
                const asn1 = fromBER(cert);
                return new Certificate({ schema: asn1.result });
            });

            const certChainEngine = new CertificateChainValidationEngine({
                trustedCerts: [this.parseCertificate(APPLE_ROOT_CA_G3)],
                certs: certs
            });

            const certChain = await certChainEngine.verify();
            if (!certChain.result) {
                throw new Error("Certificate chain validation failed.");
            }

            // 3. Verify the leaf certificate's App Attest extension and nonce.
            const leafCert = certs[0];
            const appAttestExtension = leafCert.extensions?.find((ext: any) => ext.extnID === APP_ATTEST_OID);
            if (!appAttestExtension) {
                throw new Error("App Attest OID extension not found in leaf certificate.");
            }

            // Compute expected nonce
            const authDataBytes = new Uint8Array(decodedAttestation.get('authData'));
            const clientDataBytes = new Uint8Array(clientDataHash);
            const nonceBuffer = new Uint8Array(authDataBytes.length + clientDataBytes.length);
            nonceBuffer.set(authDataBytes, 0);
            nonceBuffer.set(clientDataBytes, authDataBytes.length);
            const expectedNonce = await sha256(nonceBuffer.buffer);

            // The App Attest extension's value is an OCTET STRING containing a DER-encoded SEQUENCE.
            // We must parse the buffer and navigate the nested structure to find the nonce.
            if (!appAttestExtension.extnValue.valueBlock.valueHex) {
                throw new Error("Could not find the value of the App Attest extension.");
            }
            const extensionValueBuffer = appAttestExtension.extnValue.valueBlock.valueHex;
            const parsedExtension = fromBER(extensionValueBuffer);
            if (parsedExtension.offset === -1) {
                throw new Error("Failed to parse ASN.1 structure from extension value.");
            }
            const sequence = parsedExtension.result as any;

            if (!sequence.valueBlock || !sequence.valueBlock.value || !sequence.valueBlock.value[0] ||
                !sequence.valueBlock.value[0].valueBlock || !sequence.valueBlock.value[0].valueBlock.value || !sequence.valueBlock.value[0].valueBlock.value[0] ||
                !sequence.valueBlock.value[0].valueBlock.value[0].valueBlock || !sequence.valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex
            ) {
                throw new Error("Invalid ASN.1 structure for App Attest nonce.");
            }

            const nonceInCert = sequence.valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex;

            if (!this.arrayBuffersAreEqual(expectedNonce, nonceInCert)) {
                throw new Error("Nonce does not match expected value in certificate extension.");
            }

            // 4. Parse authenticator data and verify the App ID hash.
            const authData = this.parseAuthData(decodedAttestation.get('authData'));
            if (authData.counter !== 0) {
                throw new Error("Counter must be zero for initial attestation.");
            }
            const appIDHash = await sha256(new TextEncoder().encode(this.teamId + '.' + this.bundleId));

            if (!this.arrayBuffersAreEqual(appIDHash, authData.rpIdHash)) {
                console.error("App ID Hash Mismatch:");
                console.error("Expected (from env):", arrayBufferToBase64(appIDHash));
                console.error("Received (from client):", arrayBufferToBase64(authData.rpIdHash));
                throw new Error("App ID hash does not match.");
            }

            // 5. If all checks pass, return the attested public key and counter.
            const attestedPublicKey = leafCert.subjectPublicKeyInfo.toSchema().toBER(false);

            return {
                success: true,
                data: {
                    publicKey: attestedPublicKey,
                    counter: authData.counter
                }
            };
        } catch (error) {
            console.error("Error verifying attestation:", error);
            return { success: false };
        }
    }

    private parseCertificate(pem: string): Certificate {
        const pemContents = pem
            .replace('-----BEGIN CERTIFICATE-----', '')
            .replace('-----END CERTIFICATE-----', '')
            .replace(/\s/g, '');
        const binaryDer = base64ToArrayBuffer(pemContents);
        return new Certificate({ schema: fromBER(binaryDer).result });
    }

    private arrayBuffersAreEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
        if (a.byteLength !== b.byteLength) return false;
        const viewA = new Uint8Array(a);
        const viewB = new Uint8Array(b);
        for (let i = 0; i < viewA.length; i++) {
            if (viewA[i] !== viewB[i]) return false;
        }
        return true;
    }

    private parseAuthData(authData: ArrayBuffer): { rpIdHash: ArrayBuffer, counter: number } {
        const rpIdHash = authData.slice(0, 32);
        // Flags are at byte 32
        const counter = new DataView(authData.slice(33, 37)).getUint32(0);
        return { rpIdHash, counter };
    }
}
