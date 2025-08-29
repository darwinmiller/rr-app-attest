# rr-app-attest

This is how we handle device auth in the RoastReel iOS app.

This app has optional sign in and uses device IDs in place of user IDs in most situations.
We need to ensure devices are trusted and unique to safely allow them to use a limited free trial of our service.

We first generate an Apple app attestation. 
This attestation is proof of the following claims:
- The app code running is signed and verified to be the code published by the developer.
- This copy of the app is running on a genuine Apple device.
- The app running on the device was installed on the current device, and not transferred from another.
- The keys to the attestation were generated and stored in the Secure Enclave on a genuine apple CPU.

This initial attestation takes in an anti-reply challenge from the server, in this case a signed timestamp. 

The device then sends an attestation which the server verifies cryptographically and with Apple.

This attestation is then used to generate subsequent assertions. These assertions are easier to generate and verify, and are cryptographically tied to the initial attestation. 

We use the assertions as a refresh mechanism to mint new short lived stateless JWT’s that we use as device access tokens. 

[AppAttestService.swift](AppAttestService.swift) is the device side of the service.
[auth.ts](auth.ts) and [attestationService.ts](attestationService.ts) are the server side components.

Database and surrounding code are excluded from this example.
