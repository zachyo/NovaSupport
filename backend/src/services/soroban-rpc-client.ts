import { Address, scValToNative, xdr } from "@stellar/stellar-sdk";
import { randomUUID } from "node:crypto";
import type {
  EventIndexerRpcClient,
  RpcEventPage,
  SupportEventRecord,
} from "./event-indexer.js";
import { logger } from "../logger.js";

type RpcEvent = {
  ledger: number;
  pagingToken?: string;
  txHash: string;
  ledgerClosedAt: string;
  topic: string[];
  value: string;
  contractId: string;
  id: string;
};

type RpcResponse =
  | {
      result: {
        latestLedger: number;
        events: RpcEvent[];
        cursor?: string;
      };
    }
  | {
      error: { code: number; message: string; data?: unknown };
    };

function asAddress(value: unknown): string {
  if (value instanceof Address) {
    return value.toString();
  }

  if (typeof value === "string") {
    return value;
  }

  return String(value ?? "");
}

function toNumber(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function decodeSupportEvent(event: RpcEvent): SupportEventRecord | null {
  if (!event.topic.length) return null;

  let native: unknown;
  try {
    native = scValToNative(xdr.ScVal.fromXDR(event.value, "base64"));
  } catch (err) {
    logger.warn({
      msg: "Malformed support event payload discarded (XDR decode error)",
      ledger: event.ledger,
      contractId: event.contractId,
      txHash: event.txHash,
      err
    });
    return null;
  }

  if (!native || Array.isArray(native) || typeof native !== "object") {
    logger.warn({
      msg: "Malformed support event payload discarded (not an object)",
      ledger: event.ledger,
      contractId: event.contractId,
      txHash: event.txHash,
      native
    });
    return null;
  }

  const nativeObj = native as Record<string, unknown>;
  const supporter = nativeObj.supporter;
  const recipient = nativeObj.recipient;

  if (!supporter || !recipient) {
    logger.warn({
      msg: "Malformed support event payload discarded (missing supporter or recipient)",
      ledger: event.ledger,
      contractId: event.contractId,
      txHash: event.txHash,
      native: nativeObj
    });
    return null;
  }

  return {
    txHash: event.txHash,
    ledger: event.ledger,
    pagingToken: event.pagingToken ?? event.id,
    amount: String(nativeObj.amount ?? "0"),
    assetCode: String(nativeObj.asset_code ?? nativeObj.assetCode ?? ""),
    assetIssuer:
      nativeObj.asset_issuer != null
        ? String(nativeObj.asset_issuer)
        : nativeObj.assetIssuer != null
          ? String(nativeObj.assetIssuer)
          : null,
    recipientAddress: asAddress(recipient),
    supporterAddress: asAddress(supporter),
    message: nativeObj.message == null ? null : String(nativeObj.message),
    emittedAt: new Date(toNumber(nativeObj.timestamp) * 1000),
  };
}

export function createSorobanRpcClient(
  rpcUrl: string,
  pageSize = 100,
): EventIndexerRpcClient {
  return {
    async fetchEvents({ contractId, cursor, startLedger }): Promise<RpcEventPage> {
      // When no cursor exists yet, determine the start ledger:
      //   - If the caller explicitly provides startLedger (backfill), use it.
      //   - Otherwise fall back to the current latest ledger so the indexer
      //     picks up only recent events (safe default).
      const effectiveStartLedger =
        cursor || startLedger === undefined
          ? undefined
          : startLedger;

      const params: Record<string, unknown> = {
        filters: [
          {
            type: "contract",
            contractIds: [contractId],
          },
        ],
        pagination: {
          limit: pageSize,
          ...(cursor ? { cursor } : {}),
        },
      };

      if (effectiveStartLedger !== undefined) {
        params.startLedger = effectiveStartLedger;
      } else if (!cursor) {
        params.startLedger = await getLatestLedger(rpcUrl);
      }

      const requestBody: Record<string, unknown> = {
        jsonrpc: "2.0",
        id: randomUUID(),
        method: "getEvents",
        params,
      };

      const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        throw new Error(`Soroban RPC request failed: ${response.status}`);
      }

      const json = (await response.json()) as RpcResponse;
      if ("error" in json) {
        throw new Error(`Soroban RPC error: ${json.error.message}`);
      }

      const events = json.result.events
        .map((event) => decodeSupportEvent(event))
        .filter((event): event is SupportEventRecord => event !== null);

      return {
        events,
        nextPagingToken: json.result.cursor ?? null,
      };
    },
  };
}

async function getLatestLedger(rpcUrl: string): Promise<number> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: randomUUID(),
      method: "getLatestLedger",
    }),
  });

  if (!response.ok) {
    throw new Error(`Soroban RPC ledger lookup failed: ${response.status}`);
  }

  const json = (await response.json()) as {
    result?: { sequence?: number; latestLedger?: number };
    error?: { message?: string };
  };

  if (json.error) {
    throw new Error(`Soroban RPC error: ${json.error.message ?? "unknown error"}`);
  }

  return json.result?.sequence ?? json.result?.latestLedger ?? 0;
}
