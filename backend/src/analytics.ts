import { Prisma } from "@prisma/client";
import { prisma } from "./db.js";

const analyticsCache = new Map<
  string,
  { data: any; timestamp: number }
>();
const CACHE_TTL = 3600000; // 1 hour

interface DailyContribution {
  date: string;
  amount: string;
  count: number;
  uniqueContributors: number;
  avgContribution: string;
}

function isCacheValid(timestamp: number): boolean {
  return Date.now() - timestamp < CACHE_TTL;
}

export function fillGaps(
  results: any[],
  period: string,
  fromDate: Date,
  toDate: Date
) {
  const map = new Map<string, any>();
  for (const row of results) {
    const d = new Date(row.date);
    let key = "";
    if (period === "monthly") {
      key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-01`;
    } else if (period === "weekly") {
      const day = d.getDay();
      const diff = d.getDate() - day + (day === 0 ? -6 : 1);
      const monday = new Date(d.setDate(diff));
      key = monday.toISOString().split("T")[0];
    } else {
      key = d.toISOString().split("T")[0];
    }
    map.set(key, {
      amount: row.total?.toString() ?? "0",
      count: Number(row.txCount ?? 0),
      uniqueContributors: Number(row.uniqueContributors ?? 0),
      avgContribution: row.avgContribution?.toString() ?? "0",
    });
  }

  const data = [];
  const current = new Date(fromDate);
  if (period === "monthly") current.setDate(1);
  if (period === "weekly") {
    const day = current.getDay();
    const diff = current.getDate() - day + (day === 0 ? -6 : 1);
    current.setDate(diff);
  }

  const end = new Date(toDate);
  // Normalize dates to midnight for comparison
  current.setHours(0, 0, 0, 0);
  end.setHours(0, 0, 0, 0);

  while (current <= end) {
    const keyStr = current.toISOString().split("T")[0];
    const existing = map.get(keyStr);
    data.push({
      date: keyStr,
      amount: existing?.amount ?? "0",
      count: existing?.count ?? 0,
      uniqueContributors: existing?.uniqueContributors ?? 0,
      avgContribution: existing?.avgContribution ?? "0",
    });

    if (period === "monthly") {
      current.setMonth(current.getMonth() + 1);
    } else if (period === "weekly") {
      current.setDate(current.getDate() + 7);
    } else {
      current.setDate(current.getDate() + 1);
    }
  }

  return { period, data };
}

export async function getAnalytics(
  profileId: string,
  startDate?: Date,
  endDate?: Date,
  format?: "json" | "csv"
) {
  const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end = endDate || new Date();

  const cacheKey = `${profileId}:${start.toISOString()}:${end.toISOString()}:${format}`;
  const cached = analyticsCache.get(cacheKey);

  if (cached && isCacheValid(cached.timestamp)) {
    return format === "csv" ? convertToCSV(cached.data) : cached.data;
  }

  // Aggregate in the database rather than loading every row into memory.
  // SUM is computed by Postgres on the Decimal column, preserving precision
  // (no Number() conversion), and only one row per day is returned.
  const [dailyRows, summaryAgg, contributorRows, assetGroups] =
    await Promise.all([
      prisma.$queryRaw<
        {
          date: string;
          total: string | null;
          txCount: number;
          uniqueContributors: number;
        }[]
      >`
        SELECT
          to_char("createdAt", 'YYYY-MM-DD') AS date,
          SUM("amount")::text AS total,
          COUNT(*)::int AS "txCount",
          COUNT(DISTINCT "supporterAddress")::int AS "uniqueContributors"
        FROM "SupportTransaction"
        WHERE "profileId" = ${profileId}
          AND "createdAt" >= ${start}
          AND "createdAt" <= ${end}
        GROUP BY 1
        ORDER BY 1 ASC
      `,
      prisma.supportTransaction.aggregate({
        where: { profileId, createdAt: { gte: start, lte: end } },
        _sum: { amount: true },
        _count: true,
      }),
      prisma.$queryRaw<{ count: number }[]>`
        SELECT COUNT(DISTINCT "supporterAddress")::int AS count
        FROM "SupportTransaction"
        WHERE "profileId" = ${profileId}
          AND "createdAt" >= ${start}
          AND "createdAt" <= ${end}
      `,
      prisma.supportTransaction.groupBy({
        by: ["assetCode"],
        where: { profileId, createdAt: { gte: start, lte: end } },
        _sum: { amount: true },
        _count: true,
      }),
    ]);

  // Per-day metrics, keeping amounts as decimal strings.
  const dailyData: DailyContribution[] = dailyRows.map((row) => {
    // Normalize Postgres numeric text (e.g. "150.0000000") to "150".
    const amount =
      row.total != null ? new Prisma.Decimal(row.total).toString() : "0";
    const avgContribution =
      row.txCount > 0
        ? new Prisma.Decimal(amount).div(row.txCount).toString()
        : "0";
    return {
      date: row.date,
      amount,
      count: row.txCount,
      uniqueContributors: row.uniqueContributors,
      avgContribution,
    };
  });

  // Fill gaps
  const filledData: DailyContribution[] = [];
  let currentDate = new Date(start);

  const dataMap = new Map(dailyData.map((d) => [d.date, d]));

  while (currentDate <= end) {
    const dateStr = currentDate.toISOString().split("T")[0];
    const existing = dataMap.get(dateStr);

    filledData.push(
      existing || {
        date: dateStr,
        amount: "0",
        count: 0,
        uniqueContributors: 0,
        avgContribution: "0",
      }
    );

    currentDate.setDate(currentDate.getDate() + 1);
  }

  // Calculate summary using Decimal arithmetic to avoid precision loss.
  const totalAmount = (
    summaryAgg._sum.amount ?? new Prisma.Decimal(0)
  ).toString();
  const totalContributors = contributorRows[0]?.count ?? 0;
  const avgDailyContribution =
    filledData.length > 0
      ? new Prisma.Decimal(totalAmount).div(filledData.length).toString()
      : "0";

  const result = {
    profileId,
    summary: {
      totalRaised: totalAmount,
      totalContributors,
      avgDailyContribution,
      transactionCount: summaryAgg._count,
      dateRange: { start: start.toISOString(), end: end.toISOString() },
    },
    dailyContributions: filledData,
    assetBreakdown: assetGroups.map((group) => ({
      asset: group.assetCode,
      amount: (group._sum.amount ?? new Prisma.Decimal(0)).toString(),
      count: group._count,
    })),
  };

  analyticsCache.set(cacheKey, { data: result, timestamp: Date.now() });

  if (format === "csv") {
    return convertToCSV(result);
  }

  return result;
}

function convertToCSV(analytics: any): string {
  const headers = [
    "Date",
    "Amount",
    "Transaction Count",
    "Unique Contributors",
    "Avg Contribution",
  ];
  const rows = analytics.dailyContributions.map(
    (d: DailyContribution) => [
      d.date,
      d.amount,
      d.count,
      d.uniqueContributors,
      d.avgContribution,
    ]
  );

  const csv =
    [headers, ...rows]
      .map((row) => row.map((cell: unknown) => `"${cell}"`).join(","))
      .join("\n") + "\n";

  return csv;
}

export function clearAnalyticsCache(profileId?: string): void {
  if (profileId) {
    Array.from(analyticsCache.keys())
      .filter((key) => key.startsWith(profileId))
      .forEach((key) => analyticsCache.delete(key));
  } else {
    analyticsCache.clear();
  }
}
