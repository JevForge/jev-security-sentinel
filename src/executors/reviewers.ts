export interface ReviewerClient {
  requestReviewers(input: { reviewers: string[]; teamReviewers: string[] }): Promise<void>;
}

export function parseReviewerList(raw: string | undefined): { reviewers: string[]; teamReviewers: string[] } {
  const reviewers: string[] = [];
  const teamReviewers: string[] = [];
  if (!raw?.trim()) return { reviewers, teamReviewers };
  for (const part of raw.split(/[\n,]+/).map(item => item.trim()).filter(Boolean)) {
    if (part.startsWith('team:')) teamReviewers.push(part.slice('team:'.length).trim());
    else reviewers.push(part.replace(/^@/, ''));
  }
  return { reviewers, teamReviewers };
}

export async function maybeRequestReviewers(
  enabled: boolean,
  dryRun: boolean,
  rawList: string | undefined,
  client: ReviewerClient | null,
): Promise<'requested' | 'dry-run' | 'skipped'> {
  if (!enabled) return 'skipped';
  const { reviewers, teamReviewers } = parseReviewerList(rawList);
  if (reviewers.length === 0 && teamReviewers.length === 0) return 'skipped';
  if (dryRun || !client) return 'dry-run';
  await client.requestReviewers({ reviewers, teamReviewers });
  return 'requested';
}
