import { describe, expect, it } from 'vitest';
import { maybeRequestReviewers, parseReviewerList } from '../../src/executors/reviewers.js';

describe('reviewer request', () => {
  it('parses users and team:slug entries', () => {
    expect(parseReviewerList('@alice, team:security\nbob')).toEqual({
      reviewers: ['alice', 'bob'],
      teamReviewers: ['security'],
    });
  });

  it('requests reviewers when enabled', async () => {
    const calls: unknown[] = [];
    const status = await maybeRequestReviewers(true, false, 'alice, team:sec', {
      async requestReviewers(input) {
        calls.push(input);
      },
    });
    expect(status).toBe('requested');
    expect(calls[0]).toEqual({ reviewers: ['alice'], teamReviewers: ['sec'] });
  });
});
