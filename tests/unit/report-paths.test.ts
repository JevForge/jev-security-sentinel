import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expandReportPaths, resolveReportPathInput, splitPathInput } from '../../src/utils/report-paths.js';
import { loadFindings } from '../../src/collectors/load.js';

describe('report path expansion', () => {
  it('splits comma and newline lists', () => {
    expect(splitPathInput('a.sarif, b.sarif\nc.sarif')).toEqual(['a.sarif', 'b.sarif', 'c.sarif']);
    expect(splitPathInput('  ')).toEqual([]);
  });

  it('expands globs and literal multi-paths inside the workspace', () => {
    const root = mkdtempSync(join(tmpdir(), 'sentinel-paths-'));
    mkdirSync(join(root, 'reports'), { recursive: true });
    writeFileSync(join(root, 'reports', 'a.sarif'), JSON.stringify({ runs: [] }));
    writeFileSync(join(root, 'reports', 'b.sarif'), JSON.stringify({ runs: [] }));
    writeFileSync(join(root, 'reports', 'other.json'), '{}');

    const globbed = expandReportPaths(root, ['reports/*.sarif']);
    expect(globbed.errors).toEqual([]);
    expect(globbed.paths.sort()).toEqual(['reports/a.sarif', 'reports/b.sarif']);

    const multi = resolveReportPathInput(root, 'reports/a.sarif, reports/b.sarif');
    expect(multi.paths.sort()).toEqual(['reports/a.sarif', 'reports/b.sarif']);
  });

  it('rejects workspace escapes and loads multiple SARIF files', () => {
    const root = mkdtempSync(join(tmpdir(), 'sentinel-load-'));
    mkdirSync(join(root, 'out'), { recursive: true });
    const sarif = {
      runs: [
        {
          tool: { driver: { name: 't', rules: [{ id: 'R1' }] } },
          results: [
            {
              ruleId: 'R1',
              level: 'error',
              message: { text: 'issue' },
              locations: [
                { physicalLocation: { artifactLocation: { uri: 'src/a.ts' }, region: { startLine: 1 } } },
              ],
            },
          ],
        },
      ],
    };
    writeFileSync(join(root, 'out', 'one.sarif'), JSON.stringify(sarif));
    writeFileSync(join(root, 'out', 'two.sarif'), JSON.stringify(sarif));

    const escaped = expandReportPaths(root, ['../outside.sarif']);
    expect(escaped.errors[0]).toContain('escapes');

    const loaded = loadFindings({
      workspace: root,
      sarifPath: 'out/*.sarif',
      maxFindings: 100,
    });
    expect(loaded.errors).toEqual([]);
    expect(loaded.loadedPaths.sort()).toEqual(['out/one.sarif', 'out/two.sarif']);
    expect(loaded.findings).toHaveLength(2);
  });
});
