import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /rest/country-mapping', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'bopla',
        'improper_asset_management',
        'xss',
        'sqli',
        'nosql',
        'ldapi',
        'xxe',
        'osi',
        'rfi',
        'lfi',
        'ssrf',
        'ssti',
        'stored_xss',
        'unvalidated_redirect',
        'version_control_systems',
        'secret_tokens'
      ],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/rest/country-mapping`,
      headers: { 'X-Recruiting': 'undefined' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
