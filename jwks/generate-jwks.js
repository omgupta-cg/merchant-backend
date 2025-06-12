import { importX509, exportJWK, calculateJwkThumbprint } from 'jose';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';

const main = async () => {
  const pemCertificate = await fs.readFile('./certificate.pem', 'utf-8');
  const base64Cert = pemCertificate.trim().split('\n').slice(1, -1).join('');
  const certificate = await importX509(pemCertificate, 'RS256', { extractable: true });
  const jwk = await exportJWK(certificate);
  jwk.x5t = createHash('sha1').update(base64Cert).digest('base64');
  jwk.kid = await calculateJwkThumbprint(jwk);
  jwk.x5c = [base64Cert];

  await fs.writeFile('./jwks.json', JSON.stringify({ keys: [jwk] }, null, 2));
}
main();
