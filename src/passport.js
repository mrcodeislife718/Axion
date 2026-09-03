export function buildPassport({ registry, credentials }, identityId) {
  const inspected = registry.inspect(identityId);
  if (!inspected) return null;
  const credentialRecords = credentials.listForSubject(identityId, { includeRevoked: true });
  const verified = credentialRecords.map((credential) => ({
    credentialId: credential.credentialId,
    status: credential.status,
    issuerId: credential.issuerId,
    claims: structuredClone(credential.claims),
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    verification: credentials.verify(credential.credentialId),
  }));
  const activeCredentials = verified.filter((item) => item.verification.verified).length;
  return {
    identity: inspected.system,
    release: inspected.release,
    trust: {
      activeCredentials,
      totalCredentials: verified.length,
      releaseVerified: registry.verify(identityId, inspected.system.currentVersion).verified,
    },
    credentials: verified,
  };
}
