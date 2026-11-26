const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');

class AuditService {
  /**
   * Compute SHA-256 digest of record components
   */
  computeHash(seq, timestamp, agentId, action, resource, decision, riskScore, reason, prevHash) {
    const raw = [
      seq,
      new Date(timestamp).toISOString(),
      agentId,
      action,
      resource,
      decision,
      riskScore,
      reason,
      prevHash
    ].join('|');

    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  /**
   * Append a new tamper-evident audit record to the hash chain
   */
  async recordEvent(entry) {
    const lastRecord = await AuditLog.findOne().sort({ seq: -1 }).lean();
    const seq = lastRecord ? lastRecord.seq + 1 : 1;
    const prevHash = lastRecord ? lastRecord.hash : 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';
    const timestamp = entry.timestamp || new Date();

    const hash = this.computeHash(
      seq,
      timestamp,
      entry.agentId,
      entry.action,
      entry.resource,
      entry.decision,
      entry.riskScore,
      entry.reason,
      prevHash
    );

    const log = new AuditLog({
      seq,
      timestamp,
      agentId: entry.agentId,
      agentName: entry.agentName,
      action: entry.action,
      resource: entry.resource,
      decision: entry.decision,
      riskScore: entry.riskScore,
      reason: entry.reason,
      prevHash,
      hash,
      metadata: entry.metadata || {}
    });

    await log.save();
    return log;
  }

  /**
   * Verify the entire cryptographic hash chain
   */
  async verifyChain() {
    const records = await AuditLog.find().sort({ seq: 1 }).lean();
    if (records.length === 0) {
      return { ok: true, count: 0, message: 'Chain is empty (GENESIS).' };
    }

    let prevHash = 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < records.length; i++) {
      const r = records[i];

      if (r.prevHash !== prevHash) {
        return {
          ok: false,
          index: i,
          seq: r.seq,
          reason: `Previous-hash linkage broken at record #${r.seq}. Expected: ${prevHash}, Found: ${r.prevHash}`
        };
      }

      const calculatedHash = this.computeHash(
        r.seq,
        r.timestamp,
        r.agentId,
        r.action,
        r.resource,
        r.decision,
        r.riskScore,
        r.reason,
        r.prevHash
      );

      if (calculatedHash !== r.hash) {
        return {
          ok: false,
          index: i,
          seq: r.seq,
          reason: `Cryptographic digest mismatch at record #${r.seq}. Payload altered. Calculated: ${calculatedHash}, Recorded: ${r.hash}`
        };
      }

      prevHash = r.hash;
    }

    return {
      ok: true,
      count: records.length,
      headHash: records[records.length - 1].hash,
      message: `Verified all ${records.length} records in SHA-256 chain. Zero tampering detected.`
    };
  }
}

module.exports = new AuditService();
