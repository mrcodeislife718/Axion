import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalize } from './axion.js';

const hash = value => crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');

export class AxionTransparencyLedger {
  constructor({ root }) {
    if (!root) throw new Error('ledger root required');
    this.root = path.resolve(root);
    this.logPath = path.join(this.root,'ledger.ndjson');
    fs.mkdirSync(this.root,{recursive:true,mode:0o700});
    if (!fs.existsSync(this.logPath)) fs.writeFileSync(this.logPath,'',{mode:0o600});
  }
  entries() {
    const text = fs.readFileSync(this.logPath,'utf8').trim();
    return text ? text.split('\n').map(line=>JSON.parse(line)) : [];
  }
  head() { const entries=this.entries(); return entries.at(-1) || null; }
  append(type, subjectId, payload = {}) {
    const previous=this.head();
    const body={ index:previous ? previous.index+1 : 0, type, subjectId, payload:canonicalize(payload), previousHash:previous?.entryHash || null, at:new Date().toISOString() };
    const entry={...body,entryHash:hash(body)};
    fs.appendFileSync(this.logPath,`${JSON.stringify(entry)}\n`,{encoding:'utf8',mode:0o600});
    return entry;
  }
  verify() {
    const entries=this.entries(); let previousHash=null;
    for (let i=0;i<entries.length;i++) {
      const entry=entries[i];
      if (entry.index!==i) return {verified:false,reason:'index-gap',index:i};
      if (entry.previousHash!==previousHash) return {verified:false,reason:'previous-hash-mismatch',index:i};
      const {entryHash,...body}=entry;
      const calculated=hash(body);
      if (calculated!==entryHash) return {verified:false,reason:'entry-hash-mismatch',index:i};
      previousHash=entryHash;
    }
    return {verified:true,entries:entries.length,headHash:previousHash};
  }
  checkpoint(keyRing) {
    const verification=this.verify();
    if (!verification.verified) throw new Error(`ledger integrity failure: ${verification.reason}`);
    const statement={ledger:'axion-transparency-v1',entries:verification.entries,headHash:verification.headHash,createdAt:new Date().toISOString()};
    return {statement,signature:keyRing.sign(statement)};
  }
}
