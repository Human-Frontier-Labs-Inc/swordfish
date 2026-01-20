/**
 * Email Authentication Types
 * Common types for SPF, DKIM, and DMARC validation
 */

// SPF Types
export type SPFResult =
  | 'pass'
  | 'fail'
  | 'softfail'
  | 'neutral'
  | 'none'
  | 'temperror'
  | 'permerror';

export interface SPFMechanism {
  type: 'all' | 'ip4' | 'ip6' | 'a' | 'mx' | 'ptr' | 'exists' | 'include' | 'redirect';
  qualifier: '+' | '-' | '~' | '?';
  value?: string;
  cidr?: number;
}

export interface SPFRecord {
  version: string;
  mechanisms: SPFMechanism[];
  redirect?: string;
  exp?: string;
  raw: string;
}

export interface SPFValidationResult {
  result: SPFResult;
  domain: string;
  senderIP: string;
  mechanism?: SPFMechanism;
  explanation?: string;
  lookupCount: number;
}

// DKIM Types
export type DKIMResult =
  | 'pass'
  | 'fail'
  | 'neutral'
  | 'temperror'
  | 'permerror';

export type DKIMCanonicalization = 'simple' | 'relaxed';

export interface DKIMSignature {
  version: string;              // v=
  algorithm: string;            // a= (e.g., rsa-sha256)
  signature: string;            // b=
  bodyHash: string;             // bh=
  canonicalization: {           // c=
    header: DKIMCanonicalization;
    body: DKIMCanonicalization;
  };
  domain: string;               // d=
  signedHeaders: string[];      // h=
  selector: string;             // s=
  timestamp?: number;           // t=
  expiration?: number;          // x=
  identity?: string;            // i=
  bodyLength?: number;          // l=
  queryMethod?: string;         // q=
}

export interface DKIMPublicKey {
  version?: string;             // v=
  keyType?: string;             // k= (default: rsa)
  publicKey: string;            // p=
  hashAlgorithms?: string[];    // h=
  serviceTypes?: string[];      // s=
  flags?: string[];             // t=
  notes?: string;               // n=
}

export interface DKIMValidationResult {
  result: DKIMResult;
  domain: string;
  selector: string;
  signature?: DKIMSignature;
  error?: string;
  alignment?: 'strict' | 'relaxed' | 'none';
}

// DMARC Types
export type DMARCResult =
  | 'pass'
  | 'fail'
  | 'none';

export type DMARCPolicy = 'none' | 'quarantine' | 'reject';

export type DMARCAlignment = 'strict' | 'relaxed';

export interface DMARCRecord {
  version: string;              // v=
  policy: DMARCPolicy;          // p=
  subdomainPolicy?: DMARCPolicy; // sp=
  percentage?: number;          // pct=
  ruaAddresses?: string[];      // rua= (aggregate reports)
  rufAddresses?: string[];      // ruf= (forensic reports)
  adkim?: DMARCAlignment;       // adkim= (DKIM alignment)
  aspf?: DMARCAlignment;        // aspf= (SPF alignment)
  reportFormat?: string;        // rf=
  reportInterval?: number;      // ri=
  failureOptions?: string;      // fo=
  raw: string;
}

export interface DMARCEvaluationResult {
  result: DMARCResult;
  domain: string;
  policy: DMARCPolicy;
  appliedPolicy: DMARCPolicy;
  spfAlignment: boolean;
  dkimAlignment: boolean;
  spfResult?: SPFResult;
  dkimResults?: DKIMValidationResult[];
  percentage?: number;
  record?: DMARCRecord;
}

// DNS Types
export interface DNSCache {
  get(key: string): Promise<string[] | null>;
  set(key: string, value: string[], ttl: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
}

export interface DNSResolver {
  resolveTxt(domain: string): Promise<string[]>;
  resolveA(domain: string): Promise<string[]>;
  resolveAAAA(domain: string): Promise<string[]>;
  resolveMx(domain: string): Promise<Array<{ priority: number; exchange: string }>>;
}

// Email context for validation
export interface EmailAuthContext {
  senderIP: string;
  mailFrom: string;           // SMTP MAIL FROM (envelope sender)
  headerFrom: string;         // RFC5322.From header
  dkimSignatures?: string[];  // Raw DKIM-Signature headers
  rawHeaders?: string;        // For DKIM verification
  rawBody?: string;           // For DKIM body hash
}
