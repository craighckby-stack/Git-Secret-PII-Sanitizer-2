import { Finding, SecretPattern, Severity, Confidence, ScanStats, SkipBreakdown, FileScanAuditItem } from '../types';

/**
 * Validates a credit card number using the Luhn Algorithm.
 * Returns true if valid Luhn checksum, eliminating false positive digit streams.
 */
export function validateLuhn(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Calculates Shannon Entropy of a string (bits per character).
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const SENSITIVE_PATTERNS: SecretPattern[] = [
  // AI & LLM Keys
  {
    id: 'openai-key',
    name: 'OpenAI API Key / Project Token',
    category: 'AI & LLM Keys',
    regex: /\b(sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_-]{20,}|sk-admin-[a-zA-Z0-9_-]{20,})\b/g,
    placeholder: '<OPENAI_API_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed OpenAI secret key or project token',
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic Claude API Key',
    category: 'AI & LLM Keys',
    regex: /\b(sk-ant-api03-[a-zA-Z0-9_-]{80,})\b/g,
    placeholder: '<ANTHROPIC_API_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Anthropic Claude API key',
  },
  {
    id: 'google-gemini-key',
    name: 'Google Gemini / Cloud API Key',
    category: 'AI & LLM Keys',
    regex: /\b(AIzaSy[a-zA-Z0-9_-]{33})\b/g,
    placeholder: '<GEMINI_API_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Google Gemini or Firebase AI key',
  },
  {
    id: 'cohere-key',
    name: 'Cohere API Key',
    category: 'AI & LLM Keys',
    regex: /\b(co-[a-zA-Z0-9]{38,40})\b/g,
    placeholder: '<COHERE_API_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Cohere API token',
  },
  {
    id: 'mistral-key',
    name: 'Mistral AI API Key',
    category: 'AI & LLM Keys',
    regex: /\b(mis_[a-zA-Z0-9]{32})\b/g,
    placeholder: '<MISTRAL_API_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Mistral AI token',
  },

  // GitHub & GitLab Tokens
  {
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    category: 'Authentication & Tokens',
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g,
    placeholder: '<GITHUB_PAT_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed GitHub personal access token',
  },
  {
    id: 'github-oauth-user-server',
    name: 'GitHub OAuth / App Token',
    category: 'Authentication & Tokens',
    regex: /\b(gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b/g,
    placeholder: '<GITHUB_OAUTH_TOKEN_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed GitHub OAuth or refresh token',
  },
  {
    id: 'gitlab-token',
    name: 'GitLab Personal Access Token',
    category: 'Authentication & Tokens',
    regex: /\b(glpat-[a-zA-Z0-9_-]{20,})\b/g,
    placeholder: '<GITLAB_TOKEN_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed GitLab access token',
  },

  // Cloud Providers (AWS, GCP, Azure)
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    category: 'Cloud Keys',
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/g,
    placeholder: '<AWS_ACCESS_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Amazon Web Services access key ID',
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    category: 'Cloud Keys',
    regex: /(?<=aws_secret_access_key\s*=\s*['"]?)[a-zA-Z0-9\/+]{40}(?=['"]?)/gi,
    placeholder: '<AWS_SECRET_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed AWS secret access key',
  },
  {
    id: 'azure-storage-key',
    name: 'Azure Storage Account Key / Connection String',
    category: 'Cloud Keys',
    regex: /\b(DefaultEndpointsProtocol=https?;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9\/+=]{86,};?)\b/g,
    placeholder: '<AZURE_CONNECTION_STRING_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Azure Storage connection string',
  },
  {
    id: 'gcp-service-account',
    name: 'GCP Service Account Private Key',
    category: 'Cloud Keys',
    regex: /"type"\s*:\s*"service_account"\s*,\s*"project_id"\s*:\s*"[a-z0-9-]{4,30}"/g,
    placeholder: '"type": "service_account", "project_id": "<GCP_PROJECT_REDACTED>"',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed GCP service account JSON credential block',
  },

  // Payment & Finance
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret / Restricted Key',
    category: 'Payment & Finance',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,32}|rk_live_[0-9a-zA-Z]{24,32})\b/g,
    placeholder: '<STRIPE_SECRET_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Stripe live production key',
  },
  {
    id: 'stripe-publishable-key',
    name: 'Stripe Publishable Key',
    category: 'Payment & Finance',
    regex: /\b(pk_live_[0-9a-zA-Z]{24,32})\b/g,
    placeholder: '<STRIPE_PUB_KEY_REDACTED>',
    defaultConfidence: 'Medium',
    severity: 'Low',
    description: 'Exposed Stripe publishable key',
  },
  {
    id: 'paypal-client-id',
    name: 'PayPal Secret / Client Key',
    category: 'Payment & Finance',
    regex: /\b(E[A-Za-z0-9_-]{79})\b/g,
    placeholder: '<PAYPAL_SECRET_REDACTED>',
    defaultConfidence: 'Medium',
    severity: 'High',
    description: 'Exposed PayPal live client secret',
  },

  // Communication & Social
  {
    id: 'twilio-account-sid',
    name: 'Twilio Account SID & Auth Token',
    category: 'Communication & Social',
    regex: /\b(AC[a-f0-9]{32})\b/g,
    placeholder: '<TWILIO_SID_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Twilio Account SID',
  },
  {
    id: 'slack-bot-token',
    name: 'Slack Bot / User Token',
    category: 'Communication & Social',
    regex: /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}|xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}|xapp-[0-9]-[a-zA-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64})\b/g,
    placeholder: '<SLACK_TOKEN_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Slack API token',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook URL',
    category: 'Communication & Social',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g,
    placeholder: 'https://hooks.slack.com/services/<SLACK_WEBHOOK_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Slack incoming webhook URL',
  },
  {
    id: 'discord-bot-token',
    name: 'Discord Bot Token',
    category: 'Communication & Social',
    regex: /\b([MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38})\b/g,
    placeholder: '<DISCORD_TOKEN_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Discord bot token',
  },
  {
    id: 'notion-integration-secret',
    name: 'Notion Integration Secret',
    category: 'Communication & Social',
    regex: /\b(secret_[a-zA-Z0-9]{43})\b/g,
    placeholder: '<NOTION_SECRET_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Notion API integration secret',
  },
  {
    id: 'shopify-token',
    name: 'Shopify Admin / Access Token',
    category: 'Payment & Finance',
    regex: /\b(shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32})\b/g,
    placeholder: '<SHOPIFY_TOKEN_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed Shopify access token',
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    category: 'Communication & Social',
    regex: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/g,
    placeholder: '<SENDGRID_API_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed SendGrid mail key',
  },
  {
    id: 'mailgun-key',
    name: 'Mailgun API Key',
    category: 'Communication & Social',
    regex: /\b(key-[0-9a-zA-Z]{32})\b/g,
    placeholder: '<MAILGUN_KEY_REDACTED>',
    defaultConfidence: 'High',
    severity: 'High',
    description: 'Exposed Mailgun private key',
  },

  // Databases & URIs
  {
    id: 'mongodb-atlas-uri',
    name: 'MongoDB Connection String with Credentials',
    category: 'Database & Storage',
    regex: /mongodb(\+srv)?:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+/g,
    placeholder: 'mongodb+srv://<USER>:<PASSWORD_REDACTED>@<HOST>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed MongoDB connection URI with user/pass',
  },
  {
    id: 'postgres-mysql-redis-uri',
    name: 'PostgreSQL / MySQL / Redis Connection URI',
    category: 'Database & Storage',
    regex: /(postgres|postgresql|mysql|redis):\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:\d+/g,
    placeholder: '$1://<USER>:<PASSWORD_REDACTED>@<HOST>:<PORT>',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed relational database or cache connection URI',
  },

  // Keys & JWTs
  {
    id: 'private-pem-rsa-key',
    name: 'PEM / RSA / EC / SSH Private Key Block',
    category: 'Private Keys',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{30,2000}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    placeholder: '[REDACTED_PRIVATE_KEY_BLOCK]',
    defaultConfidence: 'High',
    severity: 'Critical',
    description: 'Exposed cryptographic private key block',
  },
  {
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    category: 'Authentication & Tokens',
    regex: /\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
    placeholder: '<JWT_TOKEN_REDACTED>',
    defaultConfidence: 'Medium',
    severity: 'Medium',
    description: 'Exposed JSON Web Token (JWT) bearer string',
  },

  // PII & Identifiers
  {
    id: 'pii-email',
    name: 'Email Address',
    category: 'PII & Financial Data',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    placeholder: '<EMAIL_ADDRESS_REDACTED>',
    defaultConfidence: 'Low',
    severity: 'Low',
    description: 'Personal or employee email address',
  },
  {
    id: 'pii-phone',
    name: 'Phone Number',
    category: 'PII & Financial Data',
    regex: /\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    placeholder: '<PHONE_NUMBER_REDACTED>',
    defaultConfidence: 'Low',
    severity: 'Low',
    description: 'Phone number in standard international/national format',
  },
  {
    id: 'pii-ipv4-v6',
    name: 'IP Address (IPv4 / IPv6)',
    category: 'PII & Financial Data',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    placeholder: '<IP_ADDRESS_REDACTED>',
    defaultConfidence: 'Low',
    severity: 'Low',
    description: 'IPv4 public or internal IP address',
  },
  {
    id: 'pii-mac-address',
    name: 'MAC Address',
    category: 'PII & Financial Data',
    regex: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g,
    placeholder: '<MAC_ADDRESS_REDACTED>',
    defaultConfidence: 'Low',
    severity: 'Low',
    description: 'Hardware MAC address',
  },
  {
    id: 'pii-iban-swift',
    name: 'IBAN / SWIFT Bank Identifier',
    category: 'PII & Financial Data',
    regex: /\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/g,
    placeholder: '<IBAN_SWIFT_REDACTED>',
    defaultConfidence: 'High',
    severity: 'Medium',
    description: 'International Bank Account Number / SWIFT code',
  }
];

/**
 * Checks if an IP address is a benign, non-routable, loopback, broadcast, or documentation address.
 * RFC 5735 / RFC 5737 / RFC 1122
 */
export function isBenignIpAddress(ip: string): boolean {
  if (!ip) return false;
  // Wildcards, loopbacks, broadcast
  if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '255.255.255.255') return true;
  // 0.0.0.0/8 (current network) and 127.0.0.0/8 (loopback block)
  if (ip.startsWith('0.') || ip.startsWith('127.')) return true;
  // RFC 5737 Documentation ranges: TEST-NET-1 (192.0.2.x), TEST-NET-2 (198.51.100.x), TEST-NET-3 (203.0.113.x)
  if (ip.startsWith('192.0.2.') || ip.startsWith('198.51.100.') || ip.startsWith('203.0.113.')) return true;
  // Common subnet broadcast or network identifiers
  if (ip.endsWith('.255') || ip.endsWith('.0')) return true;
  return false;
}

/**
 * Checks if matched text is already redacted or part of a scanner rule/type definition.
 */
export function isAlreadyRedactedOrPlaceholder(matchedText: string, contextLine: string = ''): boolean {
  if (!matchedText) return false;
  // Already contains a redaction placeholder marker
  if (/<[A-Z0-9_-]+_REDACTED>/i.test(matchedText) || /\[REDACTED[A-Z0-9_ -]*\]/i.test(matchedText)) {
    return true;
  }
  // Line is defining a regex, placeholder, patternId or test fixture in code
  if (contextLine) {
    if (/\b(?:placeholder|regex|patternId|defaultConfidence)\s*:\s*['"`/]/.test(contextLine)) {
      return true;
    }
  }
  return false;
}

/**
 * Detects standard public documentation dummy keys, sample credentials, or movie fixtures.
 */
export function isDocumentationOrDummySecret(
  matchedText: string,
  patternId: string,
  contextLine: string = ''
): boolean {
  if (!matchedText) return false;
  const upper = matchedText.toUpperCase();
  const lineUpper = contextLine.toUpperCase();

  // Explicit documentation dummies across all providers
  if (
    upper.includes('EXAMPLEKEY') ||
    upper.includes('AKIAIOSFODNN7EXAMPLE') ||
    upper.includes('YOUR_API_KEY') ||
    upper.includes('YOUR_KEY') ||
    upper.includes('INSERT_API_KEY') ||
    upper.includes('INSERT_KEY') ||
    upper.includes('MY_SECRET_KEY') ||
    upper.includes('DUMMY_KEY') ||
    upper.includes('REPLACE_ME') ||
    upper.includes('CHANGEME') ||
    upper.includes('SAMPLE_TOKEN') ||
    upper.includes('FAKE_SECRET') ||
    upper.includes('000000000000') ||
    upper.includes('XXXXXXXXXXXX')
  ) {
    return true;
  }

  // AWS Secret Access Key: official AWS docs example key
  if (patternId === 'aws-secret-access-key' && upper.includes('EXAMPLEKEY')) {
    return true;
  }

  // Database URIs: dummy demo passwords or sample hosts
  if (patternId === 'mongodb-atlas-uri' || patternId === 'postgres-mysql-redis-uri') {
    if (
      /:password@/i.test(matchedText) ||
      /:admin@/i.test(matchedText) ||
      /:root@/i.test(matchedText) ||
      /:changeme@/i.test(matchedText) ||
      /:test@/i.test(matchedText) ||
      /:P@ssw0rd/i.test(matchedText) ||
      (matchedText.includes('cluster0.mongodb.net') && /admin:P@ssw0rd/i.test(matchedText))
    ) {
      return true;
    }
  }

  // PII Email: Fictional / Reserved test domains (RFC 2606)
  if (patternId === 'pii-email') {
    const lower = matchedText.toLowerCase();
    const fictionalDomains = [
      '@example.com',
      '@example.org',
      '@example.net',
      '@test.com',
      '@localhost',
      '@domain.com',
      '@company.com',
      '@cyberdyne.org',
      '@sample.org',
      '@yourdomain.com',
    ];
    if (fictionalDomains.some(d => lower.endsWith(d))) {
      return true;
    }
  }

  // PII Phone: Fictional exchange (555 telephone exchange reserved for entertainment/fiction)
  if (patternId === 'pii-phone') {
    if (/\b555[-.\s]?\d{4}\b/.test(matchedText) || /\(555\)/.test(matchedText) || /[-.\s]555[-.\s]/.test(matchedText)) {
      return true;
    }
  }

  // If the line is clearly labelled as a sample, mock, or test snippet
  if (
    lineUpper.includes('SAMPLE_SNIPPETS') ||
    lineUpper.includes('MOCK_CREDENTIAL') ||
    lineUpper.includes('DUMMY_DATA')
  ) {
    return true;
  }

  return false;
}

/**
 * Checks if a relative file path should be skipped during scanning.
 */
export function isIgnoredPath(filePath: string): boolean {
  if (!filePath) return false;
  const normalized = filePath.toLowerCase();
  const ignoredDirs = [
    'node_modules/', '.git/', 'dist/', 'build/', 'coverage/',
    '.next/', '.output/', 'vendor/', 'tmp/', 'temp/', '.cache/'
  ];
  const ignoredFiles = [
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'composer.lock', 'go.sum', 'Cargo.lock'
  ];
  const binaryExtensions = [
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.zip', '.tar', '.gz', '.pdf', '.mp3', '.mp4'
  ];

  for (let i = 0; i < ignoredDirs.length; i++) {
    if (normalized.includes(ignoredDirs[i])) return true;
  }
  for (let j = 0; j < ignoredFiles.length; j++) {
    if (normalized.endsWith(ignoredFiles[j])) return true;
  }
  for (let k = 0; k < binaryExtensions.length; k++) {
    if (normalized.endsWith(binaryExtensions[k])) return true;
  }
  return false;
}

/**
 * Sniffs first 1000 characters for null bytes or typical binary non-text indicators.
 */
export function isBinaryContent(content: string): boolean {
  if (!content) return false;
  const sample = content.slice(0, 1024);
  const len = sample.length;
  for (let i = 0; i < len; i++) {
    if (sample.charCodeAt(i) === 0) return true;
  }
  return false;
}

export interface SanitizeOptions {
  skipDummyExamples?: boolean;
}

/**
 * Scans content for secrets and PII, returning findings and the sanitized content.
 */
export function sanitizeContent(
  content: string,
  filePath: string = 'snippet.txt',
  repoName?: string,
  options?: SanitizeOptions
): { sanitizedContent: string; findings: Finding[] } {
  if (!content) {
    return { sanitizedContent: content || '', findings: [] };
  }

  const findings: Finding[] = [];
  let sanitizedContent = content;
  const lines = content.split(/\r?\n/);

  // 1. Regex Pattern Matching
  for (const pattern of SENSITIVE_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const matchedText = match[0];
      const matchIndex = match.index;
      const preMatchContent = content.slice(0, matchIndex);
      const lineNumber = preMatchContent.split(/\r?\n/).length;
      const currentLine = lines[lineNumber - 1] || '';

      // Special check for Credit Card Luhn validation
      if (pattern.id === 'pii-credit-card' || /^\d{13,19}$/.test(matchedText.replace(/\D/g, ''))) {
        if (!validateLuhn(matchedText)) {
          continue; // Skip invalid credit card numbers to reduce false positives
        }
      }

      // Check for benign IP address (0.0.0.0, 127.0.0.1, documentation IPs)
      if (pattern.id === 'pii-ipv4-v6' && isBenignIpAddress(matchedText)) {
        continue;
      }

      // Check if already redacted or part of a scanner rule definition
      if (isAlreadyRedactedOrPlaceholder(matchedText, currentLine)) {
        continue;
      }

      // Check if it's a known documentation dummy / mock credential
      const isMock = isDocumentationOrDummySecret(matchedText, pattern.id, currentLine);
      if (options?.skipDummyExamples && isMock) {
        continue;
      }

      // Extract surrounding context snippet (~40 chars around match)
      const startCtx = Math.max(0, matchIndex - 20);
      const endCtx = Math.min(content.length, matchIndex + matchedText.length + 20);
      const rawSnippet = content.slice(startCtx, endCtx).replace(/[\r\n]+/g, ' ');
      const contextSnippet = `...${rawSnippet}...`;

      findings.push({
        id: `finding-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        repo: repoName,
        filePath,
        lineNumber,
        patternId: pattern.id,
        patternName: pattern.name,
        category: pattern.category,
        matchedText,
        redactedText: pattern.placeholder,
        contextSnippet,
        confidence: isMock ? 'Low' : pattern.defaultConfidence,
        severity: pattern.severity,
        timestamp: new Date().toISOString(),
        isMockOrExample: isMock,
      });
    }

    // Surgical replacement preserving syntax and excluding false positives
    sanitizedContent = sanitizedContent.replace(
      new RegExp(pattern.regex.source, pattern.regex.flags),
      (m) => {
        if (pattern.id === 'pii-ipv4-v6' && isBenignIpAddress(m)) {
          return m;
        }
        if (isAlreadyRedactedOrPlaceholder(m)) {
          return m;
        }
        if (options?.skipDummyExamples && isDocumentationOrDummySecret(m, pattern.id)) {
          return m;
        }
        return pattern.placeholder;
      }
    );
  }

  // 2. Shannon Entropy Detector for variable assignments matching secret keywords
  const secretVarRegex = /(?:const|let|var|export|set|define|env|process\.env|ENV)\.?\s*([a-zA-Z0-9_]*key|[a-zA-Z0-9_]*token|[a-zA-Z0-9_]*secret|[a-zA-Z0-9_]*password|[a-zA-Z0-9_]*credential|[a-zA-Z0-9_]*auth)\s*[:=]\s*['"`]([a-zA-Z0-9_\-+/=]{16,128})['"`]/gi;
  
  let entropyMatch: RegExpExecArray | null;
  while ((entropyMatch = secretVarRegex.exec(content)) !== null) {
    const varName = entropyMatch[1];
    const secretCandidate = entropyMatch[2];
    const entropy = calculateEntropy(secretCandidate);

    // If entropy is > 3.8 and not already flagged by regex patterns
    if (entropy > 3.8) {
      if (
        isAlreadyRedactedOrPlaceholder(secretCandidate) ||
        (options?.skipDummyExamples && isDocumentationOrDummySecret(secretCandidate, 'entropy-detector'))
      ) {
        continue;
      }

      const isAlreadyFlagged = findings.some(f => f.matchedText.includes(secretCandidate));
      if (!isAlreadyFlagged) {
        const matchIndex = entropyMatch.index;
        const lineNumber = content.slice(0, matchIndex).split(/\r?\n/).length;
        const contextSnippet = `...${lines[lineNumber - 1] || entropyMatch[0]}...`;

        findings.push({
          id: `entropy-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          repo: repoName,
          filePath,
          lineNumber,
          patternId: 'entropy-detector',
          patternName: `High-Entropy Secret (${varName})`,
          category: 'Authentication & Tokens',
          matchedText: secretCandidate,
          redactedText: `<HIGH_ENTROPY_SECRET_REDACTED>`,
          contextSnippet,
          confidence: 'Medium',
          severity: 'High',
          timestamp: new Date().toISOString(),
          isMockOrExample: false,
        });

        // Replace only the candidate string literal value
        sanitizedContent = sanitizedContent.replace(secretCandidate, `<HIGH_ENTROPY_SECRET_REDACTED>`);
      }
    }
  }

  return { sanitizedContent, findings };
}

/**
 * Calculates Scan Stats summary.
 */
export function calculateScanStats(
  scannedCount: number,
  skippedBreakdown: SkipBreakdown,
  findings: Finding[],
  durationSeconds: number,
  extraAudit?: {
    totalLinesScanned?: number;
    totalBytesScanned?: number;
    auditedFiles?: ReadonlyArray<FileScanAuditItem>;
  }
): ScanStats {
  const findingsBySeverity: Record<Severity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  const findingsByCategory: Record<string, number> = {};

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
    findingsByCategory[f.category] = (findingsByCategory[f.category] || 0) + 1;
  }

  return {
    filesScanned: scannedCount,
    filesSkipped: skippedBreakdown.binary + skippedBreakdown.tooLarge + skippedBreakdown.ignored,
    skipReasons: skippedBreakdown,
    totalFindings: findings.length,
    durationSeconds: Math.max(0.1, parseFloat(durationSeconds.toFixed(2))),
    findingsBySeverity,
    findingsByCategory,
    totalLinesScanned: extraAudit?.totalLinesScanned,
    totalBytesScanned: extraAudit?.totalBytesScanned,
    auditedFiles: extraAudit?.auditedFiles,
  };
}

/**
 * Formats findings as SARIF v2.1.0 JSON format for GitHub Security integration.
 */
export function exportToSarif(findings: Finding[]): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Git Secret & PII Sanitizer',
            informationUri: 'https://github.com/craighckby-stack/AI-Project-Genesis-Scaffold',
            rules: SENSITIVE_PATTERNS.map(p => ({
              id: p.id,
              name: p.name,
              shortDescription: { text: p.description || p.name },
              defaultConfiguration: {
                level: p.severity === 'Critical' || p.severity === 'High' ? 'error' : 'warning',
              },
            })),
          },
        },
        results: findings.map(f => ({
          ruleId: f.patternId,
          message: {
            text: `Exposed ${f.patternName} detected on line ${f.lineNumber}.`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.filePath,
                },
                region: {
                  startLine: f.lineNumber,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Formats findings as CSV string.
 */
export function exportToCsv(findings: Finding[]): string {
  const headers = ['Repo', 'File Path', 'Line Number', 'Pattern Name', 'Category', 'Severity', 'Confidence', 'Matched Text', 'Redacted Text', 'Timestamp'];
  const rows = new Array(findings.length);
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    rows[i] = [
      `"${f.repo || 'Local'}"`,
      `"${f.filePath}"`,
      f.lineNumber,
      `"${f.patternName}"`,
      `"${f.category}"`,
      `"${f.severity}"`,
      `"${f.confidence}"`,
      `"${f.matchedText.replace(/"/g, '""')}"`,
      `"${f.redactedText.replace(/"/g, '""')}"`,
      `"${f.timestamp}"`,
    ].join(',');
  }

  return [headers.join(','), ...rows].join('\n');
}

/**
 * Formats findings as JSON string.
 */
export function exportToJson(findings: Finding[]): string {
  return JSON.stringify(findings, null, 2);
}