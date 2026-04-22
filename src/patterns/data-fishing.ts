import type { PatternRule } from '../types.js';

export const dataFishingRules: PatternRule[] = [
  {
    id: 'fishing-all-passwords',
    category: 'data-fishing',
    pattern: /(give|show|list|return|output|provide|dump)\s+(me\s+)?(all\s+)?(the\s+)?(user\s+)?passwords?(\s+in\s+the\s+(database|system|file))?/,
    weight: 9,
    description: 'Request all passwords',
  },
  {
    id: 'fishing-database-dump',
    category: 'data-fishing',
    pattern: /(dump|export|return|output|extract|download)\s+(the\s+)?(entire\s+|full\s+|whole\s+)?(database|db|data\s+store|datastore|data\s+warehouse)/,
    weight: 9,
    description: 'Dump entire database',
  },
  {
    id: 'fishing-list-users',
    category: 'data-fishing',
    pattern: /(list|show|return|output|give\s+me)\s+(all\s+|every\s+)?(users?|accounts?|customers?|members?|registered\s+users?)\s*(in\s+the\s+)?(system|database|db)?/,
    weight: 8,
    description: 'List all users/accounts',
  },
  {
    id: 'fishing-credit-cards',
    category: 'data-fishing',
    pattern: /(retrieve|get|return|show|give|output)\s+(all\s+)?(credit\s+card|payment\s+card|debit\s+card|financial|card)\s+(numbers?|data|info(rmation)?|details?)/,
    weight: 9,
    description: 'Retrieve credit card data',
  },
  {
    id: 'fishing-pii-bulk',
    category: 'data-fishing',
    pattern: /(export|extract|return|output|give|dump)\s+(all\s+)?(pii|personal\s+(data|information)|personally\s+identifiable)/,
    weight: 9,
    description: 'Bulk PII export',
  },
  {
    id: 'fishing-secret-files',
    category: 'data-fishing',
    pattern: /(read|open|output|return|show|cat|print)\s+.{0,20}(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\.env|secrets?\.json|credentials?\.json|config\.json|id_rsa)/,
    weight: 10,
    description: 'Read sensitive system files',
  },
  {
    id: 'fishing-env-vars',
    category: 'data-fishing',
    pattern: /(print|show|output|return|list|dump)\s+(all\s+)?(environment\s+variables?|env\s+vars?|process\.env|os\.environ)/,
    weight: 8,
    description: 'Dump environment variables',
  },
  {
    id: 'fishing-private-keys',
    category: 'data-fishing',
    pattern: /(show|return|export|output|give|read)\s+(me\s+)?(my\s+|the\s+)?(private\s+(\w+\s+)?key|ssh\s+key|rsa\s+key|pgp\s+key|gpg\s+key|signing\s+key)/,
    weight: 9,
    description: 'Extract private/SSH keys',
  },
  {
    id: 'fishing-internal-endpoints',
    category: 'data-fishing',
    pattern: /(list|show|output|return)\s+(all\s+)?(internal\s+)?(api\s+endpoints?|routes?|urls?|http\s+routes?|rest\s+endpoints?)/,
    weight: 7,
    description: 'List internal API endpoints',
  },
  {
    id: 'fishing-sql-injection-probe',
    category: 'data-fishing',
    pattern: /(\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\b|\bdelete\s+from\b|\btruncate\s+table\b|\bexec(\s+|\())/,
    weight: 8,
    description: 'SQL injection probe',
  },
];
