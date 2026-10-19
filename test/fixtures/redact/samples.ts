/**
 * Synthetic redaction fixtures. None of these values is a real credential:
 * every token is assembled at runtime from inert fragments so the repository
 * does not contain a contiguous provider-key pattern (GitHub push protection)
 * while the redaction rules still see the full shape.
 */

const j = (...parts: readonly string[]): string => parts.join('')

const PEM_BEGIN = j('-----BEGIN ', 'RSA PRIVATE KEY-----')
const PEM_END = j('-----END ', 'RSA PRIVATE KEY-----')

/** One-read strings used by the rule/tier tests. */
export const SAMPLE = {
  /** Multi-line, self-contained PEM block with a synthetic body. */
  pem: [PEM_BEGIN, 'U3ludGhldGljIHRlc3QgY29udGVudCBvbmx5', PEM_END].join('\n'),
  awsAccessKey: j('AKIA', 'CNY9KV6HS3EP0BMX'),
  githubToken: j('ghp_', 'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3A'),
  openaiKey: j('sk-', 'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3AHOVcjqx4BIPW'),
  anthropicKey: j('sk-ant-', 'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3AHOVc'),
  deepseekKey: j('sk-', '16b05af49e38d27c', '16b05af49e38d27c'),
  bearer: j('Bearer ', 'DKRYfmt07ELSZgnu18FMTaho'),
  jwt: j(
    'eyJhbGciOiJIUzI1NiJ9',
    '.',
    'eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9',
    '.',
    'c2lnbmF0dXJlLXN5bnRoZXRpYy0wMDE',
  ),
  googleApiKey: j('AIza', 'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3'),
  alibabaAccessKey: j('LTAI', 'DKRYfmt07ELSZgnu'),
  slackToken: j('xoxb-', 'DKRYfmt07ELS'),
  slackWebhook: j(
    'https://hooks.slack.com/services/',
    'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3AHOVcjqx4',
  ),
  npmToken: j('npm_', 'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3A'),
  gitlabPat: j('glpat-', 'DKRYfmt07ELSZgnu18FMTaho'),
  telegramToken: j('123456789', ':', 'DKRYfmt07ELSZgnu18FMTahov29GNUbipw3'),
  urlCredentials: j(
    'postgres://',
    'svc_user',
    ':',
    'Q7mZ2vK9pR4t',
    '@db.synthetic.test:5432/app',
  ),
  urlAccessToken: j(
    'https://app.synthetic.test/callback?access_token=',
    'Q7mZ2vK9pR4tW1yB6nL3cD5f',
  ),
  /** A mixed-class 24-char token that the entropy fallback accepts. */
  highEntropy: 'Q7mZ2vK9pR4tW1yB6nL3cD5f',
  /** Lowercase prose long enough to interest the entropy fallback, but single-class. */
  prose: 'implementationconfigurationdocumentationnotes',
  /** Glued common English words: mixed case but semantically prose. */
  gluedProse: 'TheAndForThatWithThisFrom',
  /** Documentation placeholder; the api-key validator must reject it. */
  fakeApiKeyAssignment: j('api_key = ', '"your_api_key_here"'),
  email: 'alice.synthetic@example.test',
  emailUpper: '  ALICE.SYNTHETIC@EXAMPLE.TEST  ',
  phoneCn: '13800138000',
  phoneCnSpaced: '138-0013-8000',
  phoneIntl: '+8613800138000',
  isoDate: '2026-10-19',
  idCn: '11010519900307123X',
  idCnLower: '11010519900307123x',
  /** Public, non-account Visa test PAN (Luhn valid). */
  cardValid: '4111111111111111',
  cardValidSpaced: '4111 1111 1111 1111',
  /** Same PAN with the check digit changed (Luhn invalid). */
  cardInvalid: '4111111111111112',
  ssnUs: '123-45-6789',
  ssnUsDigits: '123456789',
  envSecret: j('AWS_SECRET_ACCESS_KEY=', 'Q7mZ2vK9pR4tW1yB6nL3cD5f'),
  keyAssignment: j('deepseek_api_key=', 'Q7mZ2vK9pR4tW1yB6nL3cD5f'),
  safeEnvName: 'PASSWORD_STORE_DIR=/home/synthetic/.password-store',
  nonSensitiveEnvName: 'KEYBOARD_LAYOUT=us',
  propertyChainPassword: 'password=req.body.password',
  propertyChainToken: 'token=response.data.token',
} as const

/** Ordinary text that no rule should touch at any level. */
export const BENIGN = 'Deploy notes: the service starts on port 8080 and logs to stdout.'
