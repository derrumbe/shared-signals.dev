// OpenID Foundation Shared Signals interoperability events. Participant lists come from the
// OIDF posts linked here (plus SGNL's and Okta's write-ups where OIDF published no list).
export const INTEROP_EVENTS = {
  'london-2024': {
    label: 'Gartner IAM London, Mar 2024',
    short: 'LON ’24',
    url: 'https://openid.net/shared-signals-enhanced-security-for-all/',
    note: 'The first CAEP interop event.',
  },
  'texas-2024': {
    label: 'Gartner IAM Grapevine TX, Dec 2024',
    short: 'TX ’24',
    url: 'https://openid.net/shared-signals-interoperability-at-gartner-iam/',
    note: 'SSF, CAEP, RISC and SCIM Events; 14 implementations, with published push/poll results.',
  },
  'london-2025': {
    label: 'Gartner IAM London, Mar 2025',
    short: 'LON ’25',
    url: 'https://www.okta.com/blog/product-innovation/okta-leads-the-way-driving-real-time-security-with-shared-signals/',
    note: 'OIDF published no participant list; participants are compiled from Okta’s write-up and participant confirmations, and may be partial.',
  },
  'authenticate-2025': {
    label: 'Authenticate 2025, Carlsbad CA, Oct 2025',
    short: 'AUTH ’25',
    url: 'https://openid.net/top-firms-test-interoperability-of-final-ssf-and-caep/',
    note: 'The first interop against the final SSF 1.0 and CAEP 1.0 specifications; 8 implementations.',
  },
} as const;

export type InteropEventId = keyof typeof INTEROP_EVENTS;
