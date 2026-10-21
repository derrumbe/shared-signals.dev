export const SITE = {
  title: 'shared-signals.dev',
  description:
    'A developer guide to the OpenID Shared Signals Framework (SSF), CAEP, RISC and SCIM Events: how the standards work, who implements them, and tools to try them.',
};

export const NAV = [
  { href: '/learn/', label: 'Learn' },
  { href: '/specs/', label: 'Specs' },
  { href: '/events/', label: 'Events' },
  { href: '/implementations/', label: 'Implementations' },
  { href: '/playground/', label: 'Playground' },
  { href: '/working-group/', label: 'Working group' },
  { href: '/about/', label: 'About' },
];

export const LEARN = [
  { href: '/learn/', label: 'Overview' },
  { href: '/learn/streams/', label: 'Streams & management' },
  { href: '/learn/sets/', label: 'Security Event Tokens' },
  { href: '/learn/subjects/', label: 'Subjects' },
  { href: '/learn/delivery/', label: 'Push & poll delivery' },
  { href: '/learn/discovery/', label: 'Discovery' },
];

export const SPEC_URLS = {
  ssf: 'https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html',
  caep: 'https://openid.net/specs/openid-caep-1_0-final.html',
  risc: 'https://openid.net/specs/openid-risc-1_0-final.html',
  scimEvents: 'https://www.rfc-editor.org/rfc/rfc9967',
  caepInterop: 'https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html',
  caepInteropEditors: 'https://openid.github.io/sharedsignals/openid-caep-interoperability-profile-1_0.html',
  editors: 'https://openid.github.io/sharedsignals/',
  wg: 'https://openid.net/wg/sharedsignals/',
  github: 'https://github.com/openid/sharedsignals',
};

// The openid/sharedsignals commit this site's content was last checked against.
// `npm run check-specs` lists anything newer.
export const SPECS_SYNC = { commit: 'a34d6ff', date: '2026-09-01', checked: '2026-10-18' };

// OpenID Foundation Shared Signals Working Group. Meeting time from the WG wiki (Meetings page,
// notes weekly through 2026-10-13); chairs from openid.net/wg/sharedsignals (checked 2026-10-14).
export const WG = {
  chairs: ['Mike Kiser (SailPoint)', 'Sean O’Dell (CVS Health)', 'Atul Tulshibagwale (CrowdStrike)'],
  meetings: 'Every Tuesday, 10:00 Pacific / 13:00 Eastern',
  meetingsWiki: 'https://github.com/openid/sharedsignals/wiki/Meetings',
  list: 'openid-specs-risc@lists.openid.net',
  listInfo: 'https://lists.openid.net/mailman/listinfo/openid-specs-risc',
  listArchive: 'https://lists.openid.net/pipermail/openid-specs-risc/',
  charter: 'https://openid.net/wg/sharedsignals/charter/',
};
