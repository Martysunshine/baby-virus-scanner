/* baby-virus-scanner dashboard v2: application shell and main views (agent UI-A).
 *
 * - Creates window.BVSApp synchronously (docs/ui-contract.md) so storage-view.js, infosec.js and
 *   scanner.js can attach to it. Everything they add is optional: without them the shell shows
 *   friendly placeholder views and "Ask INFOSEC" goes to #/infosec.
 * - Loads the scan's data scripts (script tags, so file:// works), then runs a hash router.
 * - The page itself never changes the PC. v3 (docs/ui-contract-v3.md, agent L): buttons send *signals*
 *   to the user's Claude session (POST /api/signal); fixes and deletions always need the user's own typed
 *   confirmation in the Claude chat, and deletions also need a typed "I confirm" here first.
 * - Privacy mode (default on) hides names under personal folders; AI needs an explicit consent.
 * - Scan data is untrusted: it reaches the DOM only as text (util.js el() / textContent). */
(function () {
  'use strict';
  var U = window.BVSUI.util;
  var el = U.el;
  var BVS = window.BVS;
  var ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
  var HASH_RE = /^#\/[\w\/?&=,.%+:~!*'()@-]*$/;
  var PATH_D_RE = /^[MmLlHhVvCcSsQqTtAaZz0-9 ,.\-]+$/;
  var COLOR_RE = /^(#[0-9a-fA-F]{3,8}|var\(--[a-z0-9-]+\)|(rgb|hsl)a?\([0-9.,%\s]+\))$/;
  var SVGNS = 'http://www.w3.org/2000/svg';
  var PAGE_SIZE = 60;

  // ================================================================== icons (inline SVG paths)
  var ICONS = {
    overview: 'M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z',
    shield: 'M12 3l8 3v6c0 4.8-3.4 8.4-8 9-4.6-.6-8-4.2-8-9V6z',
    shieldCheck: 'M12 3l8 3v6c0 4.8-3.4 8.4-8 9-4.6-.6-8-4.2-8-9V6zM8.5 12l2.5 2.5 4.5-5',
    shieldAlert: 'M12 3l8 3v6c0 4.8-3.4 8.4-8 9-4.6-.6-8-4.2-8-9V6zM12 8v5M12 16.5v.01',
    question: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM9.2 9.2a2.9 2.9 0 0 1 5.6 1c0 1.9-2.8 2.6-2.8 2.6M12 17h.01',
    storage: 'M21 12a9 9 0 1 1-9-9v9zM15 3.6A9 9 0 0 1 20.4 9H15z',
    performance: 'M13 2 4 14h7l-1 8 9-12h-7z',
    health: 'M3 12h4l3-7 4 14 3-7h4',
    basket: 'M3 9h18l-1.8 9.6a2 2 0 0 1-2 1.6H6.8a2 2 0 0 1-2-1.6zM8 9l4-6 4 6M9.5 13v4M14.5 13v4',
    infosec: 'M12 3l1.8 4.9L19 9.6l-5.2 1.8L12 16.4l-1.8-5L5 9.6l5.2-1.7zM19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z',
    file: 'M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8zM14 3v5h5',
    fix: 'M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9z',
    info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 16v-5M12 8h.01',
    check: 'M20 6 9 17l-5-5',
    checkCircle: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM8 12.5l2.5 2.5L16 9.5',
    alert: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
    xCircle: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM15 9l-6 6M9 9l6 6',
    chevron: 'M9 18l6-6-6-6',
    chevronLeft: 'M15 18l-6-6 6-6',
    arrow: 'M5 12h14M13 5l7 7-7 7',
    back: 'M19 12H5M11 19l-7-7 7-7',
    menu: 'M4 6h16M4 12h16M4 18h16',
    close: 'M18 6 6 18M6 6l12 12',
    sun: 'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
    moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
    auto: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 3v18M12 7h5M12 11h7M12 15h6',
    search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
    lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
    refresh: 'M21 12a9 9 0 0 1-15.5 6.3L3 16M3 21v-5h5M3 12a9 9 0 0 1 15.5-6.3L21 8M21 3v5h-5',
    activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
    copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
    eyeOff: 'M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.9 8.3 2 12 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2',
    list: 'M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01',
    cpu: 'M6 6h12v12H6zM9.5 9.5h5v5h-5zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4',
    package: 'M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8',
    power: 'M12 2v9M18.4 6.6a9 9 0 1 1-12.8 0',
    battery: 'M3 7h15v10H3zM21 10.5v3M6 10v4M9 10v4',
    disk: 'M22 12H2M5.5 5h13L22 12v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6zM6 16h.01M10 16h.01',
    link: 'M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7',
    folder: 'M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z',
    globe: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18',
    wifi: 'M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0M12 19.5h.01',
    key: 'M7.5 21a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9zM10.7 13.3 20 4M16 8l3 3M18 6l2 2',
    code: 'M16 18l6-6-6-6M8 6l-6 6 6 6',
    bot: 'M12 8V4H8M4 8h16v12H4zM2 14h2M20 14h2M15 13v2M9 13v2',
    history: 'M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5M12 7v5l4 2',
    browser: 'M3 5h18v14H3zM3 9h18M6.5 7h.01M9 7h.01',
    users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8',
    clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2',
    trash: 'M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14',
    eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    send: 'M4 12 20 4l-6 16-2.5-6.5zM11.5 13.5 20 4',
    plug: 'M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5',
    terminal: 'M3 5h18v14H3zM7 9l3 3-3 3M12 15h5',
    hand: 'M8 13V5.5a1.5 1.5 0 0 1 3 0V11M11 10.5V4a1.5 1.5 0 0 1 3 0v6.5M14 10.5V5.5a1.5 1.5 0 0 1 3 0V14a7 7 0 0 1-7 7h-.5A6.5 6.5 0 0 1 4 17l-1.6-3.2a1.5 1.5 0 0 1 2.6-1.4L8 15',
    dot: 'M12 12h.01'
  };

  // ================================================================== friendly wording (contract)
  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  var SEV = {
    critical: { label: 'Act now', plain: 'likely an active threat', tech: 'Critical', color: 'var(--sev-critical)' },
    high: { label: 'Important', plain: 'fix soon', tech: 'High', color: 'var(--sev-high)' },
    medium: { label: 'Worth fixing', plain: 'a weakness', tech: 'Medium', color: 'var(--sev-medium)' },
    low: { label: 'Minor', plain: 'small tidy-up', tech: 'Low', color: 'var(--sev-low)' },
    info: { label: 'FYI', plain: 'for your information', tech: 'Info', color: 'var(--sev-info)' }
  };
  var CLASS_ORDER = ['compromise', 'suspicious', 'hardening', 'hygiene', 'info'];
  var CLASSES = {
    compromise: { label: 'Sign of attack', plain: 'a sign that someone may have broken in' },
    suspicious: { label: 'Needs a look', plain: 'something unusual that deserves a look; on its own it is not proof of an attack' },
    hardening: { label: 'Security setting to tighten', plain: 'a setting or habit that makes an attack easier; it is not a sign of attack' },
    hygiene: { label: 'Clean-up', plain: 'a leftover or tidy-up item' },
    info: { label: 'Information', plain: 'background information only' }
  };
  var VERIFY_ORDER = ['refuted', 'confirmed', 'inconclusive', 'unverified'];
  var VERIFY = {
    refuted: { label: 'Checked: false alarm', plain: 'A second, different check showed this is not a real problem, so it does not count.', tone: 'good', icon: 'checkCircle' },
    confirmed: { label: 'Checked: real', plain: 'A second check confirmed this is real.', tone: 'bad', icon: 'alert' },
    inconclusive: { label: 'Checked: unclear', plain: 'A second check could not decide either way.', tone: 'warn', icon: 'question' },
    unverified: { label: 'Not double-checked', plain: 'Nobody has run a second check on this yet.', tone: 'neutral', icon: 'clock' }
  };
  var SAFETY_ORDER = ['safe', 'safe_after_check', 'review', 'use_tool', 'do_not_touch'];
  var SAFETY = {
    safe: { label: 'Safe to remove', plain: 'Nothing needs it; removing it is harmless.', tone: 'good', color: 'var(--saf-safe)' },
    safe_after_check: { label: 'Safe after a quick check', plain: 'Usually fine to remove; glance at it first.', tone: 'info', color: 'var(--saf-check)' },
    review: { label: 'Look before deleting', plain: 'It might be something you want to keep. Open it and decide.', tone: 'warn', color: 'var(--saf-review)' },
    use_tool: { label: "Clean with the app's own tool", plain: "Don't delete these files by hand; use the app or Windows tool named in the instructions.", tone: 'tool', color: 'var(--saf-tool)' },
    do_not_touch: { label: 'System: leave alone', plain: 'Windows or a program needs this. Do not delete it.', tone: 'neutral', color: 'var(--saf-system)' }
  };
  var VERDICTS = {
    COMPROMISED: { label: 'Hacked', headline: 'Signs of an attack were found. Act now.', plain: 'At least one serious sign of attack was double-checked and confirmed real.', status: 'danger', icon: 'shieldAlert' },
    SUSPICIOUS: { label: 'Needs a closer look', headline: 'Something unusual needs a closer look.', plain: 'An important warning sign has not been ruled out yet. That is not proof of an attack.', status: 'warning', icon: 'shieldAlert' },
    HARDENING_NEEDED: { label: 'Safe, settings to tighten', headline: 'No signs of hacking found. A few security settings should be tightened.', plain: 'Nothing points to an attack, but some settings make one easier than it should be.', status: 'warning', icon: 'shieldCheck' },
    OK: { label: 'All good', headline: 'Your computer looks clean and well protected.', plain: 'Nothing more serious than small tidy-ups was found.', status: 'safe', icon: 'shieldCheck' }
  };
  var STATUS = {
    safe: { label: 'Looks good', tone: 'good', icon: 'checkCircle' },
    warning: { label: 'Needs attention', tone: 'warn', icon: 'alert' },
    danger: { label: 'Act now', tone: 'bad', icon: 'xCircle' }
  };
  var GRADES = {
    good: { label: 'Good', tone: 'good', icon: 'checkCircle' },
    ok: { label: 'OK', tone: 'info', icon: 'info' },
    attention: { label: 'Needs attention', tone: 'warn', icon: 'alert' },
    bad: { label: 'Problem', tone: 'bad', icon: 'xCircle' }
  };
  var MODULES = {
    S01: 'Startup & persistence', S02: 'Running programs & files', S03: 'Accounts & settings', S04: 'History & logs',
    S05: 'Antivirus history', S06: 'Browsers', S07: 'Network', S08: 'Devices on your Wi-Fi', S09: 'Claude Code & AI tools',
    S10: 'Code editors & git', S11: 'Software packages', S12: 'Exposed secrets', S13: 'GitHub & npm',
    G0: 'Disk inventory', G1: 'Junk & big files', G2: 'Duplicates', H1: 'Programs & startup speed', H2: 'Disk & system health',
    A1: 'Administrator checks'
  };
  var MODULE_ICONS = {
    S01: 'power', S02: 'cpu', S03: 'users', S04: 'history', S05: 'shield', S06: 'browser', S07: 'globe', S08: 'wifi',
    S09: 'bot', S10: 'code', S11: 'package', S12: 'key', S13: 'code', G0: 'disk', G1: 'storage', G2: 'copy', H1: 'performance', H2: 'health'
  };
  var AREAS = ['Security', 'Storage', 'Stability', 'Privacy', 'Updates'];
  var AREA_ICONS = { Security: 'shield', Storage: 'storage', Stability: 'activity', Privacy: 'lock', Updates: 'refresh' };
  var AREA_LINKS = {
    Security: '#/security?sev=critical,high,medium&active=1', Storage: '#/storage', Stability: '#/health',
    Privacy: '#/security?module=S12,S06&active=1', Updates: '#/security?module=S11'
  };
  var COVERAGE_STATUS = {
    ok: { label: 'Checked fully', tone: 'good', plain: 'The check ran and saw everything it needed.' },
    partial: { label: 'Only partly checked', tone: 'warn', plain: 'The check ran but could not see everything, often because it was not run as administrator or the logs only go back a short time.' },
    needs_admin: { label: 'Needs administrator rights', tone: 'warn', plain: 'Windows only lets an administrator read this. Running the admin checks fills it in.' },
    needs_consent: { label: 'Needs your permission', tone: 'info', plain: 'Waiting for you to log in or allow it, for example a GitHub login.' },
    skipped: { label: 'Skipped', tone: 'neutral', plain: 'Not run this time, usually because something it depends on was missing.' },
    error: { label: 'Failed to run', tone: 'bad', plain: 'The check crashed or returned something unreadable.' },
    not_applicable: { label: "Doesn't apply to this PC", tone: 'neutral', plain: 'Nothing to check here on this computer.' }
  };
  var COVERAGE_ORDER = ['needs_admin', 'needs_consent', 'error', 'partial', 'skipped', 'not_applicable', 'ok'];
  var REASONS = {
    plaintext_secret: 'a password or token is saved as plain, readable text',
    user_writable: 'it sits in a folder that any program you run can change',
    created_lt_30d: 'it appeared in the last 30 days',
    exposed_service: 'it lets other computers connect in',
    weak_acl: 'its permissions are looser than they should be',
    expected_match: 'it matches a known, normal item',
    persistence: 'it starts automatically',
    unencrypted_key: 'a private key is saved without a password',
    missing_target: 'it points to a file that no longer exists',
    package_registry_credential: 'it holds a login for a software-package website',
    av_detection_history: 'your antivirus detected something here before',
    prompt_injection: 'it contains text that tries to give instructions to AI tools',
    autorun_on_open: 'it runs code automatically when a folder is opened',
    registry_config: 'it is a Windows registry setting',
    tls_verification_disabled: 'secure-connection checks are switched off',
    sent_to_model: 'its content may have been sent to an AI model',
    public_network: 'it talks to the internet',
    av_content_hit: 'your antivirus flagged its content',
    running: 'it is running right now',
    motw_unknown_host: 'it was downloaded from an unfamiliar website',
    source_chat_cdn: 'it was downloaded from a chat-app link',
    quarantined: 'your antivirus quarantined it',
    av_exclusion: 'it is excluded from antivirus scanning',
    outdated_component: 'it is an outdated version',
    banner_version: 'it shows its version number to the network',
    trust_disabled: 'a safety prompt is switched off',
    shell_history: 'it appears in your command history',
    remote_ahead: 'the online copy has changes you do not have',
    unsigned: 'it has no digital signature from its maker',
    invalid_signature: 'its digital signature is broken',
    masquerading: 'it pretends to be something else',
    random_name: 'it has a random-looking name',
    removed_entry: 'an entry was removed',
    av_url_block: 'your antivirus blocked a web address',
    unquoted_service_path: 'a service path is written in an unsafe way',
    stale_registration: 'it is a leftover registration',
    all_sites_access: 'it can read every website you visit',
    sensitive_api: 'it uses powerful browser features',
    developer_mode: 'developer mode is switched on',
    external_registration: 'it was installed from outside the official store',
    orphan: 'nothing uses it any more',
    stale: 'it has not changed for a long time',
    vulnerable_dependency: 'it uses a component with a known security hole',
    obfuscation: 'its code is deliberately hard to read',
    nonstandard_location: 'it is in an unusual place',
    recently_changed: 'it changed recently',
    decoded_url_opener: 'it opens a hidden web address',
    encoded_command: 'it runs a hidden (encoded) command',
    defender_off: 'Microsoft Defender is switched off',
    wallet_present: 'a crypto wallet was found',
    upnp: 'it can open ports on your router automatically',
    plaintext_http: 'it uses an unencrypted connection',
    unknown_device_census: 'there are devices on your network we could not identify',
    third_party_repo: 'it uses a third-party software source',
    key_material: 'it contains secret key material'
  };
  var FLAGS = {
    not_used_180d: 'Not used for 6+ months', no_recent_use_evidence: 'No sign of recent use', server_software: 'Server software',
    shadowed_duplicate: 'Installed twice', pup_candidate: 'Possibly unwanted', bloat_candidate: 'Possibly bloatware', broken: 'Broken',
    battery_drain: 'Drains battery', running: 'Running now', top_cpu: 'Busy processor', top_ram: 'Uses lots of memory', unsigned: 'Not signed',
    work_at_risk: 'Unsaved work at risk', hardlinks_overcount: 'Size overstated', stability_hot_spot: 'Stability problem',
    hardware_warning: 'Hardware warning', needs_admin: 'Needs admin', backup_required: 'Back up first', stale: 'Old', different_names: 'Different names'
  };
  var BUGCHECKS = {
    '0x9F': 'a driver failed while the PC went to sleep or woke up',
    '0x154': 'Windows hit an error in its memory store, often a disk or driver problem',
    '0x50': 'a program or driver used memory that was not there',
    '0x14F': 'a power or standby watchdog timed out',
    '0xD1': 'a driver used memory it was not allowed to',
    '0x133': 'a driver took too long to respond',
    '0x1A': 'a memory-management error, sometimes faulty RAM',
    '0x7E': 'a system component crashed',
    '0xEF': 'a critical Windows process stopped',
    '0x124': 'the hardware reported an error',
    '0x0': 'power loss or a hard freeze'
  };

  // ================================================================== state
  var S = {
    ready: false, dirId: null, scanId: null, base: null, manifest: null, summary: {}, findings: [],
    findingsById: new Map(), coverage: {}, guide: null, datasets: {}, itemsById: new Map(), basket: null,
    current: { id: null, def: null, root: null, key: null }, lastSecurityQS: '', failed: []
  };
  var views = Object.create(null);
  var viewOrder = Object.create(null);
  var viewSeq = 0;
  var readyFns = [];

  // ================================================================== window.BVSApp (synchronous)
  var App = window.BVSApp || {};
  window.BVSApp = App;
  App.version = 2;
  App.ready = false;
  App.basket = null;
  App.askImpl = App.askImpl || null;
  App.pendingInfosec = null;
  App.icons = ICONS;

  App.registerView = function (id, def) {
    if (typeof id !== 'string' || !ID_RE.test(id) || !def || typeof def.mount !== 'function') {
      if (window.console) { console.warn('BVSApp.registerView: ignored invalid view', id); }
      return false;
    }
    if (!viewOrder[id]) { viewOrder[id] = ++viewSeq; }
    views[id] = def;
    if (S.ready) {
      renderNav();
      if (S.current.id === id) { S.current.key = null; S.current.def = null; route(); }
    }
    return true;
  };

  App.navigate = function (hash, opts) {
    opts = opts || {};
    if (typeof hash !== 'string') { return; }
    if (hash.charAt(0) === '/') { hash = '#' + hash; }
    if (!HASH_RE.test(hash)) { return; }
    if (opts.replace) {
      try { history.replaceState(null, '', hash); } catch (e) { window.location.replace(hash); return; }
      route();
    } else if (window.location.hash === hash) {
      route();
    } else {
      window.location.hash = hash;
    }
  };

  App.findingById = function (id) { return S.findingsById.get(id) || null; };
  App.itemById = function (id) { return S.itemsById.get(id) || null; };
  App.onReady = function (fn) {
    if (typeof fn !== 'function') { return; }
    if (S.ready) { try { fn(App); } catch (e) { console.error(e); } } else { readyFns.push(fn); }
  };
  App.data = {
    get: function (name) { return BVS.get(name); },
    summary: function () { return S.summary; },
    findings: function () { return S.findings; },
    guide: function () { return S.guide; },
    items: function (name) { return (S.datasets[name] || {}).items || []; }
  };
  App.scan = {};
  App.loadChunk = function (name) {
    if (typeof name !== 'string' || !ID_RE.test(name) || !S.base) { return Promise.reject(new Error('bad chunk name')); }
    return BVS.loadScript(S.base + name + '.js');
  };

  // onEvent / signal (optional) pass through to INFOSEC: streamed answer events and the Stop button.
  App.ask = function (question, context, onEvent, signal) {
    var offline = { text: offlineAnswer(question, context), source: 'offline' };
    if (typeof App.askImpl === 'function') {
      try {
        return Promise.resolve(App.askImpl(question, context, onEvent, signal)).then(function (r) {
          return r && typeof r.text === 'string' ? r : Object.assign({ error: 'empty answer' }, offline);
        }, function (err) {
          return Object.assign({ error: String((err && err.message) || err) }, offline);
        });
      } catch (e) { return Promise.resolve(Object.assign({ error: String(e && e.message) }, offline)); }
    }
    return Promise.resolve(Object.assign({ error: 'INFOSEC is not available in this copy' }, offline));
  };

  // Default "Ask INFOSEC": infosec.js replaces this function when it loads (opens the docked copilot).
  App.openInfosec = function (opts) {
    App.pendingInfosec = opts || null;
    App.navigate('#/infosec');
  };

  App.friendly = {
    severity: function (sev) {
      var key = SEV[sev] ? sev : 'info', m = SEV[key];
      return { key: key, label: m.label, plain: m.plain, color: m.color, tech: m.tech };
    },
    safety: function (s) {
      var key = SAFETY[s] ? s : 'review', m = SAFETY[key];
      return { key: key, label: m.label, plain: m.plain, color: m.color, tone: m.tone };
    },
    verdict: function (v) {
      var key = VERDICTS[v] ? v : 'HARDENING_NEEDED', m = VERDICTS[key];
      return { key: key, label: m.label, headline: m.headline, plain: m.plain, status: m.status, color: statusColor(m.status) };
    },
    verification: function (v) { var key = VERIFY[v] ? v : 'unverified'; return { key: key, label: VERIFY[key].label, plain: VERIFY[key].plain, tone: VERIFY[key].tone }; },
    klass: function (c) { var key = CLASSES[c] ? c : 'info'; return { key: key, label: CLASSES[key].label, plain: CLASSES[key].plain }; },
    module: function (m) { return MODULES[m] || String(m || ''); },
    reason: function (r) { return reasonText(r); },
    flag: function (f) { return FLAGS[f] || humanize(f); }
  };

  // ================================================================== DOM helpers
  function $(id) { return document.getElementById(id); }
  function svgEl(tag, attrs) {
    var n = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, String(attrs[k])); });
    return n;
  }
  function icon(name, cls) {
    var d = ICONS[name] || (typeof name === 'string' && name.length < 4000 && PATH_D_RE.test(name) ? name : ICONS.dot);
    var svg = svgEl('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false', 'class': 'ico' + (cls ? ' ' + cls : '') });
    svg.appendChild(svgEl('path', { d: d }));
    return svg;
  }
  function short(s, n) {
    s = U.safeText(s);
    n = n || 80;
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }
  function bvs(type, id, label, extra) {
    var a = { 'data-bvs-type': type };
    if (id !== undefined && id !== null && id !== '') { a['data-bvs-id'] = String(id); }
    if (label) { a['data-bvs-label'] = short(label, 120); }
    if (extra) { Object.keys(extra).forEach(function (k) { a[k] = extra[k]; }); }
    return a;
  }
  function link(hash, opts, children) {
    var a = el('a', opts || {}, children);
    if (typeof hash === 'string' && HASH_RE.test(hash)) { a.setAttribute('href', hash); }
    return a;
  }
  function button(label, onClick, opts) {
    opts = opts || {};
    return el('button', {
      cls: 'btn' + (opts.cls ? ' ' + opts.cls : ''), title: opts.title,
      attrs: Object.assign({ type: 'button' }, opts.attrs || {}), on: { click: onClick }
    }, [opts.icon ? icon(opts.icon) : null, label ? el('span', { text: label }) : null, opts.after ? icon(opts.after) : null]);
  }
  function goLink(hash, label, opts) {
    opts = opts || {};
    return link(hash, { cls: 'go-link' + (opts.cls ? ' ' + opts.cls : ''), attrs: opts.attrs }, [el('span', { text: label }), icon('arrow')]);
  }
  function plural(n, one, many) { return n === 1 ? one : many; }
  function humanize(s) {
    s = String(s || '').replace(/[_-]+/g, ' ').trim();
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
  }
  function lowerFirst(s) { s = String(s || ''); return s ? s.charAt(0).toLowerCase() + s.slice(1) : s; }
  function upperFirst(s) { s = String(s || ''); return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }
  function reasonText(r) { return REASONS[r] || humanize(r).toLowerCase(); }
  function moduleName(m) { return MODULES[m] || String(m || 'Unknown area'); }
  function statusColor(st) { return st === 'safe' ? 'var(--good)' : st === 'danger' ? 'var(--bad)' : 'var(--warn)'; }
  function arr(v) { return Array.isArray(v) ? v.filter(function (x) { return x !== null && x !== undefined && x !== ''; }) : []; }
  function str(v) { return typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v); }
  function safeHash(h, fallback) { return typeof h === 'string' && HASH_RE.test(h) ? h : fallback; }
  function fmtWhen(v) {
    var d = U.toDate(v);
    if (!d) { return '—'; }
    try { return d.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch (e) { return U.fmtDate(v, true); }
  }
  function fmtDay(v) {
    var d = U.toDate(v);
    if (!d) { return '—'; }
    try { return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }); } catch (e) { return U.fmtDate(v); }
  }
  function splitSteps(text) {
    if (Array.isArray(text)) { return arr(text).map(str); }
    var s = str(text).trim();
    if (!s) { return []; }
    return s.split(/(?<=[.!?])\s+(?=[A-Z0-9("'])/).map(function (t) { return t.trim(); }).filter(Boolean);
  }
  function firstSentence(text) { return splitSteps(text)[0] || ''; }

  function toneBadge(text, tone, iconName, title) {
    return el('span', { cls: 'badge tone-' + (tone || 'neutral'), title: title }, [iconName ? icon(iconName) : null, el('span', { text: text })]);
  }
  function sevBadge(sev) {
    var key = SEV[sev] ? sev : 'info', m = SEV[key];
    return el('span', { cls: 'sev-badge sev-' + key, title: 'How serious: ' + m.label + ' (' + m.tech + ') = ' + m.plain }, [
      el('span', { cls: 'sev-dot', attrs: { 'aria-hidden': 'true' } }), el('span', { text: m.label })
    ]);
  }
  function verifyBadge(v) { var m = VERIFY[v] || VERIFY.unverified; return toneBadge(m.label, m.tone, m.icon, m.plain); }
  function safetyBadge(s) {
    var key = SAFETY[s] ? s : 'review', m = SAFETY[key];
    return el('span', { cls: 'safety-badge saf-' + key, title: m.plain }, [el('span', { cls: 'saf-dot', attrs: { 'aria-hidden': 'true' } }), el('span', { text: m.label })]);
  }
  // Items with nothing to remove (method "none") get "Advice only" instead of a deletion-safety label,
  // except system items, where "System: leave alone" is the useful message.
  function itemSafetyBadge(it) {
    if (it && it.method === 'none' && it.safety !== 'do_not_touch') { return toneBadge('Advice only', 'neutral', 'info', 'Nothing to delete here: open it for advice.'); }
    return safetyBadge(it ? it.safety : null);
  }
  function gradeBadge(g) { var m = GRADES[g] || GRADES.ok; return toneBadge(m.label, m.tone, m.icon); }
  function flagChip(f) {
    var risky = /work_at_risk|unpushed|uncommitted|broken|hardware|stability|pup/.test(f);
    return el('span', { cls: 'flag-chip' + (risky ? ' risk' : ''), text: FLAGS[f] || humanize(f) });
  }
  function pageHead(iconName, title, intro, extra) {
    return el('header', { cls: 'page-head', attrs: { 'data-bvs-section': 'page-head' } }, [
      el('div', { cls: 'page-icon' }, icon(iconName)),
      el('div', { cls: 'page-titles' }, [el('h1', { text: title }), intro ? el('p', { cls: 'page-intro', text: intro }) : null]),
      extra ? el('div', { cls: 'page-extra' }, extra) : null
    ]);
  }
  function card(opts, children) {
    opts = opts || {};
    var head = null;
    if (opts.title) {
      var t = opts.href ? link(opts.href, { cls: 'card-title-link' }, [el('span', { text: opts.title }), icon('chevron')]) : opts.title;
      head = el('div', { cls: 'card-head' }, [
        opts.icon ? el('span', { cls: 'card-ico' }, icon(opts.icon)) : null,
        el('div', { cls: 'card-titles' }, [el(opts.h || 'h2', { cls: 'card-title' }, t), opts.sub ? el('p', { cls: 'card-sub', text: opts.sub }) : null]),
        opts.aside || null
      ]);
    }
    var attrs = Object.assign({}, opts.attrs || {});
    if (opts.section) { attrs['data-bvs-section'] = opts.section; }
    var c = el(opts.tag || 'section', { cls: 'card' + (opts.cls ? ' ' + opts.cls : ''), attrs: attrs }, [head]);
    U.append(c, children);
    if (opts.accent) { c.style.setProperty('--card-accent', opts.accent); }
    return c;
  }
  function callout(tone, iconName, title, body) {
    var b = !body ? null : typeof body === 'string' ? el('p', { text: body }) : Array.isArray(body) ? el('div', { cls: 'callout-body' }, body) : body;
    return el('div', { cls: 'callout tone-' + tone }, [icon(iconName), el('div', { cls: 'callout-main' }, [title ? el('strong', { text: title }) : null, b])]);
  }
  function psection(title, iconName, content) {
    return el('section', { cls: 'p-section' }, [el('h3', { cls: 'p-h' }, [icon(iconName), el('span', { text: title })]), content]);
  }
  function stepsList(steps) {
    var ol = el('ol', { cls: 'steps' });
    steps.forEach(function (s) { ol.appendChild(el('li', null, el('span', { text: s }))); });
    return ol;
  }
  function emptyState(text, iconName, extra) {
    return el('div', { cls: 'empty-state' }, [icon(iconName || 'checkCircle'), el('p', { text: text }), extra || null]);
  }
  function kv(rows) {
    var dl = el('dl', { cls: 'kv' });
    rows.forEach(function (r) {
      if (r[1] === null || r[1] === undefined || r[1] === '') { return; }
      dl.appendChild(el('dt', { text: r[0] }));
      dl.appendChild(el('dd', null, typeof r[1] === 'string' || typeof r[1] === 'number' ? el('span', { cls: 'break', text: String(r[1]) }) : r[1]));
    });
    return dl;
  }
  function sectionHeading(title, sub, extra) {
    return el('div', { cls: 'section-heading' }, [el('div', null, [el('h2', { text: title }), sub ? el('p', { text: sub }) : null]), extra || null]);
  }
  function clickable(node, fn) {
    node.setAttribute('tabindex', '0');
    node.setAttribute('role', 'button');
    node.addEventListener('click', function (ev) { if (ev.target.closest('a, button, input')) { return; } fn(); });
    node.addEventListener('keydown', function (ev) { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target === node) { ev.preventDefault(); fn(); } });
    return node;
  }

  App.ui = {
    icon: icon, sevBadge: sevBadge, verifyBadge: verifyBadge, safetyBadge: safetyBadge, toneBadge: toneBadge,
    pageHead: pageHead, card: card, link: link, button: button, callout: callout, flagChip: flagChip
  };

  // ================================================================== v3: privacy mode (ui-contract-v3 §2)
  // While on (the default), names under personal folders show as "[personal file · .ext]" and
  // "[personal folder]". Generic technical folder names (node_modules, .git, ...) stay readable because
  // they say nothing about the person. The real name appears only after a click in a side panel.
  var PV_KEY = 'bvs.privacy.v1';
  var PERSONAL_ROOT_RE = /^(documents|desktop|downloads|pictures|videos|music|onedrive(?: - .+)?)$/i;
  var PROFILE_MARK_RE = /^(~|%userprofile%|\$env:userprofile|\$home)$/i;
  var PV_TEXT_RE = /((?:[A-Za-z]:)?[\\/]+(?:Users|home)[\\/]+[^\\/\s"'<>|:*?]+[\\/]+|(?:~|%USERPROFILE%|\$env:USERPROFILE|\$HOME)[\\/]+)(Documents|Desktop|Downloads|Pictures|Videos|Music|OneDrive(?: - [^\\/\s"'<>|:*?]+)?)((?:[\\/]+[^\\/\s"'<>|:*?]+)*)/gi;
  var PV_USER_RE = /([\\/](?:Users|home)[\\/]+)(?!<user>)([^\\/\s"'<>|:*?]+)/gi;
  var GENERIC_SEGS = Object.create(null);
  ['node_modules', '.git', '.venv', 'venv', '__pycache__', 'dist', 'build', 'out', 'target', '.next', '.nuxt', '.cache', 'cache',
    'temp', 'tmp', 'bin', 'obj', 'packages', 'vendor', 'logs', '.vs', '.vscode', '.idea', '.github', 'src', 'lib', 'data'].forEach(function (s) { GENERIC_SEGS[s] = true; });
  var pvState = { on: U.storage.get(PV_KEY, 'on') !== 'off', listeners: [] };

  function pvLooksFile(seg) { return /\.[A-Za-z0-9]{1,8}$/.test(seg); }
  function pvExt(seg) { var m = /(\.[A-Za-z0-9]{1,8})$/.exec(seg); return m ? m[1].toLowerCase() : ''; }
  function pvGeneric(seg) { return seg.length < 2 || !!GENERIC_SEGS[seg.toLowerCase()] || PERSONAL_ROOT_RE.test(seg); }
  function pvPlaceholder(seg, isFile) {
    if (!isFile) { return '[personal folder]'; }
    var ext = pvExt(seg);
    return ext ? '[personal file · ' + ext + ']' : '[personal file]';
  }
  function pvAnalyse(p) {
    var s = str(p);
    if (!s || s.length > 4000) { return null; }
    var segs = s.split(/[\\/]+/), root = -1;
    for (var i = 0; i < segs.length && root < 0; i++) {
      var low = segs[i].toLowerCase();
      if ((low === 'users' || low === 'home') && i + 2 < segs.length && PERSONAL_ROOT_RE.test(segs[i + 2])) { root = i + 2; }
      else if (PROFILE_MARK_RE.test(segs[i]) && i + 1 < segs.length && PERSONAL_ROOT_RE.test(segs[i + 1])) { root = i + 1; }
    }
    if (root < 0) { return null; }
    return { segs: segs, root: root, tail: segs.slice(root + 1).filter(Boolean), sep: s.indexOf('\\') >= 0 ? '\\' : '/' };
  }
  function pvParts(info, kind) {
    var out = [];
    info.tail.forEach(function (seg, i) {
      if (pvGeneric(seg)) { return; }
      var last = i === info.tail.length - 1;
      var isFile = last ? (kind ? kind === 'file' : pvLooksFile(seg)) : false;
      out.push({ seg: seg, isFile: isFile, ph: pvPlaceholder(seg, isFile) });
    });
    return out;
  }
  function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  // Replace every personal segment (and a file's stem) inside a display name, via tokens so that a
  // placeholder is never re-matched by a later, shorter segment.
  function pvReplaceIn(text, parts) {
    var s = str(text), tokens = [];
    parts.slice().sort(function (a, b) { return b.seg.length - a.seg.length; }).forEach(function (p) {
      var needles = [p.seg];
      if (p.isFile) { var stem = p.seg.replace(/\.[A-Za-z0-9]{1,8}$/, ''); if (stem.length >= 3 && stem !== p.seg) { needles.push(stem); } }
      needles.forEach(function (n) {
        var re = new RegExp('(^|[^A-Za-z0-9])' + escRe(n) + '(?![A-Za-z0-9])', 'gi');
        s = s.replace(re, function (m, pre) { tokens.push(p.ph); return pre + '\u0001' + (tokens.length - 1) + '\u0001'; });
      });
    });
    return s.replace(/\u0001(\d+)\u0001/g, function (m, i) { return tokens[Number(i)] || ''; });
  }
  function pvRedactPath(p, kind) {
    var info = pvAnalyse(p);
    if (!info) { return pvRedactText(p); }
    var tail = info.tail.map(function (seg, i) {
      if (pvGeneric(seg)) { return seg; }
      var last = i === info.tail.length - 1;
      return pvPlaceholder(seg, last ? (kind ? kind === 'file' : pvLooksFile(seg)) : false);
    });
    return info.segs.slice(0, info.root + 1).join(info.sep) + (tail.length ? info.sep + tail.join(info.sep) : '');
  }
  // Free text: find paths under personal folders and hide the personal part (a safety net; spaces
  // inside a name end the match, so structured fields go through label()/path() instead).
  function pvRedactText(text) {
    var s = str(text);
    if (s.indexOf('\\') < 0 && s.indexOf('/') < 0) { return s; }
    return s.replace(PV_TEXT_RE, function (m, head, root, tail) {
      if (!tail) { return m; }
      var sep = m.indexOf('\\') >= 0 ? '\\' : '/';
      var segs = tail.split(/[\\/]+/).filter(Boolean);
      var trail = '';
      if (segs.length) {
        var lm = /[.,;:)\]]+$/.exec(segs[segs.length - 1]);
        if (lm && lm[0].length < segs[segs.length - 1].length) { trail = lm[0]; segs[segs.length - 1] = segs[segs.length - 1].slice(0, -trail.length); }
      }
      return head + root + sep + segs.map(function (seg, i) { return pvGeneric(seg) ? seg : pvPlaceholder(seg, i === segs.length - 1 && pvLooksFile(seg)); }).join(sep) + trail;
    });
  }
  function pvForAI(value, depth) {
    depth = depth || 0;
    if (typeof value === 'string') { return pvRedactText(value).replace(PV_USER_RE, '$1<user>'); }
    if (!value || typeof value !== 'object' || depth > 6) { return value; }
    if (Array.isArray(value)) { return value.slice(0, 400).map(function (v) { return pvForAI(v, depth + 1); }); }
    var out = {};
    var path = typeof value.path === 'string' ? value.path : null;
    var info = path ? pvAnalyse(path) : null;
    var parts = info ? pvParts(info, value.kind === 'file' ? 'file' : value.kind === 'dir' ? 'folder' : null) : [];
    Object.keys(value).forEach(function (k) {
      var v = value[k];
      if (parts.length && typeof v === 'string' && k !== 'path') { v = pvReplaceIn(v, parts); }
      out[k] = k === 'path' && path ? pvRedactPath(path).replace(PV_USER_RE, '$1<user>') : pvForAI(v, depth + 1);
    });
    return out;
  }

  var privacy = {
    // label(path, name, kind?): the name to display for the thing at `path` ('file' | 'folder' optional).
    label: function (path, name, kind) {
      var nm = name === undefined || name === null ? fileName(path) : str(name);
      if (!pvState.on) { return nm; }
      var info = pvAnalyse(path);
      var parts = info ? pvParts(info, kind) : [];
      return pvRedactText(parts.length ? pvReplaceIn(nm, parts) : nm);
    },
    path: function (p, kind) { return pvState.on ? pvRedactPath(p, kind) : str(p); },
    text: function (s) { return pvState.on ? pvRedactText(s) : str(s); },
    isPersonal: function (p) { var info = pvAnalyse(p); return !!info && pvParts(info).length > 0; },
    hides: function (p) { return pvState.on && privacy.isPersonal(p); },
    forAI: function (value) { return pvForAI(value); },
    toggle: function () { privacy.set(!pvState.on); return pvState.on; },
    set: function (on) {
      on = !!on;
      if (on === pvState.on) { return; }
      pvState.on = on;
      U.storage.set(PV_KEY, on ? 'on' : 'off');
      syncPrivacyButton();
      pvState.listeners.slice().forEach(function (fn) { try { fn(on); } catch (e) { /* ignore */ } });
      try { document.dispatchEvent(new CustomEvent('bvs:privacy', { detail: { on: on } })); } catch (e) { /* ignore */ }
      if (panel.open && panel.spec) { renderPanel(panel.spec); }
      remountCurrent();
    },
    onChange: function (fn) { if (typeof fn === 'function') { pvState.listeners.push(fn); } },
    // A "Show name" box for side panels: the real name and path appear only after the click.
    reveal: function (path, name, kind) {
      if (!privacy.hides(path)) { return null; }
      var box = el('div', { cls: 'pv-reveal', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'privacy-reveal', 'data-bvs-label': 'Name hidden by privacy mode' } });
      function hidden() {
        U.clear(box);
        box.classList.remove('is-shown');
        box.appendChild(el('span', { cls: 'pv-reveal-ico' }, icon('eyeOff')));
        box.appendChild(el('span', { cls: 'pv-reveal-text' }, [el('strong', { text: 'Name hidden' }), el('span', { text: 'Privacy mode hides the names of your personal files and folders.' })]));
        box.appendChild(button('Show name', shown, { cls: 'small', icon: 'eye' }));
      }
      function shown() {
        U.clear(box);
        box.classList.add('is-shown');
        box.appendChild(el('span', { cls: 'pv-reveal-ico' }, icon('eye')));
        box.appendChild(el('span', { cls: 'pv-reveal-text' }, [
          el('strong', { cls: 'break', text: name === undefined || name === null ? fileName(path) : str(name) }),
          el('span', { cls: 'break mono-path', text: str(path) })
        ]));
        box.appendChild(button('Hide again', hidden, { cls: 'small ghost', icon: 'eyeOff' }));
      }
      hidden();
      return box;
    }
  };
  Object.defineProperty(privacy, 'on', { get: function () { return pvState.on; }, enumerable: true });
  App.privacy = privacy;
  function pvKind(it) { return it && it.kind === 'file' ? 'file' : it && (it.kind === 'dir' || it.kind === 'folder') ? 'folder' : null; }
  function pvItemLabel(it) { return it ? privacy.label(it.path, it.label || it.path, pvKind(it)) : ''; }
  function pvItemPath(it) { return it && it.path ? privacy.path(it.path, pvKind(it)) : ''; }

  function syncPrivacyButton() {
    var b = $('bvs-privacy-toggle');
    if (!b) { return; }
    U.clear(b);
    b.appendChild(icon(pvState.on ? 'eyeOff' : 'eye'));
    b.appendChild(el('span', { cls: 'privacy-label', text: pvState.on ? 'Privacy: on' : 'Privacy: off' }));
    b.setAttribute('aria-pressed', String(pvState.on));
    b.classList.toggle('is-on', pvState.on);
    b.title = pvState.on ? 'Privacy mode is on: names of your personal files and folders are hidden. Click to show them.'
      : 'Privacy mode is off: personal file names are visible. Click to hide them.';
  }

  function remountCurrent() {
    if (!S.ready) { return; }
    var cur = S.current, y = window.scrollY || 0;
    if (cur.def && typeof cur.def.unmount === 'function') { try { cur.def.unmount(); } catch (e) { /* ignore */ } }
    S.current = { id: null, def: null, root: null, key: null };
    route();
    try { window.scrollTo(0, y); } catch (e) { /* ignore */ }
  }

  // ================================================================== v3: modal dialog + toast
  var modalStack = [], modalSeq = 0;
  App.modal = function (spec) {
    spec = spec || {};
    var opener = document.activeElement;
    var titleId = 'bvs-modal-title-' + (++modalSeq);
    var backdrop = el('div', { cls: 'bvs-modal-backdrop' });
    var kicker = el('p', { cls: 'bvs-modal-kicker', text: spec.kicker || '', hidden: !spec.kicker });
    var title = el('h2', { cls: 'bvs-modal-title', text: spec.title || '', attrs: { id: titleId, tabindex: '-1' } });
    var closeBtn = spec.dismissible === false ? null : el('button', { cls: 'icon-btn bvs-modal-x', attrs: { type: 'button', 'aria-label': 'Close (Esc)' } }, icon('close'));
    var body = el('div', { cls: 'bvs-modal-body' });
    var foot = el('div', { cls: 'bvs-modal-foot' });
    var box = el('div', {
      cls: 'bvs-modal' + (spec.cls ? ' ' + spec.cls : ''),
      attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, 'data-bvs-type': 'section', 'data-bvs-section': spec.section || 'dialog', 'data-bvs-label': short(spec.title || 'Dialog', 120) }
    }, [
      el('div', { cls: 'bvs-modal-head' }, [spec.icon ? el('span', { cls: 'bvs-modal-ico' }, icon(spec.icon)) : null, el('div', { cls: 'bvs-modal-titles' }, [kicker, title]), closeBtn]),
      body, foot
    ]);
    var entry = { box: box, dismissible: spec.dismissible !== false, closed: false };
    var api = {
      body: body, foot: foot, box: box,
      close: function (reason) {
        if (entry.closed) { return; }
        entry.closed = true;
        modalStack = modalStack.filter(function (m) { return m !== entry; });
        if (backdrop.parentNode) { backdrop.parentNode.removeChild(backdrop); }
        if (box.parentNode) { box.parentNode.removeChild(box); }
        if (!modalStack.length) { document.body.classList.remove('modal-open'); }
        if (opener && document.contains(opener) && typeof opener.focus === 'function') { try { opener.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
        if (typeof spec.onClose === 'function') { try { spec.onClose(reason || 'close'); } catch (e) { if (window.console) { console.error(e); } } }
      },
      setTitle: function (t, k) {
        title.textContent = U.safeText(t || '');
        kicker.textContent = U.safeText(k || '');
        kicker.hidden = !k;
        box.setAttribute('data-bvs-label', short(t || 'Dialog', 120));
      },
      setActions: function (list) {
        U.clear(foot);
        var byId = {};
        arr(list).forEach(function (a) {
          if (!a || !a.label) { return; }
          var b = button(str(a.label), function (ev) { if (typeof a.onClick === 'function') { a.onClick(api, ev); } }, { cls: (a.primary ? 'primary big' : a.cls || 'ghost big'), icon: a.icon });
          if (a.disabled) { b.disabled = true; }
          if (a.id) { byId[a.id] = b; }
          foot.appendChild(b);
        });
        foot.hidden = !foot.firstChild;
        return byId;
      },
      focus: function () {
        var f = box.querySelector('input:not([disabled]), textarea:not([disabled])') || title;
        try { f.focus({ preventScroll: true }); } catch (e) { f.focus(); }
      }
    };
    entry.api = api;
    if (closeBtn) { closeBtn.addEventListener('click', function () { api.close('dismiss'); }); }
    if (spec.dismissible !== false && spec.backdropCloses) { backdrop.addEventListener('click', function () { api.close('dismiss'); }); }
    document.body.appendChild(backdrop);
    document.body.appendChild(box);
    document.body.classList.add('modal-open');
    modalStack.push(entry);
    backdrop.style.zIndex = String(3000 + modalStack.length * 2);
    box.style.zIndex = String(3001 + modalStack.length * 2);
    try { if (typeof spec.render === 'function') { spec.render(body, api); } } catch (err) {
      body.appendChild(callout('bad', 'alert', 'This window could not be shown', str(err && err.message)));
      if (window.console) { console.error(err); }
    }
    api.buttons = api.setActions(spec.actions || []);
    setTimeout(function () { if (!entry.closed) { api.focus(); } }, 30);
    return api;
  };
  // Dialog keys run first (window, capture phase): Esc closes the top dialog, Tab stays inside it, and
  // other keys never reach page shortcuts underneath (for example the scanner's "S" key).
  window.addEventListener('keydown', function (ev) {
    var top = modalStack[modalStack.length - 1];
    if (!top) { return; }
    if (ev.key === 'Escape') {
      ev.preventDefault();
      ev.stopImmediatePropagation();
      if (top.dismissible) { top.api.close('dismiss'); }
      return;
    }
    if (ev.key === 'Tab') {
      var f = Array.prototype.filter.call(top.box.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), textarea, select, [tabindex]:not([tabindex="-1"])'), function (n) { return n.offsetParent !== null; });
      if (f.length) {
        var first = f[0], last = f[f.length - 1];
        if (!top.box.contains(document.activeElement)) { ev.preventDefault(); first.focus(); }
        else if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
        else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
      }
    }
    var t = ev.target, typing = !!(t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)));
    // Keys inside the dialog reach its own fields (Enter in the "I confirm" box); page shortcuts such as the
    // scanner's "S" never fire while a dialog is open.
    if (!top.box.contains(t) || ((ev.key === 's' || ev.key === 'S') && !typing)) { ev.stopPropagation(); }
  }, true);

  var toastHost = null;
  App.toast = function (text, tone, iconName) {
    if (!toastHost) {
      toastHost = el('div', { cls: 'bvs-toasts', attrs: { 'aria-live': 'polite', role: 'status' } });
      document.body.appendChild(toastHost);
    }
    var t = el('div', { cls: 'bvs-toast tone-' + (tone || 'info') }, [icon(iconName || (tone === 'bad' ? 'alert' : tone === 'good' ? 'checkCircle' : 'info')), el('span', { text: text })]);
    toastHost.appendChild(t);
    setTimeout(function () { t.classList.add('is-leaving'); }, 5200);
    setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, 5600);
  };

  // ================================================================== v3: signal bridge (ui-contract-v3 §1)
  // Talks to the local server only: GET /api/session, GET /api/signals, POST /api/signal. Without the
  // live server (file://, an older server, or a 404) every signal button is disabled with a hint.
  var SIGNAL_TYPES = ['run-admin', 'run-github-check', 'rerun-module', 'fix-request', 'delete-request', 'refresh-report'];
  var RERUN_RE = /^(S0[1-9]|S1[0-3]|G[0-2]|H[12])$/;
  var ACTIVE_STATES = { queued: true, 'picked-up': true, 'awaiting-chat-confirmation': true, running: true };
  var SIGNAL_STATES = {
    queued: { label: 'Waiting for Claude…', tone: 'neutral', icon: 'clock', plain: 'Your request is in the queue. Claude picks it up within a few seconds when its listener runs.' },
    'picked-up': { label: 'Claude picked it up', tone: 'info', icon: 'check', plain: 'Claude has your request and is getting ready.' },
    'awaiting-chat-confirmation': { label: 'Waiting for your confirmation in the Claude chat', tone: 'warn', icon: 'hand', plain: 'Your turn: read what Claude wrote in the chat and confirm there if you agree.' },
    running: { label: 'Running', tone: 'info', icon: 'refresh', plain: 'Claude is working on it now.' },
    done: { label: 'Done', tone: 'good', icon: 'checkCircle', plain: 'Finished. Refresh the page to see new results.' },
    error: { label: 'Error', tone: 'bad', icon: 'xCircle', plain: 'Something went wrong. Claude explains it in the chat.' },
    cancelled: { label: 'Cancelled', tone: 'neutral', icon: 'close', plain: 'This request was cancelled. Nothing was changed.' },
    expired: { label: 'Expired', tone: 'neutral', icon: 'clock', plain: 'Not confirmed within 60 minutes, so nothing happened. Send it again if you still want it.' }
  };
  var Bridge = {
    live: null, reason: 'checking', token: null, tokenAt: 0, session: null, signals: [], sent: new Map(),
    sessionTimer: 0, signalTimer: 0, demo: false, lastSignalsAt: 0
  };
  var liveWidgets = [];
  function isHttpPage() { return (location.protocol === 'http:' || location.protocol === 'https:') && typeof fetch === 'function'; }
  function liveWidget(node, update, events) {
    liveWidgets.push({ node: node, update: update, events: events || 'state' });
    try { update(); } catch (e) { if (window.console) { console.error(e); } }
    return node;
  }
  function refreshLive(kind) {
    liveWidgets = liveWidgets.filter(function (w) { return document.contains(w.node); });
    liveWidgets.forEach(function (w) {
      if (w.events !== 'all' && w.events !== kind) { return; }
      try { w.update(); } catch (e) { if (window.console) { console.error(e); } }
    });
  }
  function hasLiveTrackers() {
    liveWidgets = liveWidgets.filter(function (w) { return document.contains(w.node); });
    return liveWidgets.some(function (w) { return w.events === 'signals' || w.events === 'all'; });
  }
  function bridgeHint() {
    if (Bridge.reason === 'file') { return 'Needs the live dashboard (start-dashboard). This copy was opened as a file.'; }
    if (Bridge.reason === 'no-api') { return 'Needs the live dashboard (start-dashboard). This server is an older version without the Claude link: restart start-dashboard.'; }
    if (Bridge.reason === 'no-server') { return 'Needs the live dashboard (start-dashboard). The dashboard server is not answering.'; }
    if (Bridge.reason === 'checking') { return 'Checking the connection to the dashboard server…'; }
    return 'Needs the live dashboard (start-dashboard).';
  }
  function getToken(force) {
    if (!force && Bridge.token && Date.now() - Bridge.tokenAt < 120000) { return Promise.resolve(Bridge.token); }
    return fetch('/api/status', { cache: 'no-store', credentials: 'same-origin' }).then(function (r) {
      if (!r.ok) { return null; }
      return r.json().then(function (j) { Bridge.token = j && typeof j.token === 'string' ? j.token : null; Bridge.tokenAt = Date.now(); return Bridge.token; }, function () { return null; });
    }, function () { return null; });
  }
  function apiCall(method, path, body, retried) {
    if (!isHttpPage()) { return Promise.resolve({ status: 0, data: null, reason: 'file' }); }
    return getToken(retried).then(function (token) {
      var headers = { Accept: 'application/json' };
      if (token) { headers['X-BVS-Token'] = token; }
      var init = { method: method, cache: 'no-store', credentials: 'same-origin', headers: headers };
      if (body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
      return fetch(path, init).then(function (r) {
        return r.json().then(null, function () { return null; }).then(function (data) {
          if (r.status === 403 && !retried) { return apiCall(method, path, body, true); }
          return { status: r.status, data: data };
        });
      }, function () { return { status: 0, data: null, reason: 'no-server' }; });
    });
  }
  function setBridge(live, reason, session) {
    var before = [Bridge.live, Bridge.reason, Bridge.session && Bridge.session.connected].join('|');
    Bridge.live = live;
    Bridge.reason = reason;
    Bridge.session = session || null;
    var after = [Bridge.live, Bridge.reason, Bridge.session && Bridge.session.connected].join('|');
    syncSessionPill();
    if (before !== after) { refreshLive('state'); }
  }
  function pollSession() {
    clearTimeout(Bridge.sessionTimer);
    if (!isHttpPage()) { setBridge(false, 'file', null); return Promise.resolve(); }
    return apiCall('GET', '/api/session').then(function (res) {
      if (res.status === 200 && res.data && typeof res.data === 'object') {
        setBridge(true, res.data.connected ? 'connected' : 'not-listening', res.data);
      } else if (res.status === 404 || res.status === 405) {
        setBridge(false, 'no-api', null);
      } else if (res.status === 0) {
        setBridge(false, 'no-server', null);
      } else {
        setBridge(false, 'no-api', null);
      }
      var wait = Bridge.live ? 10000 : 30000;
      Bridge.sessionTimer = setTimeout(pollSession, document.hidden ? Math.max(wait, 30000) : wait);
    });
  }
  function normSignal(s) {
    if (!s || typeof s !== 'object' || typeof s.id !== 'string') { return null; }
    return {
      id: s.id.slice(0, 120), type: str(s.type).slice(0, 40), state: str(s.state || 'queued').slice(0, 40), message: str(s.message).slice(0, 600),
      createdAt: s.createdAt || s.created || null, updatedAt: s.updatedAt || s.updated || null,
      // K's /api/signals sends a short 'summary' ({module} | {findingId} | {items: n, bytes}), never the full payload.
      payload: s.payload && typeof s.payload === 'object' ? s.payload : s.summary && typeof s.summary === 'object' ? s.summary : null
    };
  }
  function pollSignals() {
    if (Bridge.demo) { refreshLive('signals'); return Promise.resolve(); }
    if (!Bridge.live) { return Promise.resolve(); }
    return apiCall('GET', '/api/signals').then(function (res) {
      if (res.status !== 200 || !res.data) { return; }
      var list = Array.isArray(res.data) ? res.data : Array.isArray(res.data.signals) ? res.data.signals : Array.isArray(res.data.items) ? res.data.items : [];
      Bridge.signals = list.map(normSignal).filter(Boolean).slice(0, 60);
      Bridge.lastSignalsAt = Date.now();
      Bridge.signals.forEach(function (s) {
        var mine = Bridge.sent.get(s.id);
        if (mine) { mine.state = s.state; mine.message = s.message; mine.updatedAt = s.updatedAt; }
      });
      refreshLive('signals');
    });
  }
  function signalLoop() {
    clearInterval(Bridge.signalTimer);
    Bridge.signalTimer = setInterval(function () {
      if (document.hidden || !hasLiveTrackers()) { return; }
      pollSignals();
    }, 4000);
  }
  // All signals the page knows about (server list + the ones this tab just sent), newest first.
  function allSignals() {
    var byId = {}, out = [];
    Bridge.signals.forEach(function (s) { byId[s.id] = true; out.push(s); });
    Bridge.sent.forEach(function (s) { if (!byId[s.id]) { out.push(s); } });
    out.sort(function (a, b) { return String(b.createdAt || '').localeCompare(String(a.createdAt || '')) || String(b.id).localeCompare(String(a.id)); });
    return out;
  }
  function signalKey(type, payload) { payload = payload || {}; return type + '|' + (payload.module || payload.findingId || ''); }
  function activeSignal(type, payload) {
    var key = signalKey(type, payload), now = Date.now();
    return allSignals().filter(function (s) {
      var sp = s.payload || (Bridge.sent.get(s.id) || {}).payload || {};
      var created = U.toDate(s.createdAt);
      return ACTIVE_STATES[s.state] && signalKey(s.type, sp) === key && (!created || now - created.getTime() < 3600000);
    })[0] || null;
  }
  App.bridge = {
    state: function () { return { live: Bridge.live, reason: Bridge.reason, session: Bridge.session }; },
    hint: bridgeHint,
    signals: allSignals,
    refresh: function () { return pollSession().then(pollSignals); },
    // send(type, payload, {typedConfirmation}) -> Promise<{ok, id, state, code?, status, message}>
    send: function (type, payload, extra) {
      if (SIGNAL_TYPES.indexOf(type) < 0) { return Promise.resolve({ ok: false, status: 0, message: 'Unknown request type.' }); }
      if (!Bridge.live) { return Promise.resolve({ ok: false, status: 0, message: bridgeHint() }); }
      var body = { type: type, payload: payload || {} };
      if (extra && typeof extra.typedConfirmation === 'string') { body.typedConfirmation = extra.typedConfirmation; }
      return apiCall('POST', '/api/signal', body).then(function (res) {
        var d = res.data || {};
        if ((res.status === 200 || res.status === 201 || res.status === 202) && typeof d.id === 'string') {
          var rec = { id: d.id, type: type, state: str(d.state || 'queued'), message: '', createdAt: new Date().toISOString(), payload: payload || {} };
          if (type === 'delete-request') { rec.payload = { count: (payload.items || []).length }; }
          Bridge.sent.set(d.id, rec);
          refreshLive('signals');
          setTimeout(pollSignals, 1200);
          return { ok: true, id: d.id, state: rec.state, code: typeof d.code === 'string' ? d.code : null, status: res.status };
        }
        if (res.status === 404 || res.status === 405) { setBridge(false, 'no-api', null); }
        var msg = d.message || (res.status === 0 ? 'The dashboard server did not answer.' : res.status === 429 ? 'Too many requests at once: wait a minute and try again.' : 'The server refused the request (HTTP ' + res.status + ').');
        return { ok: false, status: res.status, message: str(msg).slice(0, 300) };
      });
    }
  };

  function sendSignalUI(type, payload, opts) {
    opts = opts || {};
    return App.bridge.send(type, payload, opts.extra).then(function (res) {
      if (res.ok) {
        App.toast(opts.sentText || 'Sent to Claude. Keep an eye on your Claude chat.', 'good', 'send');
      } else {
        App.toast(res.message || 'Could not send the request.', 'bad');
      }
      return res;
    });
  }

  // Button that sends one signal. Disabled without the live dashboard, and while the same request is still open.
  function signalButton(label, type, payload, opts) {
    opts = opts || {};
    var status = el('span', { cls: 'sig-btn-status', attrs: { 'aria-live': 'polite' } });
    var sending = false;
    var b = button(label, function () {
      if (b.disabled || sending) { return; }
      if (typeof opts.before === 'function' && opts.before() === false) { return; }
      sending = true;
      update();
      sendSignalUI(type, payload, opts).then(function (res) {
        sending = false;
        status.textContent = res.ok ? 'Sent. See "Your requests to Claude".' : res.message || '';
        update();
        if (typeof opts.after === 'function') { opts.after(res); }
      });
    }, { cls: opts.cls || 'primary', icon: opts.icon || 'send', attrs: { 'data-bvs-type': 'tile', 'data-bvs-id': 'signal-' + type + (payload && payload.module ? '-' + payload.module : ''), 'data-bvs-label': label } });
    function update() {
      var act = activeSignal(type, payload);
      var lbl = b.querySelector('span');
      b.disabled = !Bridge.live || sending || !!act;
      if (lbl) { lbl.textContent = sending ? 'Sending…' : act ? (opts.activeLabel || 'Requested: ' + (SIGNAL_STATES[act.state] || SIGNAL_STATES.queued).label) : label; }
      b.title = !Bridge.live ? bridgeHint() : act ? 'Already requested. Progress is shown under "Your requests to Claude".' : (opts.title || '');
    }
    var wrap = el('span', { cls: 'sig-btn-wrap' }, [b, status]);
    liveWidget(wrap, update, 'all');
    return wrap;
  }

  // ================================================================== v3: AI consent (EU AI Act Art. 50 / GDPR consent)
  var CONSENT_KEY = 'bvs.aiConsent.v1';
  var consentState = { pending: null, pageChoice: null, listeners: [] };
  function consentRecord() {
    var r = U.storage.get(CONSENT_KEY, null);
    return r && (r.choice === 'yes' || r.choice === 'no') ? r : null;
  }
  var CONSENT_TEXT = 'INFOSEC sends the question, the text you selected and the related findings to Claude (Anthropic) using your Claude Code login. Personal file names are hidden first. Allow?';
  function openConsentModal(resolve) {
    var done = false;
    function finish(v) { if (done) { return; } done = true; if (typeof resolve === 'function') { resolve(v); } }
    var m = App.modal({
      kicker: 'Before the first AI answer', title: 'Allow AI answers from Claude?', icon: 'infosec', cls: 'consent-modal', section: 'ai-consent',
      render: function (body) {
        body.appendChild(el('p', { cls: 'consent-lead', text: CONSENT_TEXT }));
        var g = el('div', { cls: 'consent-grid' });
        [['send', 'What is sent', 'Your question, the part of the screen you selected and the findings it is about.'],
          ['eyeOff', 'Hidden first', 'Your Windows user name becomes <user> and personal file and folder names become [personal file].'],
          ['lock', 'Never sent', 'Passwords, file contents, browser history and private keys.'],
          ['info', 'Good to know', 'Answers are AI-generated and can be wrong. INFOSEC only explains: it never changes anything on your PC.']
        ].forEach(function (r) { g.appendChild(el('div', { cls: 'consent-item' }, [icon(r[0]), el('div', null, [el('strong', { text: r[1] }), el('p', { text: r[2] })])])); });
        body.appendChild(g);
        body.appendChild(el('p', { cls: 'p-note', text: 'You can change your answer any time on the Privacy & AI page. Choosing offline answers sends nothing: INFOSEC then uses its built-in explanations.' }));
      },
      actions: [
        { label: 'Only offline answers', icon: 'lock', onClick: function (api) { App.aiConsent.set('no'); finish('no'); api.close('chosen'); } },
        { label: 'Allow', primary: true, icon: 'check', onClick: function (api) { App.aiConsent.set('yes'); finish('yes'); api.close('chosen'); } }
      ],
      onClose: function (reason) {
        if (reason === 'chosen') { return; }
        consentState.pageChoice = 'dismissed';
        finish('dismissed');
      }
    });
    return m;
  }
  App.aiConsent = {
    text: CONSENT_TEXT,
    get: function () { var r = consentRecord(); return r ? r.choice : (consentState.pageChoice === 'yes' || consentState.pageChoice === 'no' ? consentState.pageChoice : null); },
    record: consentRecord,
    set: function (choice) {
      if (choice === 'yes' || choice === 'no') {
        var ok = U.storage.set(CONSENT_KEY, { choice: choice, at: new Date().toISOString(), version: 1 });
        consentState.pageChoice = ok ? null : choice;
      } else {
        U.storage.remove(CONSENT_KEY);
        consentState.pageChoice = null;
      }
      consentState.listeners.slice().forEach(function (fn) { try { fn(App.aiConsent.get()); } catch (e) { /* ignore */ } });
      refreshLive('state');
    },
    // request() -> Promise<'yes' | 'no' | 'dismissed'>: asks once (the modal) when nothing is decided yet.
    request: function () {
      var c = App.aiConsent.get();
      if (c) { return Promise.resolve(c); }
      if (consentState.pageChoice === 'dismissed') { return Promise.resolve('dismissed'); }
      if (consentState.pending) { return consentState.pending; }
      consentState.pending = new Promise(function (resolve) { openConsentModal(resolve); }).then(function (v) { consentState.pending = null; return v; });
      return consentState.pending;
    },
    open: function () { return openConsentModal(null); },
    onChange: function (fn) { if (typeof fn === 'function') { consentState.listeners.push(fn); } }
  };

  // ================================================================== data helpers
  function G() { return S.guide || {}; }
  function items(name) { return (S.datasets[name] || {}).items || []; }
  function fact(name, key) {
    var f = ((S.datasets[name] || {}).facts || []).filter(function (x) { return x && x.key === key; })[0];
    return f ? f.value : null;
  }
  function vres(f) { return f && f.verification && f.verification.result ? f.verification.result : 'unverified'; }
  function isActive(f) { return vres(f) !== 'refuted'; }
  function sevRank(s) { var i = SEV_ORDER.indexOf(s); return i < 0 ? 9 : i; }
  function sortFindings(list) {
    return list.slice().sort(function (a, b) {
      return (isActive(b) - isActive(a)) || (sevRank(a.severity) - sevRank(b.severity)) || ((b.score || 0) - (a.score || 0)) || String(a.id).localeCompare(String(b.id));
    });
  }
  function activeCounts() {
    var c = (S.summary.counts || {}).bySeverityActive;
    if (c) { return c; }
    var out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    S.findings.forEach(function (f) { if (isActive(f) && out[f.severity] !== undefined) { out[f.severity]++; } });
    return out;
  }
  function storageSummary() { return fact('storage', 'storageSummary'); }
  function reclaimableBytes(ss) {
    if (!ss || !ss.bySafety) { return 0; }
    return ((ss.bySafety.safe || {}).bytes || 0) + ((ss.bySafety.safe_after_check || {}).bytes || 0);
  }

  function stabilityFacts() {
    var health = items('health'), startup = items('startup');
    function ev(id) { return health.filter(function (it) { return it.category === 'disk-events' && it.x && Number(it.x.eventId) === id; })[0] || null; }
    var bsod = ev(1001), restarts = ev(41), dumpFail = ev(161);
    var crashes = startup.filter(function (it) { return it.list === 'crashes'; });
    var codes = [];
    var m, re = /0x([0-9A-F]+) x(\d+)/gi, txt = bsod ? str(bsod.purpose) : '';
    while ((m = re.exec(txt)) !== null) { codes.push({ code: '0x' + m[1].toUpperCase(), count: Number(m[2]) }); }
    return {
      bsod: bsod, restarts: restarts, dumpFail: dumpFail, crashes: crashes, codes: codes,
      bsodCount: bsod && bsod.x ? Number(bsod.x.count) || 0 : 0,
      restartCount: restarts && restarts.x ? Number(restarts.x.count) || 0 : 0
    };
  }

  // ---- curated content (guide) with graceful fallbacks ----
  function verdictInfo() { return VERDICTS[S.summary.verdict] || VERDICTS.HARDENING_NEEDED; }
  function heroStatus() {
    var st = G().status;
    return STATUS[st] ? st : verdictInfo().status;
  }

  function healthModel() {
    var gh = arr(G().health);
    if (gh.length) {
      return gh.filter(function (a) { return a && a.area; }).map(function (a) {
        var area = str(a.area);
        return { area: area, grade: GRADES[a.grade] ? a.grade : 'ok', text: str(a.text), link: safeHash(a.link, AREA_LINKS[area] || '#/overview') };
      });
    }
    var v = S.summary.verdict, act = activeCounts(), hi = (act.critical || 0) + (act.high || 0);
    var out = [];
    out.push({
      area: 'Security',
      grade: v === 'COMPROMISED' ? 'bad' : v === 'SUSPICIOUS' ? 'attention' : v === 'HARDENING_NEEDED' ? (hi ? 'attention' : 'ok') : 'good',
      text: v === 'COMPROMISED' ? 'Signs of an attack were confirmed.' : v === 'SUSPICIOUS' ? 'Something unusual has not been ruled out yet.' :
        'No signs of hacking.' + (hi ? ' ' + hi + ' important ' + plural(hi, 'thing', 'things') + ' to fix.' : act.medium ? ' ' + act.medium + ' things worth fixing.' : ''),
      link: AREA_LINKS.Security
    });
    var ss = storageSummary();
    if (ss && ss.volume && ss.volume.sizeBytes) {
      var free = ss.volume.freeBytes || 0, size = ss.volume.sizeBytes, pf = free / size, rec = reclaimableBytes(ss);
      out.push({
        area: 'Storage', grade: pf < 0.08 ? 'bad' : pf < 0.15 ? 'attention' : pf < 0.25 ? 'ok' : 'good',
        text: U.fmtBytes(free) + ' free of ' + U.fmtBytes(size) + '.' + (rec ? ' About ' + U.fmtBytes(rec) + ' of junk can be cleaned.' : ''),
        link: AREA_LINKS.Storage
      });
    } else {
      out.push({ area: 'Storage', grade: 'ok', text: 'Storage was not scanned yet.', link: AREA_LINKS.Storage });
    }
    var st = stabilityFacts();
    out.push({
      area: 'Stability', grade: st.bsodCount >= 5 ? 'bad' : st.bsodCount >= 1 ? 'attention' : st.crashes.length ? 'ok' : 'good',
      text: st.bsodCount ? st.bsodCount + ' blue ' + plural(st.bsodCount, 'screen', 'screens') + ' (whole-PC crashes) in the last 90 days.' :
        st.crashes.length ? 'No blue screens. ' + st.crashes.length + ' apps hung or crashed now and then.' : 'No crashes recorded.',
      link: AREA_LINKS.Stability
    });
    var priv = S.findings.filter(function (f) { return isActive(f) && (f.module === 'S12' || f.module === 'S06') && sevRank(f.severity) <= 2; });
    var secrets = S.findings.filter(function (f) { return isActive(f) && (f.reasons || []).some(function (r) { return r === 'plaintext_secret' || r === 'unencrypted_key'; }); }).length;
    var privHigh = priv.some(function (f) { return sevRank(f.severity) <= 1; });
    out.push({
      area: 'Privacy', grade: privHigh ? 'attention' : priv.length ? 'ok' : 'good',
      text: secrets ? secrets + ' passwords, tokens or keys are saved as plain text.' : priv.length ? priv.length + ' privacy items worth a look.' : 'No exposed passwords found.',
      link: AREA_LINKS.Privacy
    });
    var upd = S.findings.filter(function (f) {
      return isActive(f) && f.severity !== 'info' && (f.module === 'S11' || (f.reasons || []).some(function (r) { return r === 'outdated_component' || r === 'vulnerable_dependency'; }));
    });
    out.push({
      area: 'Updates', grade: upd.some(function (f) { return sevRank(f.severity) <= 1; }) ? 'attention' : upd.length ? 'ok' : 'good',
      text: upd.length ? upd.length + ' outdated or vulnerable ' + plural(upd.length, 'component', 'components') + ' found.' : 'No outdated software found by the checks.',
      link: AREA_LINKS.Updates
    });
    return out;
  }

  function verdictPlainModel() {
    var vp = G().verdictPlain || {}, s = S.summary, v = verdictInfo();
    var notChecked = arr(vp.notChecked);
    if (!notChecked.length) {
      var by = (S.coverage || {}).byStatus || {};
      if (by.needs_admin) { notChecked.push(by.needs_admin + ' checks need administrator rights (for example the Windows Security log).'); }
      if (by.needs_consent) { notChecked.push(by.needs_consent + ' checks are waiting for your permission (for example a GitHub login).'); }
      if (by.error) { notChecked.push(by.error + ' checks failed to run.'); }
      if (by.partial) { notChecked.push(by.partial + ' checks could only see part of what they look at.'); }
      arr(s.honestLimits).forEach(function (l) { if (l && l.title) { notChecked.push(str(l.title) + ': no scan from inside Windows can fully rule this out.'); } });
    }
    return {
      summary: str(vp.summary) || v.headline,
      whatItMeans: str(vp.whatItMeans) || str(s.verdictMeaning) || v.plain,
      whyNotCompromised: arr(vp.whyNotCompromised).length ? arr(vp.whyNotCompromised).map(str) : arr(s.verdictReasons).map(str),
      confidenceText: str(vp.confidenceText) || derivedConfidenceText(),
      notChecked: notChecked.map(str)
    };
  }

  function derivedConfidenceText() {
    var c = S.summary.confidence || {}, counts = S.summary.counts || {};
    var hc = counts.highCritical || 0, ver = hc - (counts.highCriticalUnverified || 0);
    var lvl = c.level ? upperFirst(c.level) + ' confidence. ' : '';
    var parts = [];
    if (typeof c.checkCoverage === 'number') { parts.push(Math.round(c.checkCoverage * 100) + '% of the checks that apply to this PC ran fully'); }
    if (hc) { parts.push(ver + ' of the ' + hc + ' important findings were double-checked with a second method'); }
    return lvl + (parts.length ? upperFirst(parts.join(', and ')) + '.' : '') + ' The rest needs administrator rights or your login to check.';
  }

  function fixesModel() {
    var gf = arr(G().topFixes);
    if (gf.length) {
      return gf.map(function (f, i) {
        return {
          id: str(f.id) || 'fix-' + (i + 1), title: str(f.title), plain: str(f.plain), why: str(f.why), effort: str(f.effort),
          priority: typeof f.priority === 'number' ? f.priority : i + 1, steps: arr(f.steps).map(str), related: arr(f.related).map(str),
          link: safeHash(f.link, null), severity: null
        };
      }).sort(function (a, b) { return a.priority - b.priority; });
    }
    var hard = arr(S.summary.hardening).filter(function (h) { var f = App.findingById(h.id); return !f || isActive(f); });
    hard.sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity); });
    return hard.filter(function (h) { return sevRank(h.severity) <= 2; }).slice(0, 8).map(function (h, i) {
      var sm = SEV[h.severity] || SEV.info;
      return {
        id: 'fix-' + h.id, title: str(h.title), plain: firstSentence(h.recommendation), why: 'Rated "' + sm.label + '": ' + sm.plain + '.',
        effort: '', priority: i + 1, steps: splitSteps(h.recommendation), related: [str(h.id)], link: '#/finding/' + encodeURIComponent(h.id), severity: h.severity
      };
    });
  }

  function questionsModel() {
    var gq = arr(G().questions);
    if (gq.length) {
      return gq.map(function (q, i) {
        return {
          id: str(q.id) || 'q-' + (i + 1), question: str(q.question), plain: str(q.plain), found: arr(q.found).map(str),
          whyItMatters: str(q.whyItMatters), ifYes: str(q.ifYes), ifNo: str(q.ifNo), related: arr(q.related).map(str), link: safeHash(q.link, null)
        };
      });
    }
    return arr(S.summary.questions).map(function (q) {
      var f = App.findingById(q.id);
      var reasons = f ? (f.reasons || []).map(reasonText) : [];
      return {
        id: 'q-' + q.id, question: 'Do you recognise this, and is it expected on your PC?', plain: str(q.title),
        found: [str(q.title) + ' (' + moduleName(q.module) + ')'].concat(reasons.length ? ['Flagged because ' + reasons.join('; ') + '.'] : []),
        whyItMatters: /without a confirmed or refuted/.test(str(q.why)) ? 'It is rated "' + (SEV[q.severity] || SEV.info).label + '", and nobody could confirm or rule it out automatically. Only you know whether it is yours.' : str(q.why),
        ifYes: q.fp_notes ? 'Then it is probably a normal setup. ' + str(q.fp_notes) : 'Then it is probably fine.',
        ifNo: q.recommendation ? 'Then treat it as a problem: ' + str(q.recommendation) : 'Ask INFOSEC or Claude what to do next.',
        related: [str(q.id)], link: '#/finding/' + encodeURIComponent(q.id)
      };
    });
  }

  function fileVerdict(file) {
    if (file.verification === 'refuted') { return { key: 'false_alarm', label: 'Checked: false alarm', tone: 'good', icon: 'checkCircle', plain: 'A second check showed this file is fine. Nothing to do.' }; }
    if (file.verification === 'confirmed') { return { key: 'fix', label: 'Checked: real problem', tone: 'bad', icon: 'alert', plain: 'A second check confirmed the problem. Follow the steps below.' }; }
    var classes = (file.findings || []).map(function (id) { var f = App.findingById(id); return f ? f['class'] : null; });
    if (classes.indexOf('hardening') >= 0 || classes.indexOf('compromise') >= 0 || sevRank(file.severity) <= 1) {
      return { key: 'fix', label: 'Needs a fix', tone: 'warn', icon: 'fix', plain: 'Not malware, but something about this file should be fixed. See the steps below.' };
    }
    return { key: 'unknown', label: 'Not double-checked', tone: 'neutral', icon: 'question', plain: 'Probably fine, but nobody double-checked it. Make sure you recognise it.' };
  }
  function fileName(p) { var s = str(p); var i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/')); return i >= 0 ? s.slice(i + 1) : s; }
  function fileFolder(p) { var s = str(p); var i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/')); return i >= 0 ? s.slice(0, i) : ''; }

  // ---- answers to questions (this browser only) ----
  function answersKey() { return 'bvs.answers.v1.' + (S.dirId || 'scan'); }
  function getAnswers() { var a = U.storage.get(answersKey(), {}); return a && typeof a === 'object' ? a : {}; }
  function setAnswer(qid, value) {
    var a = getAnswers();
    if (value) { a[qid] = value; } else { delete a[qid]; }
    U.storage.set(answersKey(), a);
    updateBadges();
  }
  var ANSWERS = { yes: "Yes, it's mine", no: 'No', unsure: 'Not sure' };

  // ================================================================== theme + sidebar
  function initTheme() {
    var btn = $('theme-toggle');
    if (!btn) { return; }
    var modes = ['auto', 'light', 'dark'];
    var names = { auto: 'Auto', light: 'Light', dark: 'Dark' };
    var icons = { auto: 'auto', light: 'sun', dark: 'moon' };
    var cur = U.storage.get('bvs.theme', 'auto');
    if (modes.indexOf(cur) < 0) { cur = 'auto'; }
    function apply(m) {
      if (m === 'auto') { document.documentElement.removeAttribute('data-theme'); } else { document.documentElement.setAttribute('data-theme', m); }
      U.clear(btn);
      btn.appendChild(icon(icons[m]));
      btn.appendChild(el('span', { cls: 'theme-label', text: names[m] }));
      btn.title = 'Theme: ' + names[m] + ' (click to change)';
      btn.setAttribute('aria-label', 'Theme: ' + names[m] + '. Click to change.');
    }
    apply(cur);
    btn.addEventListener('click', function () {
      cur = modes[(modes.indexOf(cur) + 1) % modes.length];
      U.storage.set('bvs.theme', cur);
      apply(cur);
    });
  }

  function initSidebar() {
    var root = document.documentElement;
    var collapse = $('bvs-collapse'), menu = $('bvs-menu'), scrim = $('bvs-scrim');
    if (U.storage.get('bvs.sidebar', 'expanded') === 'collapsed') { root.classList.add('side-collapsed'); }
    function syncCollapse() {
      if (!collapse) { return; }
      var c = root.classList.contains('side-collapsed');
      U.clear(collapse);
      collapse.appendChild(icon(c ? 'chevron' : 'chevronLeft'));
      collapse.appendChild(el('span', { cls: 'nav-label', text: c ? 'Expand menu' : 'Collapse menu' }));
      collapse.setAttribute('aria-expanded', String(!c));
      collapse.title = c ? 'Expand menu' : 'Collapse menu';
    }
    syncCollapse();
    if (collapse) {
      collapse.addEventListener('click', function () {
        root.classList.toggle('side-collapsed');
        U.storage.set('bvs.sidebar', root.classList.contains('side-collapsed') ? 'collapsed' : 'expanded');
        syncCollapse();
      });
    }
    function setMobile(open) {
      document.body.classList.toggle('side-open', open);
      if (menu) { menu.setAttribute('aria-expanded', String(open)); }
      if (scrim) { scrim.hidden = !open; }
    }
    if (menu) {
      menu.appendChild(icon('menu'));
      menu.addEventListener('click', function () { setMobile(!document.body.classList.contains('side-open')); });
    }
    if (scrim) { scrim.addEventListener('click', function () { setMobile(false); }); }
    $('bvs-nav').addEventListener('click', function (ev) { if (ev.target.closest('a')) { setMobile(false); } });
    App._closeMobileNav = function () { setMobile(false); };
  }

  // ================================================================== navigation (sidebar)
  // 'agents' is the slot for agent M's Agent map (agents-view.js); 'privacy' is the Privacy & AI page.
  var NAV_ORDER = ['overview', 'security', 'questions', 'storage', 'performance', 'health', 'basket', 'infosec', 'agents', 'privacy'];

  function viewDef(id) { return views[id] || PLACEHOLDERS[id] || null; }

  function renderNav() {
    var nav = $('bvs-nav');
    if (!nav) { return; }
    U.clear(nav);
    var ids = NAV_ORDER.slice();
    Object.keys(views).sort(function (a, b) { return viewOrder[a] - viewOrder[b]; }).forEach(function (id) {
      if (ids.indexOf(id) < 0 && views[id].nav !== false && !views[id].parent) { ids.push(id); }
    });
    var groups = { main: [], tools: [] };
    ids.forEach(function (id) {
      var def = viewDef(id);
      if (!def || def.nav === false) { return; }
      groups[def.group === 'tools' ? 'tools' : 'main'].push({ id: id, def: def });
    });
    ['main', 'tools'].forEach(function (g) {
      if (!groups[g].length) { return; }
      if (g === 'tools') { nav.appendChild(el('div', { cls: 'nav-group', text: 'Tools' })); }
      var ul = el('ul', { cls: 'nav-list', attrs: { role: 'list' } });
      groups[g].forEach(function (entry) {
        var def = entry.def, id = entry.id, title = str(def.title) || humanize(id);
        var a = link('#/' + id, {
          cls: 'nav-item nav-' + id + (def.placeholder ? ' is-placeholder' : ''), title: title,
          attrs: bvs('section', id, title, { 'data-view': id })
        }, [
          el('span', { cls: 'nav-ico' }, icon(def.icon || 'dot')),
          el('span', { cls: 'nav-label', text: title }),
          el('span', { cls: 'nav-badge', hidden: true, attrs: { 'data-badge': id } })
        ]);
        var accent = typeof def.accent === 'string' && COLOR_RE.test(def.accent) ? def.accent : null;
        if (accent) { a.style.setProperty('--nav-accent', accent); }
        ul.appendChild(el('li', null, a));
      });
      nav.appendChild(ul);
    });
    updateNavActive();
    updateBadges();
  }

  function updateNavActive() {
    var cur = S.current.id, def = viewDef(cur);
    var navId = def && def.parent ? def.parent : cur;
    Array.prototype.forEach.call(document.querySelectorAll('#bvs-nav .nav-item'), function (a) {
      if (a.getAttribute('data-view') === navId) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); }
    });
  }

  function setBadge(id, value, tone) {
    var b = document.querySelector('#bvs-nav [data-badge="' + id + '"]');
    if (!b) { return; }
    b.hidden = !value;
    b.textContent = value ? String(value) : '';
    b.className = 'nav-badge' + (tone ? ' tone-' + tone : '');
  }

  function updateBadges() {
    if (!S.ready) { return; }
    var act = activeCounts();
    var hi = (act.critical || 0) + (act.high || 0);
    setBadge('security', hi, act.critical ? 'bad' : 'warn');
    var qs = questionsModel(), ans = getAnswers();
    var open = qs.filter(function (q) { return !ans[q.id]; }).length;
    setBadge('questions', open, 'info');
    setBadge('basket', S.basket ? S.basket.count() : 0, 'neutral');
    var st = stabilityFacts();
    setBadge('health', st.bsodCount ? '!' : 0, 'warn');
  }

  // ================================================================== side panel (drawer)
  var panel = { open: false, spec: null, stack: [], routeBound: false, opener: null, hideTimer: 0 };
  var KIND_LABEL = { finding: 'Security finding', storageItem: 'Item details', file: 'Suspicious file', question: 'Question for you', fix: 'How to fix it', text: 'Explanation', custom: 'Details' };
  var KIND_TYPE = { finding: 'finding', storageItem: 'storageItem', file: 'file', question: 'question', fix: 'fix', text: 'section', custom: 'section' };

  function P() {
    return {
      root: $('bvs-panel'), backdrop: $('bvs-panel-backdrop'), kicker: $('bvs-panel-kicker'), title: $('bvs-panel-title'),
      sub: $('bvs-panel-subtitle'), body: $('bvs-panel-body'), actions: $('bvs-panel-actions'), close: $('bvs-panel-close'), back: $('bvs-panel-back')
    };
  }
  function reducedMotion() { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }

  App.openPanel = function (spec, opts) {
    spec = spec || {};
    opts = opts || {};
    var p = P();
    if (!p.root) { return null; }
    if (panel.open && opts.push) { panel.stack.push({ spec: panel.spec, routeBound: panel.routeBound }); }
    else if (!panel.open || !opts.keepStack) { panel.stack = []; }
    if (!panel.open) { panel.opener = document.activeElement; }
    panel.spec = spec;
    panel.routeBound = !!opts.routeBound;
    renderPanel(spec);
    clearTimeout(panel.hideTimer);
    if (!panel.open) {
      panel.open = true;
      p.root.hidden = false;
      p.backdrop.hidden = false;
      void p.root.offsetWidth;
      p.root.classList.add('open');
      p.backdrop.classList.add('open');
      document.body.classList.add('panel-open');
    }
    p.body.scrollTop = 0;
    try { p.title.focus({ preventScroll: true }); } catch (e) { p.title.focus(); }
    markOpenEntity(spec);
    return p.body;
  };

  App.closePanel = function (opts) {
    opts = opts || {};
    if (!panel.open) { return; }
    var p = P(), wasRoute = panel.routeBound;
    panel.open = false;
    panel.routeBound = false;
    panel.stack = [];
    panel.spec = null;
    p.root.classList.remove('open');
    p.backdrop.classList.remove('open');
    document.body.classList.remove('panel-open');
    panel.hideTimer = setTimeout(function () {
      if (!panel.open) { p.root.hidden = true; p.backdrop.hidden = true; U.clear(p.body); U.clear(p.actions); }
    }, reducedMotion() ? 0 : 240);
    markOpenEntity(null);
    var opener = panel.opener;
    panel.opener = null;
    if (opener && document.contains(opener) && typeof opener.focus === 'function') { try { opener.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
    if (wasRoute && opts.navigate !== false && /^#\/finding\//.test(window.location.hash)) {
      App.navigate('#/security' + (S.lastSecurityQS ? '?' + S.lastSecurityQS : ''), { replace: true });
    }
  };

  function markOpenEntity(spec) {
    Array.prototype.forEach.call(document.querySelectorAll('#bvs-view .is-open'), function (n) { n.classList.remove('is-open'); });
    if (!spec || !spec.id) { return; }
    var type = KIND_TYPE[spec.kind] || 'section';
    Array.prototype.forEach.call(document.querySelectorAll('#bvs-view [data-bvs-type="' + type + '"]'), function (n) {
      if (n.getAttribute('data-bvs-id') === String(spec.id)) { n.classList.add('is-open'); }
    });
  }

  function panelBack() {
    var prev = panel.stack.pop();
    if (!prev) { return; }
    panel.spec = prev.spec;
    panel.routeBound = prev.routeBound;
    renderPanel(prev.spec);
    markOpenEntity(prev.spec);
  }

  function renderPanel(spec) {
    var p = P();
    var kind = KIND_LABEL[spec.kind] ? spec.kind : (typeof spec.render === 'function' ? 'custom' : 'text');
    U.clear(p.body);
    U.clear(p.actions);
    // Privacy mode: an item with a path under a personal folder gets a hidden title + a "Show name" box.
    var pvPathOf = spec.item && typeof spec.item.path === 'string' ? spec.item.path : null;
    var shownTitle = pvPathOf ? privacy.label(pvPathOf, spec.title || 'Details', pvKind(spec.item)) : privacy.text(spec.title || 'Details');
    var shownSub = spec.subtitle ? (pvPathOf && spec.subtitle === pvPathOf ? privacy.path(spec.subtitle, pvKind(spec.item)) : privacy.text(spec.subtitle)) : '';
    if (pvPathOf && privacy.hides(pvPathOf) && spec.subtitle && spec.subtitle !== pvPathOf) { shownSub = privacy.label(pvPathOf, spec.subtitle, pvKind(spec.item)); }
    p.kicker.textContent = U.safeText(spec.kicker || KIND_LABEL[kind]);
    p.title.textContent = U.safeText(shownTitle);
    p.sub.textContent = U.safeText(shownSub);
    p.sub.hidden = !shownSub;
    p.root.setAttribute('data-bvs-type', KIND_TYPE[kind] || 'section');
    if (spec.id) { p.root.setAttribute('data-bvs-id', String(spec.id)); } else { p.root.removeAttribute('data-bvs-id'); }
    p.root.setAttribute('data-bvs-label', short(shownTitle, 120));
    p.root.setAttribute('data-bvs-section', 'panel');
    p.back.hidden = !panel.stack.length;
    if (pvPathOf) {
      var rv = privacy.reveal(pvPathOf, spec.item.label || fileName(pvPathOf), pvKind(spec.item));
      if (rv) { p.body.appendChild(rv); }
    }
    var item = null;
    try {
      if (typeof spec.render === 'function') {
        spec.render(p.body);
      } else if (kind === 'finding') {
        item = spec.item || App.findingById(spec.id);
        if (item) { renderFindingPanel(p.body, item); } else { p.body.appendChild(emptyState('This finding is not in this scan.', 'info')); }
      } else if (kind === 'storageItem') {
        item = spec.item || App.itemById(spec.id);
        if (item) { renderItemPanel(p.body, item); } else { p.body.appendChild(emptyState('This item is not in this scan.', 'info')); }
      } else if (kind === 'file') {
        renderFilePanel(p.body, spec.item || {});
      } else if (kind === 'question') {
        renderQuestionPanel(p.body, spec.item || {});
      } else if (kind === 'fix') {
        renderFixPanel(p.body, spec.item || {});
      } else {
        arr(Array.isArray(spec.text) ? spec.text : [spec.text]).forEach(function (t) { p.body.appendChild(el('p', { cls: 'p-text', text: t })); });
      }
    } catch (err) {
      p.body.appendChild(callout('bad', 'alert', 'This panel could not be shown', str(err && err.message)));
      if (window.console) { console.error(err); }
    }
    // actions: custom ones, then automatic ones
    arr(spec.actions).forEach(function (a) {
      if (!a || !a.label || typeof a.onClick !== 'function') { return; }
      p.actions.appendChild(button(str(a.label), function (ev) { a.onClick(ev); }, { cls: a.primary ? 'primary' : '' }));
    });
    if (kind === 'finding' && item && isActive(item)) {
      p.actions.appendChild(fixRequestButton(item));
    }
    if (kind === 'storageItem' || (spec.item && S.basket && S.basket.canAdd(spec.item) && spec.kind === 'storageItem')) {
      var it = item || spec.item;
      if (it && S.basket && S.basket.canAdd(it)) {
        var inB = S.basket.has(it.id);
        p.actions.appendChild(button(inB ? 'Remove from basket' : 'Add to basket', function () { S.basket.toggle(it); renderPanel(spec); }, { cls: inB ? '' : 'primary', icon: 'basket' }));
      }
    }
    p.actions.appendChild(button('Ask INFOSEC about this', function () { askInfosecAbout(spec, item); }, { cls: 'infosec-btn', icon: 'infosec' }));
    p.actions.appendChild(button('Close', function () { App.closePanel(); }, { cls: 'ghost' }));
  }

  // "Ask Claude to fix this" -> signal fix-request. Claude explains the fix in the chat and asks first.
  function fixRequestButton(f) {
    return signalButton('Ask Claude to fix this', 'fix-request', { findingId: str(f.id) }, {
      icon: 'fix', cls: 'fix-claude-btn', activeLabel: 'Fix requested',
      title: 'Claude explains the fix in your chat and asks before changing anything.',
      sentText: 'Sent. Claude explains the fix in your chat and asks before changing anything.'
    });
  }
  function fixRequestBox(f) {
    var box = el('div', { cls: 'fix-claude-box' }, [
      el('p', { cls: 'p-text' }, [el('strong', { text: 'Want Claude to do it? ' }), el('span', { text: 'Press "Ask Claude to fix this" below. Claude explains the fix in your chat and asks before changing anything.' })]),
      signalTracker({ filter: function (s) { var pl = s.payload || (Bridge.sent.get(s.id) || {}).payload || {}; return s.type === 'fix-request' && pl.findingId === f.id; }, limit: 2, empty: 'No fix requested for this finding yet.' })
    ]);
    return box;
  }

  function contextFor(spec, item) {
    var ctx0 = contextForRaw(spec, item);
    // AI context never carries personal names or the Windows user name (ui-contract-v3 §4), whatever the toggle says.
    try { return privacy.forAI(ctx0); } catch (e) { return ctx0; }
  }
  function contextForRaw(spec, item) {
    var kind = spec.kind || 'text';
    var it = item || spec.item || null;
    var ctx = { kind: kind, id: spec.id || (it && it.id) || null, title: str(spec.title), scanId: S.scanId };
    if (kind === 'finding' && it) {
      ctx.data = {
        id: it.id, title: it.title, severity: it.severity, severityLabel: (SEV[it.severity] || SEV.info).label, class: it['class'],
        area: moduleName(it.module), reasons: (it.reasons || []).map(reasonText), recommendation: it.recommendation, fp_notes: it.fp_notes,
        verification: it.verification ? { result: it.verification.result, notes: it.verification.notes, method: it.verification.method } : null
      };
    } else if (kind === 'storageItem' && it) {
      ctx.data = { id: it.id, label: it.label, path: it.path, bytes: it.bytes, size: U.fmtBytes(it.bytes), category: it.category, purpose: it.purpose, safety: it.safety, how: it.how, flags: it.flags };
    } else if (it) {
      try { ctx.data = JSON.parse(JSON.stringify(it)); } catch (e) { ctx.data = null; }
    } else {
      var b = $('bvs-panel-body');
      ctx.text = b ? b.textContent.slice(0, 3000) : '';
    }
    return ctx;
  }

  function askInfosecAbout(spec, item) {
    var ctx = contextFor(spec, item);
    var prefill = 'Explain this in simple words: "' + short(spec.title || 'this', 160) + '". Is it dangerous, and what exactly should I do?';
    App.closePanel();
    try { App.openInfosec({ prefill: prefill, context: ctx }); } catch (e) { App.pendingInfosec = { prefill: prefill, context: ctx }; App.navigate('#/infosec'); }
  }

  function offlineAnswer(question, context) {
    var d = context && context.data;
    if (context && context.kind === 'finding' && d) {
      return 'Offline explanation (INFOSEC is not connected). "' + d.title + '" is rated ' + d.severityLabel + '. ' +
        (d.fp_notes ? 'Why it might be harmless: ' + d.fp_notes + ' ' : '') + (d.recommendation ? 'What to do: ' + d.recommendation : '');
    }
    if (context && context.kind === 'storageItem' && d) {
      return 'Offline explanation (INFOSEC is not connected). ' + (d.purpose || d.label) + ' Safety: ' + App.friendly.safety(d.safety).label + '. ' + (d.how || '');
    }
    return 'INFOSEC is not connected in this copy of the dashboard, so it cannot answer questions. Open the item\'s side panel for the plain-English explanation, or paste your question into Claude Code.';
  }

  function relatedFindingButton(id) {
    var f = App.findingById(id);
    var label = f ? privacy.text(f.title) : id;
    return el('button', {
      cls: 'rel-item', attrs: bvs('finding', id, label, { type: 'button' }),
      on: { click: function () { openFindingPanel(id, { push: panel.open }); } }
    }, [f ? sevBadge(f.severity) : el('span', { cls: 'mono', text: id }), el('span', { cls: 'rel-title', text: short(label, 110) }), icon('chevron')]);
  }

  function openFindingPanel(id, opts) {
    opts = opts || {};
    var f = App.findingById(id);
    var sm = f ? (SEV[f.severity] || SEV.info) : null;
    return App.openPanel({
      kind: 'finding', id: id, item: f, title: f ? f.title : 'Finding ' + id,
      subtitle: f ? sm.label + ' (' + sm.tech + ') · ' + moduleName(f.module) + ' · ' + f.id : null,
      actions: S.current.id !== 'security' ? [{ label: 'Show in the security list', onClick: function () { App.closePanel({ navigate: false }); App.navigate('#/finding/' + encodeURIComponent(id)); } }] : null
    }, opts);
  }
  function openItemPanel(it, opts) {
    if (!it) { return; }
    App.openPanel({ kind: 'storageItem', id: it.id, item: it, title: it.label || it.path || it.id, subtitle: it.path && it.path !== it.label ? it.path : null }, opts);
  }
  function openFixPanel(fix, opts) { App.openPanel({ kind: 'fix', id: fix.id, item: fix, title: fix.title, subtitle: fix.effort ? 'Takes about ' + fix.effort : null }, opts); }
  function openQuestionPanel(q, opts) { App.openPanel({ kind: 'question', id: q.id, item: q, title: q.question, subtitle: q.plain }, opts); }
  function openFilePanel(file, opts) { App.openPanel({ kind: 'file', id: file.path, item: file, title: fileName(file.path), subtitle: fileFolder(file.path) }, opts); }
  function openWhyPanel() {
    var vp = verdictPlainModel();
    App.openPanel({
      kind: 'text', id: 'why-verdict', title: 'Why this verdict', subtitle: verdictInfo().label,
      render: function (body) {
        body.appendChild(callout(STATUS[heroStatus()].tone, STATUS[heroStatus()].icon, vp.summary, vp.whatItMeans));
        if (vp.whyNotCompromised.length) {
          var ul = el('ul', { cls: 'tick-list' });
          vp.whyNotCompromised.forEach(function (t) { ul.appendChild(el('li', null, [icon('check'), el('span', { text: t })])); });
          body.appendChild(psection('Why we reached this verdict', 'checkCircle', ul));
        }
        body.appendChild(psection('How sure we are', 'info', el('p', { cls: 'p-text', text: vp.confidenceText })));
        body.appendChild(psection('How we decide', 'list', rubricLadder(true)));
        body.appendChild(el('p', { cls: 'p-more' }, [goLink('#/why', 'Open the full explanation, with every finding behind it')]));
      }
    });
  }

  // ---- panel bodies ----
  function renderFindingPanel(body, f) {
    var v = vres(f), cls = CLASSES[f['class']] || CLASSES.info, sm = SEV[f.severity] || SEV.info;
    body.appendChild(el('div', { cls: 'chip-row' }, [sevBadge(f.severity), verifyBadge(v), toneBadge(cls.label, 'neutral'),
      toneBadge(moduleName(f.module), 'neutral', MODULE_ICONS[f.module] || 'dot')]));
    var rec = f.verification || {};
    if (v === 'refuted') {
      body.appendChild(callout('good', 'checkCircle', 'Checked: false alarm', 'A second check showed this is not a real problem, so it does not count toward the verdict.' + (rec.notes ? ' ' + rec.notes + '.' : '')));
    } else if (v === 'confirmed') {
      body.appendChild(callout('bad', 'alert', 'Checked: this is real', rec.notes || 'A second check confirmed it.'));
    } else if (f.explained) {
      body.appendChild(callout('good', 'checkCircle', 'Matches something normal', 'It matches a known, expected item' + (f.explainedBy ? ' (' + f.explainedBy + ')' : '') + '.'));
    }
    var meaning = el('div', null, [
      el('p', { cls: 'p-text' }, [el('strong', { text: 'What we found: ' }), el('span', { text: privacy.text(f.title) })]),
      el('p', { cls: 'p-text', text: 'In short: this is ' + lowerFirst(cls.plain) + '. We rated it "' + sm.label + '" (' + sm.plain + ').' })
    ]);
    if ((f.reasons || []).length) {
      meaning.appendChild(el('p', { cls: 'p-text', text: 'Why it was flagged: ' + f.reasons.map(reasonText).join('; ') + '.' }));
    }
    if (f.needsUserConfirmation) { meaning.appendChild(el('p', { cls: 'p-text', text: 'Only you can confirm whether this is yours.' })); }
    body.appendChild(psection('What this means', 'info', meaning));
    if (f.fp_notes) { body.appendChild(psection('Why it might be harmless', 'checkCircle', el('p', { cls: 'p-text', text: f.fp_notes }))); }
    var steps = splitSteps(f.recommendation);
    if (steps.length) {
      body.appendChild(psection('What to do', 'fix', el('div', null, [stepsList(steps.map(privacy.text)),
        el('p', { cls: 'p-note', text: 'This dashboard never changes anything by itself. These are steps for you, or for Claude with your OK.' })])));
    }
    if (isActive(f)) { body.appendChild(psection('Let Claude help', 'send', fixRequestBox(f))); }
    var recs = f.verifications || (f.verification ? [f.verification] : []);
    var vbox = el('div', { cls: 'verify-box' });
    if (recs.length) {
      recs.forEach(function (r) {
        vbox.appendChild(el('div', { cls: 'verify-rec' }, [verifyBadge(r.result),
          r.notes ? el('p', { cls: 'p-text', text: r.notes }) : null,
          r.method ? el('p', { cls: 'p-note', text: 'How it was checked: ' + r.method }) : null,
          el('p', { cls: 'p-note', text: [r.by ? 'By ' + r.by : '', r.at ? fmtWhen(r.at) : ''].filter(Boolean).join(' · ') })]));
      });
    } else {
      vbox.appendChild(el('p', { cls: 'p-text', text: VERIFY.unverified.plain + (sevRank(f.severity) <= 1 ? ' Important items normally get a second check; this one could not be checked automatically.' : ' Only important items get a second check.') }));
    }
    body.appendChild(psection('Double-check result', 'shieldCheck', vbox));
    // related entities
    var relFiles = arr(S.summary.suspiciousFiles).filter(function (sf) { return (sf.findings || []).indexOf(f.id) >= 0; });
    var relQs = questionsModel().filter(function (q) { return q.related.indexOf(f.id) >= 0; });
    var relFixes = fixesModel().filter(function (x) { return x.related.indexOf(f.id) >= 0; });
    if (relFiles.length || relQs.length || relFixes.length) {
      var rel = el('div', { cls: 'rel-list' });
      relFixes.forEach(function (x) { rel.appendChild(el('button', { cls: 'rel-item', attrs: bvs('fix', x.id, x.title, { type: 'button' }), on: { click: function () { openFixPanel(x, { push: true }); } } }, [toneBadge('Fix', 'info', 'fix'), el('span', { cls: 'rel-title', text: x.title }), icon('chevron')])); });
      relQs.forEach(function (q) { rel.appendChild(el('button', { cls: 'rel-item', attrs: bvs('question', q.id, q.question, { type: 'button' }), on: { click: function () { openQuestionPanel(q, { push: true }); } } }, [toneBadge('Question', 'info', 'question'), el('span', { cls: 'rel-title', text: q.question }), icon('chevron')])); });
      relFiles.slice(0, 12).forEach(function (sf) { rel.appendChild(el('button', { cls: 'rel-item', attrs: bvs('file', sf.path, privacy.label(sf.path, fileName(sf.path), 'file'), { type: 'button' }), on: { click: function () { openFilePanel(sf, { push: true }); } } }, [toneBadge('File', 'neutral', 'file'), el('span', { cls: 'rel-title break', text: privacy.path(sf.path, 'file') }), icon('chevron')])); });
      body.appendChild(psection('Related', 'link', rel));
    }
    // technical details
    var tech = el('details', { cls: 'tech' });
    tech.appendChild(el('summary', null, [icon('code'), el('span', { text: 'Technical details (for experts)' })]));
    var tb = el('div', { cls: 'tech-body' });
    tb.appendChild(kv([
      ['Finding ID', f.id], ['Check', f.check], ['Area', moduleName(f.module) + ' (' + f.module + ')'], ['Class', f['class']],
      ['Severity', sm.tech], ['Confidence', f.confidence], ['Score', f.score !== undefined ? f.score + ' (' + f.scoreSeverity + ' band)' : null],
      ['Reason codes', (f.reasons || []).join(', ')], ['MITRE ATT&CK', (f.mitre || []).join(', ')], ['Collected', f.collected_at ? fmtWhen(f.collected_at) : null], ['Source file', f.source]
    ]));
    (f.evidence || []).forEach(function (e, i) { tb.appendChild(el('div', { cls: 'evidence' }, [el('div', { cls: 'ev-h', text: 'Evidence ' + (i + 1) }), U.renderValue(pvDeep(e))])); });
    var ents = f.entities || {};
    if (Object.keys(ents).some(function (k) { return Array.isArray(ents[k]) ? ents[k].length : ents[k]; })) {
      tb.appendChild(el('div', { cls: 'evidence' }, [el('div', { cls: 'ev-h', text: 'Entities' }), U.renderValue(pvDeep(ents))]));
    }
    if (privacy.on) { tb.appendChild(el('p', { cls: 'p-note', text: 'Privacy mode hides personal file names in these details. Switch it off in the top bar to see them.' })); }
    if (f.expected) { tb.appendChild(el('div', { cls: 'evidence' }, [el('div', { cls: 'ev-h', text: 'Known-good match' }), U.renderValue(f.expected)])); }
    tech.appendChild(tb);
    body.appendChild(tech);
  }

  // Privacy mode for nested data (evidence, entities): every string goes through privacy.text().
  function pvDeep(v, depth) {
    depth = depth || 0;
    if (!privacy.on) { return v; }
    if (typeof v === 'string') { return privacy.text(v); }
    if (!v || typeof v !== 'object' || depth > 5) { return v; }
    if (Array.isArray(v)) { return v.map(function (x) { return pvDeep(x, depth + 1); }); }
    var o = {};
    Object.keys(v).forEach(function (k) { o[k] = pvDeep(v[k], depth + 1); });
    return o;
  }

  function renderItemPanel(body, it) {
    var sm = SAFETY[it.safety] || SAFETY.review;
    var adviceOnly = it.method === 'none' && it.safety !== 'do_not_touch';
    body.appendChild(el('div', { cls: 'chip-row' }, [itemSafetyBadge(it), it.bytes ? toneBadge(U.fmtBytes(it.bytes), 'neutral', 'disk') : null,
      !adviceOnly && it.reversible === true ? toneBadge('Can be undone', 'good', 'refresh') : !adviceOnly && it.reversible === false ? toneBadge('Cannot be undone', 'warn', 'alert') : null]));
    if (adviceOnly) {
      body.appendChild(callout('info', 'info', 'Advice only', 'There is nothing to delete here. Read what it is and follow the advice below if you want.'));
    } else {
      body.appendChild(callout(sm.tone === 'tool' ? 'info' : sm.tone, it.safety === 'do_not_touch' ? 'lock' : it.safety === 'review' ? 'alert' : 'checkCircle', sm.label, sm.plain));
    }
    if (it.purpose) { body.appendChild(psection('What it is', 'info', el('p', { cls: 'p-text', text: privacy.label(it.path, it.purpose, pvKind(it)) }))); }
    var steps = splitSteps(it.how);
    if (steps.length) { body.appendChild(psection('How to handle it', 'fix', stepsList(steps))); }
    if ((it.flags || []).indexOf('work_at_risk') >= 0) { body.appendChild(callout('warn', 'alert', 'Unsaved work', 'This copy has uncommitted or unpushed git changes. Save them first.')); }
    var x = it.x || {};
    body.appendChild(psection('Facts', 'list', kv([
      ['Where', pvItemPath(it)], ['Size', typeof it.bytes === 'number' && it.bytes ? U.fmtBytes(it.bytes) + ' (' + U.fmtNum(it.bytes) + ' bytes)' : null],
      ['Files', typeof it.files === 'number' ? U.fmtNum(it.files) : null], ['Last changed', it.newest ? fmtWhen(it.newest) : null],
      ['Last used', x.lastUsed ? fmtWhen(x.lastUsed) + (x.lastUsedSource ? ' (' + x.lastUsedSource + ')' : '') : null],
      ['Kind', it.category ? humanize(it.category) : null], ['Publisher / owner', it.owner],
      ['Flags', (it.flags || []).length ? el('span', { cls: 'chip-row' }, it.flags.map(flagChip)) : null],
      ['Found by', it.module ? moduleName(it.module) : null]
    ])));
    if (Object.keys(x).length) {
      var tech = el('details', { cls: 'tech' });
      tech.appendChild(el('summary', null, [icon('code'), el('span', { text: 'Technical details (for experts)' })]));
      tech.appendChild(el('div', { cls: 'tech-body' }, [kv([['Item ID', it.id], ['List', it.list], ['Method', it.method]]), U.renderValue(x)]));
      body.appendChild(tech);
    }
    if (S.basket && !S.basket.canAdd(it) && it.method !== 'none') {
      body.appendChild(el('p', { cls: 'p-note', text: 'This item cannot go into the clean-up basket: ' + sm.label.toLowerCase() + '.' }));
    }
  }

  function renderFilePanel(body, file) {
    var fv = fileVerdict(file);
    body.appendChild(el('div', { cls: 'chip-row' }, [toneBadge(fv.label, fv.tone, fv.icon), file.severity ? sevBadge(file.severity) : null]));
    body.appendChild(callout(fv.tone === 'neutral' ? 'info' : fv.tone, fv.icon, fv.label, fv.plain));
    if (file.title) { body.appendChild(psection('What we found', 'info', el('p', { cls: 'p-text', text: privacy.text(file.title) }))); }
    if ((file.reasons || []).length) {
      var ul = el('ul', { cls: 'tick-list plain' });
      file.reasons.forEach(function (r) { ul.appendChild(el('li', null, [icon('dot'), el('span', { text: upperFirst(reasonText(r)) })])); });
      body.appendChild(psection('Why it was flagged', 'question', ul));
    }
    var steps = splitSteps(file.action);
    if (steps.length) {
      body.appendChild(psection(fv.key === 'false_alarm' ? 'Only if you do not recognise it' : 'What to do', 'fix', stepsList(steps)));
    }
    body.appendChild(psection('Facts', 'list', kv([
      ['Full path', privacy.path(file.path, 'file')], ['Size', typeof file.size === 'number' ? U.fmtBytes(file.size) : null], ['Created', file.created ? fmtWhen(file.created) : null],
      ['Digital signature', file.sig ? file.sig + (file.signer ? ' (' + file.signer + ')' : '') : 'None'],
      ['Downloaded from', file.origin ? file.origin + (file.zone !== null && file.zone !== undefined ? ' (zone ' + file.zone + ')' : '') : null],
      ['SHA-256 fingerprint', file.sha256 ? el('code', { cls: 'break', text: file.sha256 }) : null]
    ])));
    var ids = arr(file.findings).filter(function (id, i, a) { return a.indexOf(id) === i; });
    if (ids.length) {
      var rel = el('div', { cls: 'rel-list' });
      ids.forEach(function (id) { rel.appendChild(relatedFindingButton(id)); });
      body.appendChild(psection('Findings about this file', 'shield', rel));
    }
  }

  function renderQuestionPanel(body, q) {
    if (q.plain) { body.appendChild(el('p', { cls: 'p-lead', text: q.plain })); }
    if (q.found.length) {
      var ul = el('ul', { cls: 'tick-list plain' });
      q.found.forEach(function (t) { ul.appendChild(el('li', null, [icon('dot'), el('span', { text: t })])); });
      body.appendChild(psection('What we found', 'search', ul));
    }
    if (q.whyItMatters) { body.appendChild(psection('Why it matters', 'alert', el('p', { cls: 'p-text', text: q.whyItMatters }))); }
    body.appendChild(el('div', { cls: 'yesno' }, [
      el('div', { cls: 'yn yn-yes' }, [el('strong', { text: "If it's yours" }), el('p', { text: q.ifYes || 'Then it is probably fine.' })]),
      el('div', { cls: 'yn yn-no' }, [el('strong', { text: "If it's not yours" }), el('p', { text: q.ifNo || 'Treat it as a problem and ask for help.' })])
    ]));
    body.appendChild(psection('Your answer', 'check', answerBar(q, function () { renderPanel(panel.spec); refreshQuestionsView(); })));
    if (q.related.length) {
      var rel = el('div', { cls: 'rel-list' });
      q.related.forEach(function (id) { rel.appendChild(relatedFindingButton(id)); });
      body.appendChild(psection('Related findings', 'shield', rel));
    }
  }

  function renderFixPanel(body, fix) {
    body.appendChild(el('div', { cls: 'chip-row' }, [toneBadge('Priority ' + fix.priority, fix.priority <= 1 ? 'warn' : 'info', 'fix'),
      fix.effort ? toneBadge('About ' + fix.effort, 'neutral', 'clock') : null, fix.severity ? sevBadge(fix.severity) : null]));
    if (fix.plain) { body.appendChild(el('p', { cls: 'p-lead', text: fix.plain })); }
    if (fix.why) { body.appendChild(psection('Why it matters', 'alert', el('p', { cls: 'p-text', text: fix.why }))); }
    if (fix.steps.length) {
      body.appendChild(psection('Step by step', 'list', el('div', null, [stepsList(fix.steps),
        el('p', { cls: 'p-note', text: 'Nothing here happens automatically. Do the steps yourself, or ask Claude to walk you through them.' })])));
    }
    if (fix.related.length) {
      var rel = el('div', { cls: 'rel-list' });
      fix.related.forEach(function (id) { rel.appendChild(relatedFindingButton(id)); });
      body.appendChild(psection('The findings this fixes', 'shield', rel));
    }
  }

  function answerBar(q, onChange) {
    var cur = getAnswers()[q.id];
    var bar = el('div', { cls: 'answer-bar', attrs: { role: 'group', 'aria-label': 'Your answer' } });
    ['yes', 'no', 'unsure'].forEach(function (k) {
      var b = el('button', {
        cls: 'answer-btn ans-' + k, attrs: { type: 'button', 'aria-pressed': String(cur === k), 'data-bvs-type': 'question', 'data-bvs-id': q.id, 'data-bvs-label': ANSWERS[k] },
        on: { click: function () { setAnswer(q.id, getAnswers()[q.id] === k ? null : k); if (onChange) { onChange(); } } }
      }, [icon(k === 'yes' ? 'check' : k === 'no' ? 'close' : 'question'), el('span', { text: ANSWERS[k] })]);
      bar.appendChild(b);
    });
    return bar;
  }

  function rubricLadder(compact) {
    var cur = S.summary.verdict;
    var rows = [
      ['COMPROMISED', 'We only say HACKED when a serious sign of attack was double-checked and confirmed real.'],
      ['SUSPICIOUS', 'We say NEEDS A CLOSER LOOK when an important warning sign has not been ruled out yet.'],
      ['HARDENING_NEEDED', 'We say SAFE, SETTINGS TO TIGHTEN when there is no sign of attack, but some settings are weaker than they should be.'],
      ['OK', 'We say ALL GOOD when nothing more than small tidy-ups was found.']
    ];
    var ol = el('ol', { cls: 'ladder' + (compact ? ' compact' : '') });
    rows.forEach(function (r) {
      var vm = VERDICTS[r[0]], on = r[0] === cur;
      ol.appendChild(el('li', { cls: 'rung st-' + vm.status + (on ? ' is-current' : '') }, [
        el('span', { cls: 'rung-ico' }, icon(vm.icon)),
        el('div', null, [el('strong', { text: vm.label }), on ? el('span', { cls: 'rung-you', text: 'Your result' }) : null, el('p', { text: r[1] })])
      ]));
    });
    var wrap = el('div', null, [ol, el('p', { cls: 'p-note', text: 'False alarms and FYI items never count. Storage clean-up items never affect the security verdict.' })]);
    return wrap;
  }

  // ================================================================== router
  function parseHash(hash) {
    var h = String(hash || '');
    if (h.indexOf('#/') !== 0) { return null; }
    h = h.slice(2);
    var qi = h.indexOf('?');
    var path = qi >= 0 ? h.slice(0, qi) : h, qs = qi >= 0 ? h.slice(qi + 1) : '';
    var parts = path.split('/').filter(Boolean).map(function (p) { try { return decodeURIComponent(p); } catch (e) { return p; } });
    var query = {};
    try { new URLSearchParams(qs).forEach(function (v, k) { query[k] = v; }); } catch (e) { /* ignore */ }
    return { view: parts[0] || 'overview', parts: parts.slice(1), query: query, qs: qs, hash: '#/' + h };
  }

  function buildHash(view, parts, query) {
    var order = ['sev', 'class', 'verify', 'module', 'active', 'q', 'verdict', 'status', 'tab', 'show', 'section', 'safety', 'path'];
    var keys = Object.keys(query || {}).filter(function (k) { return query[k] !== '' && query[k] !== null && query[k] !== undefined; });
    keys.sort(function (a, b) { var ia = order.indexOf(a), ib = order.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
    var qs = keys.map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(String(query[k])).replace(/%2C/gi, ','); }).join('&');
    return '#/' + [view].concat((parts || []).map(encodeURIComponent)).join('/') + (qs ? '?' + qs : '');
  }

  function route() {
    if (!S.ready) { return; }
    var r = parseHash(window.location.hash);
    if (!r) {
      if (S.current.id) { return; }
      r = parseHash('#/overview');
    }
    var findingId = null;
    if (r.view === 'finding') {
      findingId = r.parts[0] || null;
      var sq = parseHash('#/security' + (S.lastSecurityQS ? '?' + S.lastSecurityQS : ''));
      sq.hash = r.hash;
      r = sq;
    } else if (r.view === 'security') {
      S.lastSecurityQS = r.qs;
    }
    var viewId = views[r.view] || PLACEHOLDERS[r.view] ? r.view : r.view.toLowerCase();
    var def = viewDef(viewId);
    if (!def) { viewId = 'notfound'; def = NOT_FOUND; }
    var params = { id: viewId, section: r.parts[0] || '', parts: r.parts, query: r.query, qs: r.qs, hash: r.hash, findingId: findingId };
    App.route = params;
    if (panel.open && !(findingId && panel.routeBound)) { App.closePanel({ navigate: false }); }
    mountView(viewId, def, params);
    if (findingId) { openFindingPanel(findingId, { routeBound: true }); }
    updateNavActive();
    var pt = $('bvs-page-title');
    if (pt) { pt.textContent = U.safeText(def.title || humanize(viewId)); }
    document.title = U.safeText(def.title || humanize(viewId)) + ' · Baby Virus Scanner';
  }

  function mountView(id, def, params) {
    var key = id + '|' + params.parts.join('/') + '|' + params.qs;
    var cur = S.current;
    if (cur.id === id && cur.def === def && cur.root) {
      if (cur.key === key) { return; }
      cur.key = key;
      if (typeof def.update === 'function') {
        try { def.update(params); } catch (err) { reportViewError(cur.root, err); }
        return;
      }
    }
    if (cur.def && typeof cur.def.unmount === 'function') { try { cur.def.unmount(); } catch (e) { if (window.console) { console.error(e); } } }
    var host = $('bvs-view');
    U.clear(host);
    var root = el('section', { cls: 'view view-' + id, attrs: { 'data-bvs-section': id, 'aria-label': str(def.title) || id } });
    var accent = typeof def.accent === 'string' && COLOR_RE.test(def.accent) ? def.accent : null;
    if (accent) { root.style.setProperty('--view-accent', accent); }
    host.appendChild(root);
    S.current = { id: id, def: def, root: root, key: key };
    try { def.mount(root, params); } catch (err) { reportViewError(root, err); }
    window.scrollTo(0, 0);
  }

  function reportViewError(root, err) {
    root.appendChild(callout('bad', 'alert', 'This page could not be shown', str(err && err.message)));
    if (window.console) { console.error(err); }
  }

  // ================================================================== views: Overview
  function scanMetaLine() {
    var s = S.summary, bits = [];
    if (s.auditStartUtc) { bits.push('Scanned ' + fmtWhen(s.auditStartUtc)); }
    if (s.host) { bits.push(s.host); }
    if (s.os && s.os.caption) { bits.push(s.os.caption); }
    var cc = (S.coverage || {}).checkCount || (S.summary.coverage || {}).checkCount;
    if (cc) { bits.push(U.fmtNum(cc) + ' checks'); }
    if (s.elevated === false) { bits.push('run without admin rights'); }
    return bits.join(' · ');
  }

  function derivedSubhead() {
    var act = activeCounts(), counts = S.summary.counts || {}, all = counts.bySeverity || {};
    var refuted = SEV_ORDER.reduce(function (n, k) { return n + Math.max(0, (all[k] || 0) - (act[k] || 0)); }, 0);
    var bits = [];
    var hi = (act.critical || 0) + (act.high || 0);
    if (hi) { bits.push(hi + ' important ' + plural(hi, 'item', 'items')); }
    if (act.medium) { bits.push(act.medium + ' worth fixing'); }
    var t = verdictInfo().plain;
    if (bits.length) { t += ' Open right now: ' + bits.join(' and ') + '.'; }
    if (refuted) { t += ' ' + refuted + ' alarms turned out to be false and do not count.'; }
    return t;
  }

  // ---- hero orb (UI-F) ----------------------------------------------------------------------------------
  // A 3D health ring: each coloured segment is a raised block (gradient face, darker side, gloss edge) that
  // floats in a slow wave and pops out on hover. Every segment has a "spec" chip, a real link to its area,
  // joined to it by a circuit leader line; the verdict button stays in the centre. All geometry uses one
  // 620 x 310 design box: the ring SVG (viewBox 200 45 220 220) and the leader SVG (viewBox 0 0 620 310) sit
  // in it by percentages, so segments, lines and chips stay aligned at any size. In a narrow hero (container
  // query in style.css) the chips become a grid under the ring and the leader lines hide.
  var ORB = { w: 620, h: 310, cx: 310, cy: 155, r: 87, sw: 18, lead1: 104, lead2: 122, chipX: 172, minGap: 54, edge: 28 };
  var ORB_GRADES = ['good', 'ok', 'attention', 'bad'];

  function orbArc(r, a0, a1) {
    function pt(a) { return (ORB.cx + r * Math.cos(a)).toFixed(2) + ' ' + (ORB.cy + r * Math.sin(a)).toFixed(2); }
    return 'M' + pt(a0) + ' A' + r + ' ' + r + ' 0 ' + (a1 - a0 > Math.PI ? 1 : 0) + ' 1 ' + pt(a1);
  }

  // segment angles (clockwise from the top, round caps included in the gap) and chip rows per side
  function orbLayout(n) {
    var slot = 2 * Math.PI / Math.max(n, 1), cap = (ORB.sw / 2) / ORB.r;
    var gap = n > 1 ? Math.min(slot - 0.07, 0.105 + 2 * cap) : 0, items = [];
    for (var i = 0; i < n; i++) {
      var th = -Math.PI / 2 + (i + 0.5) * slot, c = Math.cos(th), s = Math.sin(th);
      items.push({
        a0: -Math.PI / 2 + i * slot + gap / 2, a1: -Math.PI / 2 + (i + 1) * slot - gap / 2 - (n === 1 ? 1e-3 : 0),
        c: c, s: s, side: c > 1e-6 ? 1 : c < -1e-6 ? -1 : (i < n / 2 ? 1 : -1), y: ORB.cy + ORB.lead2 * s
      });
    }
    [1, -1].forEach(function (side) { // keep chips in a column at least minGap apart and inside the box
      var col = items.filter(function (it) { return it.side === side; }).sort(function (a, b) { return a.y - b.y; });
      col.forEach(function (it, k) { if (k && it.y - col[k - 1].y < ORB.minGap) { it.y = col[k - 1].y + ORB.minGap; } });
      var over = col.length ? col[col.length - 1].y - (ORB.h - ORB.edge) : 0;
      col.forEach(function (it) { if (over > 0) { it.y -= over; } it.y = Math.max(ORB.edge, it.y); });
    });
    return items;
  }

  // The groove is one SVG; every segment is its own small SVG layer on top, so its float and hover pop are
  // CSS transforms of an HTML-level box that the compositor animates (animating SVG children instead would
  // re-lay-out and repaint the page on every frame).
  function orbRing(areas, lay) {
    function layer(cls) { return svgEl('svg', { viewBox: (ORB.cx - 110) + ' 45 220 220', 'class': cls, 'aria-hidden': 'true', focusable: 'false' }); }
    var svg = layer('orb-ring');
    var defs = svgEl('defs', {});
    ORB_GRADES.forEach(function (g) { // one light-from-above gradient per grade, shared by all its segments
      var lg = svgEl('linearGradient', { id: 'orb-face-' + g, 'class': 'g-' + g, gradientUnits: 'userSpaceOnUse', x1: ORB.cx, y1: 62, x2: ORB.cx, y2: 248 });
      ['hi', 'mid', 'lo'].forEach(function (k, j) { lg.appendChild(svgEl('stop', { offset: [0, 0.5, 1][j], 'class': 'orb-stop-' + k })); });
      defs.appendChild(lg);
    });
    svg.appendChild(defs);
    svg.appendChild(svgEl('circle', { cx: ORB.cx, cy: ORB.cy, r: ORB.r, 'class': 'orb-well' }));
    svg.appendChild(svgEl('circle', { cx: ORB.cx, cy: ORB.cy, r: ORB.r - ORB.sw / 2 - 7, 'class': 'orb-rim' }));
    var segs = areas.map(function (a, i) {
      var it = lay[i], d = orbArc(ORB.r, it.a0, it.a1);
      var seg = layer('orb-seg g-' + a.grade), g = svgEl('g', { 'class': 'orb-seg-hit' });
      seg.style.setProperty('--ox', it.c.toFixed(3));
      seg.style.setProperty('--oy', it.s.toFixed(3));
      seg.style.setProperty('--i', String(i));
      seg.style.setProperty('--lit', ((1 - it.s) / 2).toFixed(2));
      g.appendChild(svgEl('path', { d: d, 'class': 'orb-seg-side', transform: 'translate(0 5)' }));
      g.appendChild(svgEl('path', { d: d, 'class': 'orb-seg-face', stroke: 'url(#orb-face-' + a.grade + ')' }));
      if (it.a1 - it.a0 > 0.16) { g.appendChild(svgEl('path', { d: orbArc(ORB.r + ORB.sw / 2 - 3.5, it.a0 + 0.05, it.a1 - 0.05), 'class': 'orb-seg-gloss' })); }
      seg.appendChild(g);
      return seg;
    });
    return { svg: svg, segs: segs };
  }

  function orbLeads(areas, lay) {
    var svg = svgEl('svg', { viewBox: '0 0 ' + ORB.w + ' ' + ORB.h, 'class': 'orb-leads', 'aria-hidden': 'true', focusable: 'false' });
    var leads = areas.map(function (a, i) {
      var it = lay[i], side = it.side, ax = ORB.cx + side * ORB.chipX;
      var p1 = [ORB.cx + ORB.lead1 * it.c, ORB.cy + ORB.lead1 * it.s], p2 = [ORB.cx + ORB.lead2 * it.c, ORB.cy + ORB.lead2 * it.s];
      var dy = it.y - p2[1], bx = p2[0] + side * Math.abs(dy), pts = [p1, p2];
      bx = side > 0 ? Math.min(bx, ax - 10) : Math.max(bx, ax + 10);
      if (Math.abs(dy) > 0.5) { pts.push([bx, it.y]); }
      pts.push([ax, it.y]);
      var d = 'M' + pts.map(function (p) { return p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' L');
      var g = svgEl('g', { 'class': 'orb-lead g-' + a.grade });
      g.appendChild(svgEl('path', { d: d, 'class': 'orb-lead-line' }));
      g.appendChild(svgEl('path', { d: d, 'class': 'orb-lead-flow', pathLength: 100 }));
      g.appendChild(svgEl('circle', { cx: p1[0].toFixed(1), cy: p1[1].toFixed(1), r: 2.4, 'class': 'orb-lead-pad' }));
      g.appendChild(svgEl('circle', { cx: ax, cy: it.y.toFixed(1), r: 3.4, 'class': 'orb-lead-pad end' }));
      svg.appendChild(g);
      return g;
    });
    return { svg: svg, leads: leads };
  }

  function heroOrb(areas, v, good) {
    var lay = orbLayout(areas.length), ring = orbRing(areas, lay), leads = orbLeads(areas, lay);
    var box = el('div', { cls: 'orb-box' + (areas.length > 10 ? ' orb-many' : '') });
    var specs = el('div', { cls: 'orb-specs' }), chips = [];
    function hot(k, on) { // segment, leader and chip light up together; the others dim a little
      [ring.segs[k], leads.leads[k], chips[k]].forEach(function (n) { if (n) { n.classList.toggle('is-hot', on); } });
      box.classList.toggle('has-hot', !!specs.querySelector('.is-hot'));
    }
    areas.forEach(function (a, i) {
      var gm = GRADES[a.grade] || GRADES.ok, it = lay[i];
      var chip = link(a.link, {
        cls: 'orb-spec g-' + a.grade + (it.side > 0 ? ' side-r' : ' side-l'),
        attrs: bvs('tile', 'ring-' + a.area.toLowerCase(), a.area + ': ' + gm.label, { 'aria-label': a.area + ': ' + gm.label + '. Open the details.' })
      }, [el('span', { cls: 'orb-spec-area', text: a.area }), el('span', { cls: 'orb-spec-grade', text: gm.label })]);
      chip.style.setProperty('--sy', (it.y / ORB.h * 100).toFixed(2) + '%');
      ['pointerenter', 'focus'].forEach(function (ev) { chip.addEventListener(ev, function () { hot(i, true); }); });
      ['pointerleave', 'blur'].forEach(function (ev) { chip.addEventListener(ev, function () { hot(i, false); }); });
      var seg = ring.segs[i]; // the segment itself is a mouse shortcut to the same place; the chip is the keyboard path
      seg.addEventListener('pointerenter', function () { hot(i, true); });
      seg.addEventListener('pointerleave', function () { hot(i, false); });
      seg.addEventListener('click', function () { var h = chip.getAttribute('href'); if (h) { window.location.hash = h; } });
      chips.push(chip);
      specs.appendChild(chip);
    });
    var center = el('button', {
      cls: 'orb-center', title: 'Why this verdict?',
      attrs: bvs('tile', 'verdict', 'Verdict: ' + v.label, { type: 'button', 'aria-label': 'Verdict: ' + v.label + '. ' + good + ' of ' + areas.length + ' health areas are fine. Open the explanation.' }),
      on: { click: openWhyPanel }
    }, [icon(v.icon, 'hero-shield'), el('span', { cls: 'hero-ring-label', text: good + ' of ' + areas.length + ' areas fine' })]);
    box.appendChild(leads.svg);
    box.appendChild(el('div', { cls: 'orb-core' }, [heroCoreFx(), ring.svg].concat(ring.segs, [center])));
    box.appendChild(specs);
    var fxs = fxGroup(box); // a slow outward wave around the ring; the hover pop adds on top through `translate`
    ring.segs.forEach(function (seg, i) {
      var it = lay[i];
      function tr(k) { return 'translate(' + (it.c * k).toFixed(2) + 'px, ' + (it.s * k).toFixed(2) + 'px)'; }
      fxs.play(seg, [{ transform: tr(3), easing: 'ease-in-out' }, { transform: tr(6.5), easing: 'ease-in-out' }, { transform: tr(3) }],
        { duration: 9000, iterations: Infinity, delay: -i * 1500 });
    });
    return el('div', { cls: 'hero-orb', attrs: { role: 'group', 'aria-label': 'Health of ' + areas.length + ' areas' } }, box);
  }

  // ---- hero current (UI-F) ------------------------------------------------------------------------------
  // Calm "electricity" on circuit traces just inside the hero's edges. The traces are separate lines that meet
  // at pads (a static SVG, painted once); one closed route runs through all of them and three soft sparks,
  // each a glowing head with two trailing dots, glide along it at about 70 px/s, so the current flows from one
  // line into the next, and each pad glows as a spark passes. Sparks and glows are small HTML layers moved
  // with transform/opacity animations, which run on the compositor: no main-thread work per frame. Rebuilt
  // from the hero's real size on resize, paused while the hero is off screen, not started under reduced
  // motion; hidden in forced colours (style.css).
  var CUR = { m: 12, cBig: 30, cSmall: 14, j: 9, speed: 70, sparks: 3, lag: 0.16 };

  // Decorative animations tied to one element, written with literal transform/opacity keyframes so the
  // compositor runs them (CSS keyframes that use var() fall back to the main thread on every frame). They
  // pause while the element is off screen and never start under reduced motion.
  function fxGroup(scope) {
    var list = [], onScreen = true;
    if (window.IntersectionObserver) {
      new IntersectionObserver(function (entries) {
        onScreen = entries[entries.length - 1].isIntersecting;
        list.forEach(function (a) { if (onScreen) { a.play(); } else { a.pause(); } });
      }).observe(scope);
    }
    return {
      play: function (node, frames, opts) {
        if (reducedMotion() || typeof node.animate !== 'function') { return; }
        var a = node.animate(frames, opts);
        if (!onScreen) { a.pause(); }
        list.push(a);
      },
      clear: function () { list.forEach(function (a) { a.cancel(); }); list = []; }
    };
  }
  function currentRoute(w, h) {
    var m = CUR.m, j = CUR.j, cb = CUR.cBig, cs = CUR.cSmall, L = m, R = w - m, T = m, B = h - m, pts = [];
    function P(x, y, pad) { pts.push({ x: x, y: y, pad: !!pad }); }
    function jog(x0, y0, x1, y1, ix, iy) { P(x0, y0, true); P(x0 + Math.sign(x1 - x0) * j + ix, y0 + Math.sign(y1 - y0) * j + iy); P(x1 + ix, y1 + iy); P(x1 + Math.sign(x1 - x0) * j, y1 + Math.sign(y1 - y0) * j, true); }
    P(L, T + cb, true); P(L + cb, T);                                   // top-left bevel, then the top edge
    jog(w * 0.26, T, w * 0.38, T, 0, j); jog(w * 0.62, T, w * 0.72, T, 0, j);
    P(R - cs, T); P(R, T + cs, true);                                   // top-right, then the right edge
    jog(R, h * 0.40, R, h * 0.56, -j, 0);
    P(R, B - cb); P(R - cb, B, true);                                   // bottom-right bevel, then the bottom edge
    jog(w * 0.74, B, w * 0.62, B, 0, -j); jog(w * 0.38, B, w * 0.28, B, 0, -j);
    P(L + cs, B); P(L, B - cs, true);                                   // bottom-left, then the left edge
    jog(L, h * 0.60, L, h * 0.44, j, 0);
    return pts;
  }
  function heroCurrentFx(hero) {
    var wrap = el('div', { cls: 'hero-current', attrs: { 'aria-hidden': 'true' } });
    var svg = svgEl('svg', { 'class': 'cur-traces', focusable: 'false', preserveAspectRatio: 'none' }), fx = el('div', { cls: 'cur-fx' });
    wrap.appendChild(svg);
    wrap.appendChild(fx);
    var last = '', fxs = fxGroup(hero);
    function at(node, x, y) { node.style.transform = 'translate(' + x.toFixed(1) + 'px, ' + y.toFixed(1) + 'px)'; return node; }
    function build() {
      var w = Math.round(hero.clientWidth), h = Math.round(hero.clientHeight), key = w + 'x' + h;
      if (w < 200 || h < 160 || key === last) { return; }
      last = key;
      fxs.clear();
      U.clear(svg);
      U.clear(fx);
      svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
      var pts = currentRoute(w, h), n = pts.length, cum = [0], total = 0;
      for (var i = 1; i <= n; i++) { var a = pts[i - 1], b = pts[i % n]; total += Math.hypot(b.x - a.x, b.y - a.y); cum.push(total); }
      function xy(p) { return p.x.toFixed(1) + ' ' + p.y.toFixed(1); }
      var lines = svgEl('g', {}), pads = svgEl('g', {}), seg = [];
      for (var k = 0; k <= n; k++) { // separate lines, each running from one pad to the next
        var p = pts[k % n];
        seg.push(xy(p));
        if (k && (p.pad || k === n) && seg.length > 1) { lines.appendChild(svgEl('path', { d: 'M' + seg.join(' L'), 'class': 'cur-line' })); seg = [xy(p)]; }
      }
      pts.forEach(function (q) { if (q.pad) { pads.appendChild(svgEl('circle', { cx: q.x.toFixed(1), cy: q.y.toFixed(1), r: 2.6, 'class': 'cur-pad' })); } });
      svg.appendChild(lines);
      svg.appendChild(pads);
      if (reducedMotion()) { return; } // static traces only
      var T =Math.max(16, Math.min(60, total / CUR.speed)), perT = T / CUR.sparks;
      var route = pts.concat([pts[0]]).map(function (q, idx) { return { transform: 'translate(' + q.x.toFixed(1) + 'px, ' + q.y.toFixed(1) + 'px)', offset: cum[idx] / total }; });
      for (var s = 0; s < CUR.sparks; s++) {
        ['head', 't1', 't2'].forEach(function (cls, j) { // trailing dots start a little later, so they follow the head
          var dot = at(el('span', { cls: 'cur-spark ' + cls }), pts[0].x, pts[0].y);
          fx.appendChild(dot);
          fxs.play(dot, route, { duration: T * 1000, iterations: Infinity, easing: 'linear', delay: -((s + 1) * perT - j * CUR.lag) * 1000 });
        });
      }
      pts.forEach(function (q, idx) { // each pad flashes as a spark head arrives (every perT seconds)
        if (!q.pad) { return; }
        var d = (((cum[idx] / total) * T - 0.05 * perT) % perT + perT) % perT - perT;
        var flash = at(el('span', { cls: 'cur-flash' }), q.x, q.y);
        fx.appendChild(flash);
        fxs.play(flash, [{ opacity: 0.06 }, { opacity: 0.9, offset: 0.05 }, { opacity: 0.06, offset: 0.24 }, { opacity: 0.06 }],
          { duration: perT * 1000, iterations: Infinity, easing: 'ease-in-out', delay: d * 1000 });
      });
    }
    function safeBuild() { try { build(); } catch (e) { /* decorative only */ } }
    if (window.ResizeObserver) { new ResizeObserver(safeBuild).observe(hero); } else { window.requestAnimationFrame(function () { window.requestAnimationFrame(safeBuild); }); }
    return wrap;
  }

  // UI-D: decorative 3D "shield core" layers behind the health ring (aria-hidden, no data, no text).
  function heroCoreFx() {
    function part(cls, kids) { return el('span', { cls: cls }, kids || null); }
    return el('span', { cls: 'core-fx', attrs: { 'aria-hidden': 'true' } }, [
      part('core-fallback fx-fallback', [
        part('core-glow'),
        part('core-ring core-ring-1'), part('core-ring core-ring-2'), part('core-ring core-ring-3'),
        part('core-orbit core-orbit-1', part('core-dot')), part('core-orbit core-orbit-2', part('core-dot'))
      ])
    ]);
  }
  // UI-D: an optional floating hero illustration (hero-shield.png/.webp), decorative and aria-hidden.
  function heroArt() { return el('span', { cls: 'fx-slot hero-art', attrs: { 'data-fx-slot': 'hero-shield', 'aria-hidden': 'true' } }); }

  function heroSection() {
    var g = G(), v = verdictInfo(), status = heroStatus(), stm = STATUS[status];
    var areas = healthModel(), fixes = fixesModel(), qs = questionsModel(), ans = getAnswers();
    var unanswered = qs.filter(function (q) { return !ans[q.id]; }).length;
    var good = areas.filter(function (a) { return a.grade === 'good' || a.grade === 'ok'; }).length;
    var hero = el('section', { cls: 'hero status-' + status, attrs: { 'data-bvs-section': 'overview-hero', 'aria-label': 'Overall result' } });
    var actions = el('div', { cls: 'hero-actions' }, [
      link('#/fixes', { cls: 'btn primary big', attrs: bvs('tile', 'see-fixes', 'See what to fix (' + fixes.length + ')') }, [icon('fix'), el('span', { text: 'See what to fix (' + fixes.length + ')' })]),
      button('Why this verdict?', openWhyPanel, { cls: 'big', icon: 'question', attrs: bvs('tile', 'why-verdict', 'Why this verdict?') })
    ]);
    if (unanswered) {
      actions.appendChild(link('#/questions', { cls: 'btn ghost big', attrs: bvs('tile', 'answer-questions', 'Answer questions') }, [icon('question'), el('span', { text: 'Answer ' + unanswered + ' ' + plural(unanswered, 'question', 'questions') })]));
    }
    hero.appendChild(heroCurrentFx(hero));
    hero.appendChild(el('div', { cls: 'hero-grid' }, [heroOrb(areas, v, good), el('div', { cls: 'hero-text' }, [
      el('div', { cls: 'hero-kicker' }, [toneBadge(v.label, stm.tone, stm.icon, v.plain)]),
      el('h1', { cls: 'hero-headline', text: str(g.headline) || v.headline }),
      el('p', { cls: 'hero-sub', text: str(g.subhead) || derivedSubhead() }),
      actions,
      el('p', { cls: 'hero-meta', text: scanMetaLine() })
    ])]));
    hero.appendChild(heroArt());
    return hero;
  }

  function healthRow() {
    var areas = healthModel();
    var wrap = el('section', { cls: 'block', attrs: { 'data-bvs-section': 'overview-health', 'aria-label': 'Health check' } });
    var good = areas.filter(function (a) { return a.grade === 'good' || a.grade === 'ok'; }).length;
    wrap.appendChild(sectionHeading('Health check', areas.length + ' areas of your PC at a glance: ' + good + ' look fine. Click any card to see more.'));
    var row = el('div', { cls: 'health-cards' });
    areas.forEach(function (a) {
      var gm = GRADES[a.grade] || GRADES.ok;
      row.appendChild(link(a.link, { cls: 'health-card g-' + a.grade, attrs: bvs('tile', 'health-' + a.area.toLowerCase(), a.area + ': ' + gm.label) }, [
        el('span', { cls: 'hc-top' }, [el('span', { cls: 'hc-ico' }, icon(AREA_ICONS[a.area] || 'info')), el('span', { cls: 'hc-area', text: a.area })]),
        el('span', { cls: 'hc-grade tone-' + gm.tone }, [icon(gm.icon), el('span', { text: gm.label })]),
        el('span', { cls: 'hc-text', text: a.text }),
        el('span', { cls: 'hc-go' }, [el('span', { text: 'See details' }), icon('arrow')])
      ]));
    });
    wrap.appendChild(row);
    return wrap;
  }

  function severityRow() {
    var c = S.summary.counts || {}, all = c.bySeverity || {}, act = activeCounts();
    var wrap = el('section', { cls: 'block', attrs: { 'data-bvs-section': 'overview-severity', 'aria-label': 'Findings by importance' } });
    wrap.appendChild(sectionHeading('What the security check found', 'Sorted by how much it matters. Click any number to see the list.',
      goLink('#/security?active=1', 'All findings')));
    var row = el('div', { cls: 'sev-tiles' });
    SEV_ORDER.forEach(function (sev) {
      var m = SEV[sev], n = act[sev] || 0, refuted = Math.max(0, (all[sev] || 0) - n);
      var tile = el('div', { cls: 'sev-tile sev-' + sev + (n ? '' : ' is-zero'), attrs: bvs('tile', 'sev-' + sev, m.label + ' (' + m.tech + '): ' + n + ' open') });
      tile.appendChild(link('#/security?sev=' + sev + '&active=1', { cls: 'tile-main', attrs: { 'aria-label': n + ' ' + m.label + ' (' + m.tech + ') findings. Open the list.' } }, [
        el('span', { cls: 'tile-top' }, [el('span', { cls: 'sev-dot', attrs: { 'aria-hidden': 'true' } }), el('span', { cls: 'tile-label', text: m.label })]),
        el('span', { cls: 'tile-num', text: U.fmtNum(n) }),
        el('span', { cls: 'tile-tech', text: m.tech + ' · ' + m.plain })
      ]));
      if (refuted) {
        tile.appendChild(link('#/security?sev=' + sev + '&verify=refuted', { cls: 'tile-sub', attrs: bvs('tile', 'sev-' + sev + '-refuted', refuted + ' ' + m.label + ' false alarms') },
          [icon('checkCircle'), el('span', { text: refuted + ' false ' + plural(refuted, 'alarm', 'alarms') + ', not counted' })]));
      } else {
        tile.appendChild(el('span', { cls: 'tile-sub quiet', text: n ? 'all still open' : 'nothing here' }));
      }
      row.appendChild(tile);
    });
    var hc = c.highCritical || 0, hcu = c.highCriticalUnverified || 0, ver = Math.max(0, hc - hcu);
    var vt = el('div', { cls: 'sev-tile verified-tile', attrs: bvs('tile', 'verified-high-critical', 'Double-checked important findings: ' + ver + ' of ' + hc) });
    vt.appendChild(link('#/security?verify=refuted,confirmed,inconclusive&sev=high,critical', { cls: 'tile-main', attrs: { 'aria-label': ver + ' of ' + hc + ' important findings were double-checked. Open the list.' } }, [
      el('span', { cls: 'tile-top' }, [icon('shieldCheck'), el('span', { cls: 'tile-label', text: 'Double-checked' })]),
      el('span', { cls: 'tile-num', text: hc ? ver + ' / ' + hc : '—' }),
      el('span', { cls: 'tile-tech', text: 'Verified high/critical' })
    ]));
    if (hcu) {
      vt.appendChild(link('#/security?verify=unverified&sev=high,critical', { cls: 'tile-sub', attrs: bvs('tile', 'unverified-high-critical', hcu + ' not double-checked') },
        [icon('clock'), el('span', { text: hcu + ' not double-checked yet' })]));
    } else {
      vt.appendChild(el('span', { cls: 'tile-sub quiet', text: 'every important item checked' }));
    }
    row.appendChild(vt);
    wrap.appendChild(row);
    return wrap;
  }

  function whyCard() {
    var vp = verdictPlainModel();
    var ul = el('ul', { cls: 'tick-list' });
    vp.whyNotCompromised.slice(0, 3).forEach(function (t) { ul.appendChild(el('li', null, [icon('check'), el('span', { text: t })])); });
    return card({ title: 'Why this verdict', href: '#/why', icon: 'question', section: 'overview-why', cls: 'ov-card', accent: 'var(--acc-security)' }, [
      el('p', { cls: 'card-lead', text: vp.summary }), ul,
      el('div', { cls: 'card-actions' }, [button('Explain it simply', openWhyPanel, { cls: 'small', icon: 'info', attrs: bvs('tile', 'why-panel', 'Explain the verdict') }), goLink('#/why', 'Full explanation')])
    ]);
  }

  function questionsCard() {
    var qs = questionsModel(), ans = getAnswers();
    var open = qs.filter(function (q) { return !ans[q.id]; }).length;
    var list = el('div', { cls: 'mini-list' });
    qs.slice(0, 3).forEach(function (q) {
      var a = ans[q.id];
      list.appendChild(el('button', { cls: 'mini-row', attrs: bvs('question', q.id, q.question, { type: 'button' }), on: { click: function () { openQuestionPanel(q); } } }, [
        el('span', { cls: 'mini-main' }, [
          el('span', { cls: 'mini-title', text: q.question || q.plain }),
          q.plain && q.question ? el('span', { cls: 'mini-sub', text: q.plain }) : null,
          el('span', { cls: 'mini-badge' }, a ? toneBadge('Your answer: ' + ANSWERS[a], a === 'yes' ? 'good' : a === 'no' ? 'bad' : 'warn') : toneBadge('Not answered yet', 'info', 'clock'))
        ]), icon('chevron')
      ]));
    });
    if (!qs.length) { list.appendChild(emptyState('No questions for you this time.', 'checkCircle')); }
    return card({
      title: 'Questions for you (' + qs.length + ')', href: '#/questions', icon: 'question', section: 'overview-questions', cls: 'ov-card', accent: 'var(--acc-questions)',
      sub: qs.length ? (open ? open + ' still need your answer. Only you know if these are yours.' : 'All answered. Thank you!') : null
    }, [list, el('div', { cls: 'card-actions' }, [goLink('#/questions', open ? 'Answer the questions' : 'Review your answers')])]);
  }

  function suspiciousCard() {
    var sf = arr(S.summary.suspiciousFiles), counts = { false_alarm: 0, fix: 0, unknown: 0 };
    sf.forEach(function (f) { counts[fileVerdict(f).key]++; });
    var checked = counts.false_alarm + sf.filter(function (f) { return f.verification === 'confirmed'; }).length;
    var allChecked = sf.length && counts.unknown === 0;
    var stats = el('div', { cls: 'stat-links' }, [
      link('#/suspicious?verdict=false_alarm', { cls: 'stat-link tone-good', attrs: bvs('tile', 'files-false-alarm', counts.false_alarm + ' false alarms') }, [el('span', { cls: 'stat-num', text: String(counts.false_alarm) }), el('span', { cls: 'stat-lbl' }, [icon('checkCircle'), 'Checked: false alarm'])]),
      link('#/suspicious?verdict=fix', { cls: 'stat-link tone-warn', attrs: bvs('tile', 'files-fix', counts.fix + ' need a fix') }, [el('span', { cls: 'stat-num', text: String(counts.fix) }), el('span', { cls: 'stat-lbl' }, [icon('fix'), 'Needs a fix'])]),
      link('#/suspicious?verdict=unknown', { cls: 'stat-link tone-neutral', attrs: bvs('tile', 'files-unknown', counts.unknown + ' not double-checked') }, [el('span', { cls: 'stat-num', text: String(counts.unknown) }), el('span', { cls: 'stat-lbl' }, [icon('clock'), 'Not double-checked'])])
    ]);
    return card({
      title: 'Suspicious files (' + sf.length + (allChecked ? ', all checked' : sf.length ? ', ' + checked + ' checked' : '') + ')', href: '#/suspicious', icon: 'file',
      section: 'overview-suspicious', cls: 'ov-card', accent: 'var(--acc-performance)',
      sub: sf.length ? 'Files a check flagged as unusual. Most turned out to be fine.' : 'No file was flagged.'
    }, [stats, el('div', { cls: 'card-actions' }, [goLink('#/suspicious', 'See every file and our verdict')])]);
  }

  function fixesCard() {
    var fixes = fixesModel();
    var list = el('div', { cls: 'fix-mini' });
    fixes.slice(0, 3).forEach(function (fx, i) {
      list.appendChild(el('button', { cls: 'fix-row', attrs: bvs('fix', fx.id, fx.title, { type: 'button' }), on: { click: function () { openFixPanel(fx); } } }, [
        el('span', { cls: 'fix-num', text: String(i + 1) }),
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: fx.title }), fx.plain ? el('span', { cls: 'mini-sub', text: fx.plain }) : null]),
        fx.effort ? toneBadge(fx.effort, 'neutral', 'clock') : null, icon('chevron')
      ]));
    });
    if (!fixes.length) { list.appendChild(emptyState('Nothing to fix right now.', 'checkCircle')); }
    var more = null;
    if (fixes.length > 3) {
      more = el('div', { cls: 'fix-more' }, [el('p', { cls: 'fix-more-h', text: 'Also on the list' })]);
      fixes.slice(3, 7).forEach(function (fx, i) {
        more.appendChild(el('button', { cls: 'fix-more-row', attrs: bvs('fix', fx.id, fx.title, { type: 'button' }), on: { click: function () { openFixPanel(fx); } } }, [
          el('span', { cls: 'fix-more-num', text: String(i + 4) }), el('span', { cls: 'fix-more-title', text: fx.title }), fx.effort ? el('span', { cls: 'fix-more-eff', text: fx.effort }) : null
        ]));
      });
    }
    return card({ title: 'Top fixes', href: '#/fixes', icon: 'fix', section: 'overview-fixes', cls: 'ov-card span-2', accent: 'var(--acc-overview)', sub: 'Do these first. Each one opens step-by-step instructions.' },
      [list, more, el('div', { cls: 'card-actions' }, [goLink('#/fixes', 'See all ' + fixes.length + ' fixes')])]);
  }

  function storageBars(ss) {
    var out = el('div', { cls: 'storage-glance' });
    if (!ss) { out.appendChild(emptyState('Storage was not scanned yet.', 'storage')); return out; }
    if (ss.volume && ss.volume.sizeBytes) {
      var used = ss.volume.usedBytes || (ss.volume.sizeBytes - (ss.volume.freeBytes || 0)), size = ss.volume.sizeBytes;
      var disk = link('#/storage/map', { cls: 'disk-bar-link', attrs: bvs('tile', 'disk-usage', 'Disk ' + U.fmtBytes(used) + ' used of ' + U.fmtBytes(size)) }, [
        el('span', { cls: 'bar-label' }, [el('strong', { text: 'Disk ' + str(ss.volume.root || '') }), el('span', { text: U.fmtBytes(used) + ' used · ' + U.fmtBytes(ss.volume.freeBytes) + ' free' })]),
        el('span', { cls: 'disk-bar' }, el('span', { cls: 'disk-fill' }))
      ]);
      disk.querySelector('.disk-fill').style.width = Math.min(100, used / size * 100).toFixed(1) + '%';
      out.appendChild(disk);
    }
    var by = ss.bySafety || {};
    var total = SAFETY_ORDER.reduce(function (n, k) { return n + ((by[k] || {}).bytes || 0); }, 0);
    if (total) {
      out.appendChild(el('p', { cls: 'bar-caption', text: 'Junk and leftovers we found (' + U.fmtBytes(total) + '), by how safe it is to clean:' }));
      var bar = el('div', { cls: 'stack-bar', attrs: { role: 'list' } });
      var legend = el('div', { cls: 'stack-legend' });
      SAFETY_ORDER.forEach(function (k) {
        var b = (by[k] || {}).bytes || 0;
        if (!b) { return; }
        var m = SAFETY[k], hash = '#/storage/junk?safety=' + k;
        var seg = link(hash, { cls: 'stack-seg saf-' + k, title: m.label + ': ' + U.fmtBytes(b), attrs: bvs('tile', 'storage-' + k, m.label + ': ' + U.fmtBytes(b), { role: 'listitem', 'aria-label': m.label + ': ' + U.fmtBytes(b) }) });
        seg.style.flexGrow = String(Math.max(b / total, 0.012));
        bar.appendChild(seg);
        legend.appendChild(link(hash, { cls: 'legend-item', attrs: bvs('tile', 'storage-legend-' + k, m.label) }, [el('span', { cls: 'saf-dot saf-' + k }), el('span', { cls: 'legend-name', text: m.label }), el('span', { cls: 'legend-val', text: U.fmtBytes(b) })]));
      });
      out.appendChild(bar);
      out.appendChild(legend);
    }
    return out;
  }

  function storageHighlights() {
    var gh = arr(G().storageHighlights);
    if (gh.length) {
      return gh.map(function (h) { return { title: str(h.title), bytes: typeof h.bytes === 'number' ? h.bytes : null, plain: str(h.plain), link: safeHash(h.link, '#/storage') }; });
    }
    var out = [];
    var dups = items('duplicates').filter(function (it) { return it.list === 'duplicateGroups'; });
    var wasted = dups.reduce(function (n, it) { return n + ((it.x || {}).wastedBytes || 0); }, 0);
    if (wasted) { out.push({ title: 'Duplicate files', bytes: wasted, plain: dups.length + ' sets of identical files', link: '#/storage/duplicates' }); }
    var big = items('storage').filter(function (it) { return (it.tabs || []).indexOf('big') >= 0; });
    if (big.length) { out.push({ title: 'Biggest files', bytes: big.reduce(function (n, it) { return n + (it.bytes || 0); }, 0), plain: big.length + ' large files listed', link: '#/storage/big' }); }
    var projects = items('duplicates').filter(function (it) { return it.list === 'projectCopies'; });
    if (projects.length) { out.push({ title: 'Project copies', bytes: null, plain: projects.length + ' copies of code projects', link: '#/storage/projects' }); }
    return out;
  }

  function storageCard() {
    var ss = storageSummary(), hl = storageHighlights();
    var hlist = el('div', { cls: 'mini-links' });
    hl.slice(0, 3).forEach(function (h, i) {
      hlist.appendChild(link(h.link, { cls: 'mini-link', attrs: bvs('tile', 'storage-highlight-' + (i + 1), h.title) }, [
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: h.title }), h.plain ? el('span', { cls: 'mini-sub', text: h.plain }) : null]),
        h.bytes ? el('span', { cls: 'mini-val', text: U.fmtBytes(h.bytes) }) : null, icon('chevron')
      ]));
    });
    return card({ title: 'Storage at a glance', href: '#/storage', icon: 'storage', section: 'overview-storage', cls: 'ov-card', accent: 'var(--acc-storage)' },
      [storageBars(ss), hl.length ? hlist : null, el('div', { cls: 'card-actions' }, [goLink('#/storage', 'Open the storage map')])]);
  }

  function stabilityModel() {
    var gs = G().stability;
    if (gs && (gs.title || gs.plain)) {
      return { title: str(gs.title), plain: str(gs.plain), facts: arr(gs.facts).map(str), steps: arr(gs.steps).map(str), fromGuide: true };
    }
    var st = stabilityFacts(), top = st.codes[0];
    var facts = [];
    [st.bsod, st.restarts, st.dumpFail].forEach(function (it) { if (it && it.purpose) { facts.push(str(it.purpose)); } });
    if (st.crashes.length) { facts.push(st.crashes.length + ' apps hung or crashed at least once in 90 days (for example ' + st.crashes.slice(0, 3).map(function (c) { return c.label; }).join(', ') + ').'); }
    return {
      title: st.bsodCount ? 'Your PC hit a blue screen ' + st.bsodCount + ' times in 90 days' : 'No blue screens in the last 90 days',
      plain: st.bsodCount ? 'A blue screen is when the whole PC crashes and restarts. It is almost always a driver, update or hardware problem, not a virus.' +
        (top ? ' The most common code here is ' + top.code + (BUGCHECKS[top.code] ? ', which means ' + BUGCHECKS[top.code] : '') + '.' : '') :
        'Windows recorded no crash of the whole system.',
      facts: facts, steps: st.bsod ? splitSteps(st.bsod.how) : [], fromGuide: false
    };
  }

  function stabilityCard() {
    var sm = stabilityModel(), st = stabilityFacts();
    var body = [el('p', { cls: 'card-lead', text: sm.title }), el('p', { cls: 'card-text', text: sm.plain })];
    if (st.bsodCount || st.restartCount) {
      body.push(el('div', { cls: 'stat-links two' }, [
        st.bsod ? el('button', { cls: 'stat-link tone-warn', attrs: bvs('storageItem', st.bsod.id, 'Blue screens', { type: 'button' }), on: { click: function () { openItemPanel(st.bsod); } } }, [el('span', { cls: 'stat-num', text: String(st.bsodCount) }), el('span', { cls: 'stat-lbl' }, [icon('alert'), 'Blue screens'])]) : null,
        st.restarts ? el('button', { cls: 'stat-link tone-neutral', attrs: bvs('storageItem', st.restarts.id, 'Unexpected restarts', { type: 'button' }), on: { click: function () { openItemPanel(st.restarts); } } }, [el('span', { cls: 'stat-num', text: String(st.restartCount) }), el('span', { cls: 'stat-lbl' }, [icon('power'), 'Unexpected restarts'])]) : null
      ]));
    }
    body.push(el('div', { cls: 'card-actions' }, [goLink('#/health', 'See the stability story')]));
    return card({ title: 'Stability', href: '#/health', icon: 'activity', section: 'overview-stability', cls: 'ov-card', accent: 'var(--acc-health)' }, body);
  }

  function speedCard() {
    var progs = items('programs').filter(function (it) { return it.list === 'programs'; });
    var unused = progs.filter(function (it) { return (it.flags || []).some(function (f) { return f === 'not_used_180d' || f === 'no_recent_use_evidence'; }); });
    var startup = items('startup').filter(function (it) { return it.list === 'startupItems'; });
    var running = startup.filter(function (it) { return (it.flags || []).indexOf('running') >= 0; });
    var ps = fact('programs', 'summary') || {};
    var rows = el('div', { cls: 'mini-links' }, [
      link('#/performance?tab=startup', { cls: 'mini-link', attrs: bvs('tile', 'perf-startup', startup.length + ' start with Windows') }, [
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: startup.length + ' things start with Windows' }), el('span', { cls: 'mini-sub', text: running.length + ' running now' + (ps.startupRamMB ? ', using about ' + Math.round(ps.startupRamMB) + ' MB of memory' : '') })]), icon('chevron')]),
      link('#/performance?tab=programs&show=unused', { cls: 'mini-link', attrs: bvs('tile', 'perf-unused', unused.length + ' programs probably unused') }, [
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: unused.length + ' programs look unused' }), el('span', { cls: 'mini-sub', text: 'Not opened for months. Uninstalling frees space.' })]),
        el('span', { cls: 'mini-val', text: U.fmtBytes(unused.reduce(function (n, it) { return n + (it.bytes || 0); }, 0)) }), icon('chevron')]),
      link('#/performance?tab=programs', { cls: 'mini-link', attrs: bvs('tile', 'perf-programs', progs.length + ' programs installed') }, [
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: progs.length + ' programs installed' }), el('span', { cls: 'mini-sub', text: 'Biggest first' })]),
        el('span', { cls: 'mini-val', text: U.fmtBytes(progs.reduce(function (n, it) { return n + (it.bytes || 0); }, 0)) }), icon('chevron')])
    ]);
    return card({ title: 'Speed & startup', href: '#/performance', icon: 'performance', section: 'overview-speed', cls: 'ov-card', accent: 'var(--acc-performance)' },
      [progs.length || startup.length ? rows : emptyState('Programs and startup were not scanned yet.', 'performance'), el('div', { cls: 'card-actions' }, [goLink('#/performance', 'Open performance')])]);
  }

  function coverageCard() {
    var by = (S.coverage || {}).byStatus || {};
    var list = el('div', { cls: 'mini-links' });
    var GROUP_OF = { needs_admin: 'admin', needs_consent: 'login', error: 'problems', skipped: 'problems', partial: 'partial' };
    ['needs_admin', 'needs_consent', 'error', 'partial', 'skipped'].forEach(function (k) {
      if (!by[k]) { return; }
      var m = COVERAGE_STATUS[k];
      list.appendChild(link('#/checks?group=' + GROUP_OF[k], { cls: 'mini-link', attrs: bvs('tile', 'coverage-' + k, by[k] + ' ' + m.label) }, [
        el('span', { cls: 'cov-num tone-' + m.tone, text: String(by[k]) }),
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: m.label }), el('span', { cls: 'mini-sub', text: short(m.plain, 70) })]), icon('chevron')
      ]));
    });
    var limits = arr(S.summary.honestLimits).length;
    if (limits) {
      list.appendChild(link('#/coverage?section=limits', { cls: 'mini-link', attrs: bvs('tile', 'coverage-limits', limits + ' honest limits') }, [
        el('span', { cls: 'cov-num tone-neutral', text: String(limits) }),
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: 'Things no scan can fully prove' }), el('span', { cls: 'mini-sub', text: 'For example hidden rootkits or your router' })]), icon('chevron')
      ]));
    }
    var total = Object.keys(by).reduce(function (n, k) { return n + (by[k] || 0); }, 0);
    var cta = (by.needs_admin || by.needs_consent) ? link('#/checks', { cls: 'btn primary small', attrs: bvs('tile', 'overview-fill-gaps', 'Fill in the missing checks') }, [icon('key'), el('span', { text: 'Fill in the missing checks' })]) : null;
    return card({ title: "What we couldn't check", href: '#/checks', icon: 'eyeOff', section: 'overview-coverage', cls: 'ov-card', accent: 'var(--acc-basket)',
      sub: total ? U.fmtNum(by.ok || 0) + ' of ' + U.fmtNum(total) + ' checks ran fully.' : null }, [list, el('div', { cls: 'card-actions' }, [cta, goLink('#/checks', 'See every check')])]);
  }

  var overviewView = {
    title: 'Overview', icon: 'overview', group: 'main', accent: 'var(--acc-overview)',
    mount: function (root) {
      root.appendChild(heroSection());
      root.appendChild(healthRow());
      root.appendChild(severityRow());
      root.appendChild(el('div', { cls: 'ov-grid', attrs: { 'data-bvs-section': 'overview-cards' } },
        [whyCard(), questionsCard(), suspiciousCard(), fixesCard(), storageCard(), stabilityCard(), speedCard(), coverageCard()]));
    }
  };

  // ================================================================== views: Security family
  function subNav(active) {
    var nav = el('nav', { cls: 'subnav', attrs: { 'aria-label': 'Security pages', 'data-bvs-section': 'security-subnav' } });
    [['security', 'All findings', 'list'], ['fixes', 'What to fix', 'fix'], ['suspicious', 'Suspicious files', 'file'], ['why', 'Why this verdict', 'question'], ['checks', 'Checks & permissions', 'key'], ['coverage', 'What we checked', 'eyeOff']].forEach(function (x) {
      var hash = x[0] === 'security' ? '#/security' + (S.lastSecurityQS && active !== 'security' ? '?' + S.lastSecurityQS : '') : '#/' + x[0];
      nav.appendChild(link(hash, { cls: 'subnav-item', attrs: Object.assign(bvs('section', x[0], x[1]), x[0] === active ? { 'aria-current': 'page' } : {}) }, [icon(x[2]), el('span', { text: x[1] })]));
    });
    return nav;
  }

  function listParam(q, k) { return str(q[k]).split(',').map(function (s) { return s.trim(); }).filter(Boolean); }
  function lowerList(q, k) { return listParam(q, k).map(function (s) { return s.toLowerCase(); }); }

  function filterFindings(q) {
    var sev = lowerList(q, 'sev'), cls = lowerList(q, 'class'), ver = lowerList(q, 'verify'), mod = listParam(q, 'module').map(function (s) { return s.toUpperCase(); });
    var text = str(q.q).trim().toLowerCase(), activeOnly = q.active === '1' || q.active === 'true';
    return S.findings.filter(function (f) {
      if (activeOnly && !isActive(f)) { return false; }
      if (sev.length && sev.indexOf(f.severity) < 0) { return false; }
      if (cls.length && cls.indexOf(f['class']) < 0) { return false; }
      if (ver.length && ver.indexOf(vres(f)) < 0) { return false; }
      if (mod.length && mod.indexOf(String(f.module).toUpperCase()) < 0) { return false; }
      if (text) {
        if (f.__search === undefined) {
          try { f.__search = JSON.stringify([f.id, f.title, f.check, moduleName(f.module), f.evidence, f.entities, f.fp_notes, f.recommendation, (f.reasons || []).map(reasonText)]).toLowerCase(); }
          catch (e) { f.__search = str(f.title).toLowerCase(); }
        }
        if (f.__search.indexOf(text) < 0) { return false; }
      }
      return true;
    });
  }

  function findingCard(f) {
    var v = vres(f), refuted = v === 'refuted', cls = CLASSES[f['class']] || CLASSES.info;
    return link('#/finding/' + encodeURIComponent(f.id), {
      cls: 'f-card sev-' + (SEV[f.severity] ? f.severity : 'info') + (refuted ? ' is-refuted' : ''),
      attrs: bvs('finding', f.id, privacy.text(f.title))
    }, [
      el('span', { cls: 'f-stripe', attrs: { 'aria-hidden': 'true' } }),
      el('span', { cls: 'f-main' }, [
        el('span', { cls: 'f-top' }, [sevBadge(f.severity), v !== 'unverified' ? verifyBadge(v) : null, el('span', { cls: 'f-class', text: cls.label })]),
        el('span', { cls: 'f-title', text: privacy.text(f.title) }),
        el('span', { cls: 'f-meta' }, [icon(MODULE_ICONS[f.module] || 'dot'), el('span', { text: moduleName(f.module) + ' · ' + f.id })])
      ]),
      icon('chevron', 'f-chev')
    ]);
  }

  function makeSecurityView() {
    var root, params, filtersBox, search, activeBtn, clearBtn, resultLine, list, chips = [], limit = PAGE_SIZE;
    function q() { return params ? params.query : {}; }
    function go(query) { App.navigate(buildHash('security', [], query), { replace: true }); }
    function setParam(key, value) {
      var nq = Object.assign({}, q());
      if (value) { nq[key] = value; } else { delete nq[key]; }
      go(nq);
    }
    function toggle(key, value) {
      var cur = listParam(q(), key), i = cur.indexOf(value);
      if (i >= 0) { cur.splice(i, 1); } else { cur.push(value); }
      setParam(key, cur.join(','));
    }
    function chipGroup(label, key, values, labelFn, techFn, dotCls) {
      var row = el('div', { cls: 'chip-group', attrs: { role: 'group', 'aria-label': label } }, [el('span', { cls: 'chip-group-label', text: label })]);
      var wrap = el('div', { cls: 'chip-wrap' });
      values.forEach(function (v) {
        var b = el('button', {
          cls: 'filter-chip' + (dotCls ? ' ' + dotCls + v : ''), title: techFn ? techFn(v) : null,
          attrs: { type: 'button', 'aria-pressed': 'false', 'data-key': key, 'data-value': v, 'data-bvs-type': 'tile', 'data-bvs-id': 'filter-' + key + '-' + v, 'data-bvs-label': labelFn(v) },
          on: { click: function () { toggle(key, v); } }
        }, [dotCls ? el('span', { cls: 'sev-dot', attrs: { 'aria-hidden': 'true' } }) : null, el('span', { text: labelFn(v) }), el('span', { cls: 'chip-count', text: '0' })]);
        chips.push(b);
        wrap.appendChild(b);
      });
      row.appendChild(wrap);
      return row;
    }
    function buildFilters() {
      search = el('input', { cls: 'search-input', attrs: { type: 'search', placeholder: 'Search, for example: token, firewall, Chrome', 'aria-label': 'Search findings', autocomplete: 'off', spellcheck: 'false' } });
      search.addEventListener('input', U.debounce(function () { setParam('q', search.value.trim()); }, 260));
      activeBtn = el('button', { cls: 'switch', attrs: { type: 'button', 'aria-pressed': 'false', 'data-bvs-type': 'tile', 'data-bvs-id': 'filter-active', 'data-bvs-label': 'Hide false alarms' }, on: { click: function () { setParam('active', q().active === '1' ? '' : '1'); } } },
        [el('span', { cls: 'switch-track', attrs: { 'aria-hidden': 'true' } }, el('span', { cls: 'switch-knob' })), el('span', { text: 'Hide false alarms' })]);
      clearBtn = button('Clear all filters', function () { go({}); }, { cls: 'ghost small', icon: 'close' });
      filtersBox.appendChild(el('div', { cls: 'filter-top' }, [el('label', { cls: 'search' }, [icon('search'), search]), activeBtn, clearBtn]));
      var mods = [];
      S.findings.forEach(function (f) { if (mods.indexOf(f.module) < 0) { mods.push(f.module); } });
      mods.sort();
      var vers = VERIFY_ORDER.filter(function (v) { return S.findings.some(function (f) { return vres(f) === v; }); });
      var clss = CLASS_ORDER.filter(function (c) { return S.findings.some(function (f) { return f['class'] === c; }); });
      filtersBox.appendChild(chipGroup('How serious', 'sev', SEV_ORDER, function (v) { return SEV[v].label; }, function (v) { return SEV[v].tech + ': ' + SEV[v].plain; }, 'sev-'));
      filtersBox.appendChild(chipGroup('Type', 'class', clss, function (v) { return CLASSES[v].label; }, function (v) { return CLASSES[v].plain; }));
      filtersBox.appendChild(chipGroup('Double-checked?', 'verify', vers, function (v) { return VERIFY[v].label; }, function (v) { return VERIFY[v].plain; }));
      filtersBox.appendChild(chipGroup('Area', 'module', mods, moduleName, function (v) { return v; }));
    }
    function describe(query) {
      var bits = [];
      var sev = lowerList(query, 'sev').map(function (s) { return (SEV[s] || {}).label || s; });
      if (sev.length) { bits.push(sev.join(' or ')); }
      var cls = lowerList(query, 'class').map(function (s) { return (CLASSES[s] || {}).label || s; });
      if (cls.length) { bits.push(cls.join(' or ')); }
      var ver = lowerList(query, 'verify').map(function (s) { return (VERIFY[s] || {}).label || s; });
      if (ver.length) { bits.push(ver.join(' or ')); }
      var mod = listParam(query, 'module').map(function (s) { return moduleName(s.toUpperCase()); });
      if (mod.length) { bits.push(mod.join(' or ')); }
      if (query.active === '1') { bits.push('false alarms hidden'); }
      if (query.q) { bits.push('matching "' + query.q + '"'); }
      return bits;
    }
    function sync() {
      var query = q(), activeOnly = query.active === '1' || query.active === 'true';
      var base = S.findings.filter(function (f) { return !activeOnly || isActive(f); });
      chips.forEach(function (c) {
        var key = c.getAttribute('data-key'), val = c.getAttribute('data-value');
        var sel = (key === 'module' ? listParam(query, key).map(function (s) { return s.toUpperCase(); }) : lowerList(query, key)).indexOf(val) >= 0;
        c.setAttribute('aria-pressed', String(sel));
        var n = base.filter(function (f) { return key === 'sev' ? f.severity === val : key === 'class' ? f['class'] === val : key === 'verify' ? vres(f) === val : f.module === val; }).length;
        c.querySelector('.chip-count').textContent = String(n);
        c.classList.toggle('is-empty', n === 0 && !sel);
      });
      activeBtn.setAttribute('aria-pressed', String(activeOnly));
      if (document.activeElement !== search) { search.value = str(query.q); }
      var has = Object.keys(query).some(function (k) { return query[k]; });
      clearBtn.hidden = !has;
      var shown = sortFindings(filterFindings(query));
      var desc = describe(query);
      U.clear(resultLine);
      resultLine.appendChild(el('strong', { text: shown.length + ' ' + plural(shown.length, 'finding', 'findings') }));
      resultLine.appendChild(el('span', { text: desc.length ? ' · ' + desc.join(' · ') : ' · everything, most important first' }));
      if (has) { resultLine.appendChild(el('span', { cls: 'muted', text: ' (of ' + S.findings.length + ' in total)' })); }
      renderList(shown);
    }
    function renderList(shown) {
      U.clear(list);
      if (!shown.length) {
        var query = q();
        var onlyZero = lowerList(query, 'sev').length && Object.keys(query).every(function (k) { return k === 'sev' || k === 'active'; });
        list.appendChild(emptyState(onlyZero ? 'Nothing at this level. That is good news.' : 'No finding matches these filters.', onlyZero ? 'checkCircle' : 'search',
          button('Show all findings', function () { go({}); }, { cls: 'small' })));
        return;
      }
      shown.slice(0, limit).forEach(function (f) { list.appendChild(findingCard(f)); });
      if (shown.length > limit) {
        list.appendChild(button('Show ' + Math.min(PAGE_SIZE, shown.length - limit) + ' more (' + (shown.length - limit) + ' left)', function () { limit += PAGE_SIZE; renderList(shown); }, { cls: 'show-more' }));
      }
      if (panel.open && panel.spec) { markOpenEntity(panel.spec); }
    }
    return {
      title: 'Security', icon: 'shield', group: 'main', accent: 'var(--acc-security)',
      mount: function (r, p) {
        root = r; params = p; chips = []; limit = PAGE_SIZE;
        root.appendChild(pageHead('shield', 'Security', 'Everything the security check found, most important first. Click any item to see what it means and what to do.'));
        root.appendChild(subNav('security'));
        filtersBox = el('section', { cls: 'card filter-card', attrs: { 'data-bvs-section': 'security-filters', 'aria-label': 'Filters' } });
        root.appendChild(filtersBox);
        resultLine = el('p', { cls: 'result-line', attrs: { 'aria-live': 'polite' } });
        root.appendChild(resultLine);
        list = el('div', { cls: 'f-list', attrs: { 'data-bvs-section': 'security-list' } });
        root.appendChild(list);
        buildFilters();
        sync();
      },
      update: function (p) { params = p; limit = PAGE_SIZE; sync(); },
      unmount: function () { root = null; }
    };
  }

  var suspiciousView = {
    title: 'Suspicious files', icon: 'file', group: 'main', parent: 'security', nav: false, accent: 'var(--acc-security)',
    mount: function (root, params) {
      var all = arr(S.summary.suspiciousFiles), want = str(params.query.verdict);
      root.appendChild(pageHead('file', 'Suspicious files', 'Files that a check flagged as unusual, with our verdict for each. Most were double-checked and turned out to be fine. Click a file for the full story.'));
      root.appendChild(subNav('suspicious'));
      var counts = { false_alarm: 0, fix: 0, unknown: 0 };
      all.forEach(function (f) { counts[fileVerdict(f).key]++; });
      var defs = [['', 'All files', all.length, 'neutral', 'file'], ['false_alarm', 'Checked: false alarm', counts.false_alarm, 'good', 'checkCircle'], ['fix', 'Needs a fix', counts.fix, 'warn', 'fix'], ['unknown', 'Not double-checked', counts.unknown, 'neutral', 'clock']];
      var seg = el('div', { cls: 'pill-tabs', attrs: { role: 'group', 'aria-label': 'Filter by verdict', 'data-bvs-section': 'suspicious-filters' } });
      defs.forEach(function (d) {
        seg.appendChild(link(d[0] ? '#/suspicious?verdict=' + d[0] : '#/suspicious', { cls: 'pill-tab tone-' + d[3], attrs: Object.assign(bvs('tile', 'files-' + (d[0] || 'all'), d[1] + ': ' + d[2]), want === d[0] ? { 'aria-current': 'true' } : {}) },
          [icon(d[4]), el('span', { text: d[1] }), el('span', { cls: 'chip-count', text: String(d[2]) })]));
      });
      root.appendChild(seg);
      var rows = all.filter(function (f) { return !want || fileVerdict(f).key === want; });
      rows.sort(function (a, b) { var ka = ['fix', 'unknown', 'false_alarm'].indexOf(fileVerdict(a).key), kb = ['fix', 'unknown', 'false_alarm'].indexOf(fileVerdict(b).key); return ka - kb || sevRank(a.severity) - sevRank(b.severity); });
      var box = el('section', { cls: 'card table-card', attrs: { 'data-bvs-section': 'suspicious-list' } });
      if (!rows.length) { box.appendChild(emptyState('No file in this group.', 'checkCircle')); }
      else {
        var wrap = el('div', { cls: 'table-wrap' });
        var table = el('table', { cls: 'nice' });
        table.appendChild(el('thead', null, el('tr', null, ['File', 'Our verdict', 'Why it was flagged', 'Signed by', 'Size'].map(function (h, i) { return el('th', { text: h, cls: i === 4 ? 'num' : '', attrs: { scope: 'col' } }); }))));
        var tb = el('tbody');
        rows.forEach(function (f) {
          var fv = fileVerdict(f);
          var tr = el('tr', { cls: 'row-click' + (fv.key === 'false_alarm' ? ' is-dim' : ''), attrs: bvs('file', f.path, privacy.label(f.path, fileName(f.path), 'file')) });
          tr.appendChild(el('td', null, [el('div', { cls: 'cell-main break', text: privacy.label(f.path, fileName(f.path), 'file') }), el('div', { cls: 'cell-sub break', text: privacy.path(fileFolder(f.path), 'folder') })]));
          tr.appendChild(el('td', null, toneBadge(fv.label, fv.tone, fv.icon)));
          tr.appendChild(el('td', { cls: 'cell-wrap', text: (f.reasons || []).map(function (r) { return upperFirst(reasonText(r)); }).join('; ') || '—' }));
          tr.appendChild(el('td', { text: f.signer || (f.sig ? f.sig : 'Not signed') }));
          tr.appendChild(el('td', { cls: 'num nowrap', text: typeof f.size === 'number' ? U.fmtBytes(f.size) : '—' }));
          clickable(tr, function () { openFilePanel(f); });
          tb.appendChild(tr);
        });
        table.appendChild(tb);
        wrap.appendChild(table);
        box.appendChild(wrap);
      }
      root.appendChild(box);
    }
  };

  var whyView = {
    title: 'Why this verdict', icon: 'question', group: 'main', parent: 'security', nav: false, accent: 'var(--acc-security)',
    mount: function (root) {
      var vp = verdictPlainModel(), v = verdictInfo(), st = heroStatus(), s = S.summary;
      root.appendChild(pageHead('question', 'Why this verdict', 'How we reached our conclusion, in plain words, and how sure we are.'));
      root.appendChild(subNav('why'));
      root.appendChild(el('section', { cls: 'card why-hero status-' + st, attrs: { 'data-bvs-section': 'why-summary' } }, [
        el('span', { cls: 'why-ico' }, icon(v.icon)),
        el('div', null, [toneBadge(v.label, STATUS[st].tone, STATUS[st].icon), el('h2', { cls: 'why-title', text: vp.summary }), el('p', { cls: 'card-text', text: vp.whatItMeans })])
      ]));
      var grid = el('div', { cls: 'two-col' });
      var ul = el('ul', { cls: 'tick-list' });
      vp.whyNotCompromised.forEach(function (t) { ul.appendChild(el('li', null, [icon('check'), el('span', { text: t })])); });
      grid.appendChild(card({ title: 'Why we reached this verdict', icon: 'checkCircle', section: 'why-reasons' }, ul));
      grid.appendChild(card({ title: 'How we decide', icon: 'list', section: 'why-rubric' }, rubricLadder(false)));
      root.appendChild(grid);
      // confidence
      var c = s.confidence || {}, counts = s.counts || {}, hc = counts.highCritical || 0, ver = hc - (counts.highCriticalUnverified || 0);
      var meters = el('div', { cls: 'meters' });
      if (typeof c.checkCoverage === 'number') { meters.appendChild(meter('Checks that ran fully', c.checkCoverage, Math.round(c.checkCoverage * 100) + '%', '#/coverage')); }
      if (hc) { meters.appendChild(meter('Important findings double-checked', ver / hc, ver + ' of ' + hc, '#/security?verify=refuted,confirmed,inconclusive&sev=high,critical')); }
      root.appendChild(card({ title: 'How sure we are' + (c.level ? ': ' + c.level + ' confidence' : ''), icon: 'info', section: 'why-confidence' }, [el('p', { cls: 'card-text', text: vp.confidenceText }), meters]));
      // drivers
      var driverIds = arr(s.verdictDrivers);
      var drivers = sortFindings(driverIds.map(function (id) { return App.findingById(id); }).filter(Boolean));
      var unresolved = driverIds.filter(function (id) { return !App.findingById(id); });
      var dl = el('div', { cls: 'f-list compact' });
      var shown = 12;
      function drawDrivers() {
        U.clear(dl);
        drivers.slice(0, shown).forEach(function (f) { dl.appendChild(findingCard(f)); });
        if (drivers.length > shown) { dl.appendChild(button('Show all ' + drivers.length, function () { shown = drivers.length; drawDrivers(); }, { cls: 'show-more' })); }
      }
      drawDrivers();
      var driverBody = [];
      if (drivers.length) { driverBody.push(dl); }
      if (unresolved.length) {
        driverBody.push(callout('warn', 'alert', unresolved.length + ' findings could not be shown', 'Their details did not load (' + short(unresolved.join(', '), 120) + '). Reload the page to see them.'));
      }
      if (!driverIds.length) { driverBody.push(emptyState('Nothing drives the verdict: all clear.', 'checkCircle')); }
      root.appendChild(card({ title: 'What drove this verdict (' + driverIds.length + ')', icon: 'shield', section: 'why-drivers', sub: 'These open findings are the reason the verdict is not "All good". Click one for details.' }, driverBody));
      // not checked
      var nc = el('ul', { cls: 'tick-list plain' });
      vp.notChecked.forEach(function (t) { nc.appendChild(el('li', null, [icon('eyeOff'), el('span', { text: t })])); });
      root.appendChild(card({ title: "What we couldn't check", icon: 'eyeOff', section: 'why-not-checked' }, [nc, el('div', { cls: 'card-actions' }, [goLink('#/coverage', 'See every check')])]));
    }
  };

  function meter(label, frac, valueText, hash) {
    var m = link(hash, { cls: 'meter', attrs: bvs('tile', 'meter-' + label.toLowerCase().replace(/[^a-z]+/g, '-'), label + ': ' + valueText) }, [
      el('span', { cls: 'meter-top' }, [el('span', { text: label }), el('strong', { text: valueText })]),
      el('span', { cls: 'meter-bar' }, el('span', { cls: 'meter-fill' }))
    ]);
    m.querySelector('.meter-fill').style.width = Math.max(0, Math.min(100, frac * 100)).toFixed(1) + '%';
    return m;
  }

  var fixesView = {
    title: 'What to fix', icon: 'fix', group: 'main', parent: 'security', nav: false, accent: 'var(--acc-overview)',
    mount: function (root) {
      var fixes = fixesModel();
      root.appendChild(pageHead('fix', 'What to fix', 'The most useful fixes, in order. Each one has numbered steps. Nothing happens automatically: you stay in control.'));
      root.appendChild(subNav('fixes'));
      if (!fixes.length) { root.appendChild(emptyState('Nothing to fix right now.', 'checkCircle')); return; }
      var list = el('div', { cls: 'fix-list', attrs: { 'data-bvs-section': 'fixes-list' } });
      fixes.forEach(function (fx, i) {
        var c = el('article', { cls: 'card fix-card', attrs: bvs('fix', fx.id, fx.title) });
        c.appendChild(el('div', { cls: 'fix-head' }, [
          el('span', { cls: 'fix-num big', text: String(i + 1) }),
          el('div', { cls: 'fix-titles' }, [el('h2', { text: fx.title }), fx.plain ? el('p', { cls: 'card-text', text: fx.plain }) : null]),
          el('div', { cls: 'chip-row' }, [toneBadge('Priority ' + fx.priority, fx.priority <= 1 ? 'warn' : 'info'), fx.effort ? toneBadge(fx.effort, 'neutral', 'clock') : null, fx.severity ? sevBadge(fx.severity) : null])
        ]));
        if (fx.why) { c.appendChild(el('p', { cls: 'fix-why' }, [el('strong', { text: 'Why: ' }), el('span', { text: fx.why })])); }
        if (fx.steps.length) { c.appendChild(stepsList(fx.steps)); }
        var foot = el('div', { cls: 'card-actions' });
        fx.related.slice(0, 4).forEach(function (id) {
          var f = App.findingById(id);
          foot.appendChild(el('button', { cls: 'btn small ghost', attrs: bvs('finding', id, f ? f.title : id, { type: 'button' }), on: { click: function () { openFindingPanel(id); } } }, [icon('shield'), el('span', { text: 'Finding ' + id })]));
        });
        foot.appendChild(button('Open as a checklist', function () { openFixPanel(fx); }, { cls: 'small', icon: 'list' }));
        c.appendChild(foot);
        list.appendChild(c);
      });
      root.appendChild(list);
    }
  };

  var coverageView = {
    title: 'What we checked', icon: 'eyeOff', group: 'main', parent: 'security', nav: false, accent: 'var(--acc-basket)',
    mount: function (root, params) {
      var cov = S.coverage || {}, by = cov.byStatus || {}, want = str(params.query.status), section = str(params.query.section);
      root.appendChild(pageHead('eyeOff', 'What we checked', 'Every scan has blind spots. Here is what ran fully, what was only partly checked, and what no scan can prove.'));
      root.appendChild(subNav('coverage'));
      if (by.needs_admin || by.needs_consent || by.error) {
        root.appendChild(callout('info', 'key', 'Some checks need your permission', el('div', null, [el('p', { text: 'Open Checks & permissions to run them with one button: the admin checks (1 Windows prompt) and the GitHub deep check.' }), el('div', { cls: 'card-actions' }, [goLink('#/checks', 'Open Checks & permissions')])])));
      }
      var total = Object.keys(by).reduce(function (n, k) { return n + (by[k] || 0); }, 0);
      var seg = el('div', { cls: 'pill-tabs', attrs: { role: 'group', 'aria-label': 'Filter by status', 'data-bvs-section': 'coverage-status' } });
      seg.appendChild(link('#/coverage', { cls: 'pill-tab', attrs: Object.assign(bvs('tile', 'coverage-all', 'All gaps'), !want ? { 'aria-current': 'true' } : {}) }, [el('span', { text: 'All gaps' }), el('span', { cls: 'chip-count', text: String(arr(cov.gaps).length) })]));
      COVERAGE_ORDER.forEach(function (k) {
        if (!by[k]) { return; }
        var m = COVERAGE_STATUS[k];
        seg.appendChild(link('#/coverage?status=' + k, { cls: 'pill-tab tone-' + m.tone, attrs: Object.assign(bvs('tile', 'coverage-' + k, m.label + ': ' + by[k]), want === k ? { 'aria-current': 'true' } : {}) }, [el('span', { text: m.label }), el('span', { cls: 'chip-count', text: String(by[k]) })]));
      });
      root.appendChild(seg);
      if (total) { root.appendChild(meter('Checks that ran fully', (by.ok || 0) / total, U.fmtNum(by.ok || 0) + ' of ' + U.fmtNum(total), '#/coverage?status=ok')); }
      // gaps
      var gaps = arr(cov.gaps).filter(function (g) { return !want || g.status === want; });
      var gbox = el('div', { cls: 'gap-list' });
      if (want === 'ok') { gbox.appendChild(emptyState(U.fmtNum(by.ok || 0) + ' checks ran fully. They are not listed one by one.', 'checkCircle')); }
      else if (want === 'not_applicable') { gbox.appendChild(emptyState(U.fmtNum(by.not_applicable || 0) + ' checks do not apply to this PC.', 'info')); }
      else if (!gaps.length) { gbox.appendChild(emptyState('Every check ran fully.', 'checkCircle')); }
      COVERAGE_ORDER.forEach(function (k) {
        var grp = gaps.filter(function (g) { return g.status === k; });
        if (!grp.length) { return; }
        var m = COVERAGE_STATUS[k];
        gbox.appendChild(el('div', { cls: 'gap-group-head' }, [toneBadge(m.label + ' (' + grp.length + ')', m.tone), el('span', { cls: 'muted', text: m.plain })]));
        grp.forEach(function (g) {
          gbox.appendChild(el('div', { cls: 'gap-row', attrs: bvs('section', g.id, g.description || g.id) }, [
            el('span', { cls: 'gap-mod' }, [icon(MODULE_ICONS[g.module] || 'dot'), el('span', { text: moduleName(g.module) })]),
            el('span', { cls: 'gap-main' }, [el('span', { cls: 'gap-desc', text: g.description || humanize(g.id) }), g.reason ? el('span', { cls: 'gap-reason', text: g.reason }) : null])
          ]));
        });
      });
      root.appendChild(card({ title: want ? (COVERAGE_STATUS[want] || {}).label || 'Checks' : 'Checks that did not run fully (' + arr(cov.gaps).length + ')', icon: 'list', section: 'coverage-gaps' }, gbox));
      // modules
      var mods = arr(cov.modules);
      if (mods.length) {
        var mg = el('div', { cls: 'module-grid' });
        mods.forEach(function (m) {
          var okN = (m.byStatus || {}).ok || 0, isSec = m.area === 'security';
          var target = isSec ? '#/security?module=' + m.module : m.module === 'H1' ? '#/performance' : m.module === 'H2' ? '#/health' : '#/storage';
          mg.appendChild(link(target, { cls: 'module-tile', attrs: bvs('tile', 'module-' + m.module, moduleName(m.module)) }, [
            el('span', { cls: 'mt-ico' }, icon(MODULE_ICONS[m.module] || 'dot')),
            el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: moduleName(m.module) }), el('span', { cls: 'mini-sub', text: okN + ' of ' + (m.checks || 0) + ' checks ran fully' + (isSec ? ' · ' + (m.findings || 0) + ' findings' : '') })]),
            icon('chevron')
          ]));
        });
        root.appendChild(card({ title: 'Areas we looked at', icon: 'shield', section: 'coverage-modules', sub: 'Click an area to see its findings.' }, mg));
      }
      // log windows
      var logs = arr(cov.logWindows);
      if (logs.length) {
        var wrap = el('div', { cls: 'table-wrap' });
        var t = el('table', { cls: 'nice' });
        t.appendChild(el('thead', null, el('tr', null, ['History log', 'From', 'To', 'Days covered', 'Events'].map(function (h, i) { return el('th', { text: h, cls: i >= 3 ? 'num' : '', attrs: { scope: 'col' } }); }))));
        var tb = el('tbody');
        logs.forEach(function (l) {
          tb.appendChild(el('tr', { attrs: bvs('section', 'log-' + l.log, l.log) }, [
            el('td', null, [el('div', { cls: 'cell-main', text: l.log }), el('div', { cls: 'cell-sub', text: moduleName(l.module) })]),
            el('td', { text: l.fromDate ? fmtDay(l.fromDate) : humanize((l.extra || {}).status || '—') }), el('td', { text: l.toDate ? fmtDay(l.toDate) : '—' }),
            el('td', { cls: 'num', text: l.days === null || l.days === undefined ? '—' : String(Math.round(l.days)) }),
            el('td', { cls: 'num', text: l.events === null || l.events === undefined ? '—' : U.fmtNum(l.events) })
          ]));
        });
        t.appendChild(tb);
        wrap.appendChild(t);
        root.appendChild(card({ title: 'How far back we could look', icon: 'history', section: 'coverage-logs', sub: 'Windows keeps limited history. Older events may already be overwritten.' }, wrap));
      }
      // honest limits
      var limits = arr(S.summary.honestLimits);
      if (limits.length) {
        var lg = el('div', { cls: 'limit-grid' });
        limits.forEach(function (l) {
          lg.appendChild(el('article', { cls: 'limit-card', attrs: bvs('section', 'limit-' + l.id, l.title) }, [
            el('h3', { text: l.title }), el('p', { text: l.text }), l.escalation ? el('p', { cls: 'limit-do' }, [el('strong', { text: 'What you can do: ' }), el('span', { text: l.escalation })]) : null
          ]));
        });
        var lc = card({ title: 'Things no scan can fully prove', icon: 'alert', section: 'coverage-limits', sub: 'Honest limits of any check that runs inside Windows.' }, lg);
        root.appendChild(lc);
        if (section === 'limits') { setTimeout(function () { lc.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' }); }, 30); }
      }
    }
  };

  // ================================================================== views: Questions
  var questionsRoot = null;
  function refreshQuestionsView() { if (S.current.id === 'questions' && questionsRoot) { var r = questionsRoot; U.clear(r); questionsView.mount(r); } updateBadges(); }

  function answersText() {
    var qs = questionsModel(), ans = getAnswers(), s = S.summary;
    var lines = ['My answers to the baby-virus-scanner questions (scan ' + (S.scanId || '') + (s.host ? ', ' + s.host : '') + '):', ''];
    qs.forEach(function (q, i) {
      lines.push((i + 1) + '. ' + U.safeText(q.question));
      if (q.plain) { lines.push('   About: ' + U.safeText(q.plain)); }
      if (q.related.length) { lines.push('   Related findings: ' + q.related.join(', ')); }
      lines.push('   My answer: ' + (ans[q.id] ? ANSWERS[ans[q.id]] : 'not answered yet'));
      lines.push('');
    });
    lines.push('Please use these answers to update the verdict and tell me what to do next. Do not delete or change anything without asking me first.');
    return lines.join('\n');
  }

  var questionsView = {
    title: 'Questions', icon: 'question', group: 'main', accent: 'var(--acc-questions)',
    mount: function (root) {
      questionsRoot = root;
      var qs = questionsModel(), ans = getAnswers();
      var answered = qs.filter(function (q) { return ans[q.id]; }).length;
      root.appendChild(pageHead('question', 'Questions for you', 'Only you can answer these. Tell us whether each item is yours: your answers help Claude decide what to fix. Answers are saved in this browser only.'));
      if (!qs.length) { root.appendChild(emptyState('No questions for you this time.', 'checkCircle')); return; }
      var status = el('span', { cls: 'copy-status', attrs: { 'aria-live': 'polite' } });
      var box = el('textarea', { cls: 'request-box', attrs: { readonly: true, rows: '8', spellcheck: 'false', 'aria-label': 'Your answers as text' }, hidden: true });
      var bar = el('section', { cls: 'card q-toolbar', attrs: { 'data-bvs-section': 'questions-toolbar' } }, [
        el('div', { cls: 'q-progress' }, [el('strong', { text: answered + ' of ' + qs.length + ' answered' }), el('span', { cls: 'q-progress-bar' }, el('span', { cls: 'q-progress-fill' }))]),
        el('div', { cls: 'card-actions' }, [button('Copy my answers for Claude', function () {
          var t = answersText();
          box.value = t;
          U.copyText(t).then(function (ok) {
            if (ok) { status.textContent = 'Copied. Paste it into the Claude Code chat.'; box.hidden = true; }
            else { box.hidden = false; box.focus(); box.select(); status.textContent = 'Clipboard not available here: the text is selected below, press Ctrl+C.'; }
          });
        }, { cls: 'primary', icon: 'copy', attrs: bvs('tile', 'copy-answers', 'Copy my answers for Claude') }), status]),
        box
      ]);
      bar.querySelector('.q-progress-fill').style.width = (answered / qs.length * 100).toFixed(1) + '%';
      root.appendChild(bar);
      qs.forEach(function (q, i) {
        var a = ans[q.id];
        var c = el('article', { cls: 'card q-card' + (a ? ' answered' : ''), attrs: bvs('question', q.id, q.question) });
        c.appendChild(el('div', { cls: 'q-head' }, [
          el('span', { cls: 'q-num', text: String(i + 1) }),
          el('div', { cls: 'q-titles' }, [el('h2', { text: q.question }), q.plain ? el('p', { cls: 'q-plain', text: q.plain }) : null]),
          a ? toneBadge(ANSWERS[a], a === 'yes' ? 'good' : a === 'no' ? 'bad' : 'warn', a === 'yes' ? 'check' : a === 'no' ? 'close' : 'question') : toneBadge('Waiting for you', 'info', 'clock')
        ]));
        var found = el('ul', { cls: 'tick-list plain' });
        q.found.forEach(function (t) { found.appendChild(el('li', null, [icon('dot'), el('span', { text: t })])); });
        c.appendChild(el('div', { cls: 'q-grid' }, [
          el('div', { cls: 'q-box' }, [el('h3', { cls: 'p-h' }, [icon('search'), el('span', { text: 'What we found' })]), q.found.length ? found : el('p', { cls: 'muted', text: '—' })]),
          el('div', { cls: 'q-box' }, [el('h3', { cls: 'p-h' }, [icon('alert'), el('span', { text: 'Why it matters' })]), el('p', { text: q.whyItMatters || '—' })])
        ]));
        c.appendChild(el('div', { cls: 'yesno' }, [
          el('div', { cls: 'yn yn-yes' }, [el('strong', { text: "If it's yours" }), el('p', { text: q.ifYes || 'Then it is probably fine.' })]),
          el('div', { cls: 'yn yn-no' }, [el('strong', { text: "If it's not yours" }), el('p', { text: q.ifNo || 'Treat it as a problem and ask for help.' })])
        ]));
        var foot = el('div', { cls: 'q-foot' }, [answerBar(q, refreshQuestionsView)]);
        var rel = el('div', { cls: 'q-rel' });
        q.related.forEach(function (id) {
          var f = App.findingById(id);
          rel.appendChild(el('button', { cls: 'btn small ghost', attrs: bvs('finding', id, f ? f.title : id, { type: 'button' }), on: { click: function () { openFindingPanel(id); } } }, [icon('shield'), el('span', { text: 'Finding ' + id })]));
        });
        rel.appendChild(button('More details', function () { openQuestionPanel(q); }, { cls: 'small', icon: 'info' }));
        foot.appendChild(rel);
        c.appendChild(foot);
        root.appendChild(c);
      });
    },
    unmount: function () { questionsRoot = null; }
  };

  // ================================================================== views: Performance + Health
  function vtable(container, rows, columns, opts) {
    opts = opts || {};
    var vt = new window.BVSUI.VTable(container, {
      columns: columns, rowHeight: opts.rowHeight || 56, height: opts.height || '460px', minWidth: opts.minWidth || 760,
      label: opts.label || 'table', emptyText: opts.emptyText || 'Nothing to show.', getId: function (it) { return it.id; },
      searchText: function (it) { return [it.label, it.path, it.purpose, it.owner, it.category, (it.flags || []).join(' ')].join(' '); },
      initialSort: opts.sort || null, onActivate: function (it) { openItemPanel(it); }
    });
    vt.setRows(rows);
    return vt;
  }
  function nameCol(label, width) {
    return {
      key: 'label', label: label || 'Name', width: width || 'minmax(240px, 2.4fr)', sortValue: function (it) { return str(it.label).toLowerCase(); },
      title: function (it) { return pvItemPath(it) || pvItemLabel(it); },
      render: function (it) {
        return el('span', { attrs: bvs('storageItem', it.id, pvItemLabel(it)) }, [el('span', { cls: 'primary', text: pvItemLabel(it) }), el('span', { cls: 'secondary', text: it.owner && label === 'Program' ? it.owner : (pvItemPath(it) || '—') })]);
      }
    };
  }
  function sizeCol() { return { key: 'bytes', label: 'Size', width: '96px', align: 'right', cls: 'num', defaultDir: 'desc', sortValue: function (it) { return typeof it.bytes === 'number' && it.bytes ? it.bytes : null; }, render: function (it) { return it.bytes ? U.fmtBytes(it.bytes) : '—'; } }; }
  function flagsCol(width) { return { key: 'flags', label: 'Notes', width: width || 'minmax(150px, 1.2fr)', render: function (it) { return el('span', { cls: 'chip-row nowrap' }, (it.flags || []).slice(0, 2).map(flagChip)); } }; }
  function safetyCol() { return { key: 'safety', label: 'Safety', width: '200px', sortValue: function (it) { return SAFETY_ORDER.indexOf(it.safety); }, render: function (it) { return itemSafetyBadge(it); } }; }

  function summaryTile(hash, iconName, num, label, sub, tone, id) {
    return link(hash, { cls: 'sum-tile tone-' + (tone || 'neutral'), attrs: bvs('tile', id, label + ': ' + num) }, [
      el('span', { cls: 'sum-ico' }, icon(iconName)), el('span', { cls: 'sum-num', text: String(num) }),
      el('span', { cls: 'sum-label', text: label }), sub ? el('span', { cls: 'sum-sub', text: sub }) : null
    ]);
  }

  var performanceView = {
    title: 'Performance', icon: 'performance', group: 'main', accent: 'var(--acc-performance)',
    mount: function (root, params) {
      var tab = ['programs', 'startup', 'hogs'].indexOf(params.query.tab) >= 0 ? params.query.tab : 'programs';
      var show = str(params.query.show);
      var progs = items('programs').filter(function (it) { return it.list === 'programs'; });
      var unused = progs.filter(function (it) { return (it.flags || []).some(function (f) { return f === 'not_used_180d' || f === 'no_recent_use_evidence'; }); });
      var flagged = progs.filter(function (it) { return (it.flags || []).length; });
      var startup = items('startup').filter(function (it) { return it.list === 'startupItems'; });
      var running = startup.filter(function (it) { return (it.flags || []).indexOf('running') >= 0; });
      var unsigned = startup.filter(function (it) { return (it.flags || []).indexOf('unsigned') >= 0; });
      var hogs = items('startup').filter(function (it) { return it.list === 'resourceHogs'; });
      var ps = fact('programs', 'summary') || {};
      root.appendChild(pageHead('performance', 'Performance', 'What is installed, what starts with Windows and what is busy right now. Click any row for plain-English advice.'));
      if (!progs.length && !startup.length && !hogs.length) { root.appendChild(emptyState('Programs and startup were not scanned yet. They are filled by the H1 module.', 'performance')); return; }
      var progBytes = progs.reduce(function (n, it) { return n + (it.bytes || 0); }, 0);
      root.appendChild(el('div', { cls: 'sum-tiles', attrs: { 'data-bvs-section': 'performance-summary' } }, [
        summaryTile('#/performance?tab=programs', 'package', progs.length, 'Programs installed', U.fmtBytes(progBytes) + ' in total', 'neutral', 'perf-programs'),
        summaryTile('#/performance?tab=programs&show=unused', 'clock', unused.length, 'Probably unused', U.fmtBytes(unused.reduce(function (n, it) { return n + (it.bytes || 0); }, 0)) + ' could be freed', unused.length ? 'warn' : 'good', 'perf-unused'),
        summaryTile('#/performance?tab=startup', 'power', startup.length, 'Start with Windows', running.length + ' running now', 'neutral', 'perf-startup'),
        summaryTile('#/performance?tab=startup&show=running', 'cpu', ps.startupRamMB ? Math.round(ps.startupRamMB) + ' MB' : running.length, 'Memory used by startup apps', 'right now', 'info', 'perf-startup-ram'),
        summaryTile('#/performance?tab=hogs', 'activity', hogs.length, 'Busy right now', 'top processor and memory users', 'neutral', 'perf-hogs')
      ]));
      var tabs = el('nav', { cls: 'pill-tabs', attrs: { 'aria-label': 'Performance lists', 'data-bvs-section': 'performance-tabs' } });
      [['programs', 'Installed programs', 'package', progs.length], ['startup', 'Starts with Windows', 'power', startup.length], ['hogs', 'Busy right now', 'activity', hogs.length]].forEach(function (t) {
        tabs.appendChild(link('#/performance?tab=' + t[0], { cls: 'pill-tab', attrs: Object.assign(bvs('section', 'perf-' + t[0], t[1]), tab === t[0] ? { 'aria-current': 'true' } : {}) }, [icon(t[2]), el('span', { text: t[1] }), el('span', { cls: 'chip-count', text: String(t[3]) })]));
      });
      root.appendChild(tabs);
      var box = el('section', { cls: 'card table-card', attrs: { 'data-bvs-section': 'performance-' + tab } });
      root.appendChild(box);
      function filterRow(opts) {
        var row = el('div', { cls: 'filter-row' });
        opts.forEach(function (o) {
          row.appendChild(link(o[0], { cls: 'filter-chip', attrs: Object.assign(bvs('tile', 'perf-show-' + (o[3] || 'all'), o[1]), show === (o[3] || '') ? { 'aria-current': 'true' } : {}) }, [el('span', { text: o[1] }), el('span', { cls: 'chip-count', text: String(o[2]) })]));
        });
        return row;
      }
      if (tab === 'programs') {
        var rows = show === 'unused' ? unused : show === 'flagged' ? flagged : progs;
        box.appendChild(el('p', { cls: 'card-text', text: 'Programs with their real size on disk and when they were last used. To remove one, always use Settings > Apps > Installed apps: this dashboard never uninstalls anything.' }));
        box.appendChild(filterRow([['#/performance?tab=programs', 'All programs', progs.length, ''], ['#/performance?tab=programs&show=unused', 'Probably unused', unused.length, 'unused'], ['#/performance?tab=programs&show=flagged', 'Has a note', flagged.length, 'flagged']]));
        var host = el('div');
        box.appendChild(host);
        vtable(host, rows, [nameCol('Program'), sizeCol(),
          { key: 'last', label: 'Last used', width: '130px', cls: 'num', defaultDir: 'desc', sortValue: function (it) { var d = U.toDate((it.x || {}).lastUsed); return d ? d.getTime() : null; }, render: function (it) { var lu = (it.x || {}).lastUsed; return lu ? fmtDay(lu) : 'Unknown'; } },
          flagsCol(), safetyCol()], { label: 'Installed programs', sort: { key: 'bytes', dir: 'desc' } });
      } else if (tab === 'startup') {
        var srows = show === 'running' ? running : show === 'unsigned' ? unsigned : startup;
        box.appendChild(el('p', { cls: 'card-text', text: 'Things that start automatically. Turning one off (Task Manager > Startup apps) is safe and can be undone; it is usually better than uninstalling. Leave Windows and antivirus items alone.' }));
        box.appendChild(filterRow([['#/performance?tab=startup', 'Everything', startup.length, ''], ['#/performance?tab=startup&show=running', 'Running now', running.length, 'running'], ['#/performance?tab=startup&show=unsigned', 'Not signed', unsigned.length, 'unsigned']]));
        var sh = el('div');
        box.appendChild(sh);
        vtable(sh, srows, [nameCol('Name'),
          { key: 'type', label: 'How it starts', width: '170px', sortValue: function (it) { return str((it.x || {}).startupType); }, render: function (it) { return humanize((it.x || {}).startupType || it.category); } },
          { key: 'ram', label: 'Memory', width: '100px', align: 'right', cls: 'num', defaultDir: 'desc', sortValue: function (it) { var r = (it.x || {}).ramBytes; return typeof r === 'number' ? r : null; }, render: function (it) { var r = (it.x || {}).ramBytes; return typeof r === 'number' ? U.fmtBytes(r) : '—'; } },
          { key: 'pub', label: 'Publisher', width: 'minmax(140px, 1fr)', sortValue: function (it) { return str(it.owner || (it.x || {}).signer) || null; }, render: function (it) { return it.owner || (it.x || {}).signer || 'Unknown'; } },
          safetyCol()], { label: 'Startup items', sort: { key: 'ram', dir: 'desc' } });
      } else {
        box.appendChild(el('p', { cls: 'card-text', text: 'Programs using the most processor time or memory during the scan. A snapshot of one moment: close what you do not need, and update or remove vendor tools that stay busy.' }));
        var hh = el('div');
        box.appendChild(hh);
        vtable(hh, hogs, [nameCol('Program'),
          { key: 'cpu', label: 'Processor', width: '110px', align: 'right', cls: 'num', defaultDir: 'desc', sortValue: function (it) { var c = (it.x || {}).cpuPct; return typeof c === 'number' ? c : null; }, render: function (it) { var c = (it.x || {}).cpuPct; return typeof c === 'number' ? c.toFixed(1) + '%' : '—'; } },
          { key: 'ram', label: 'Memory', width: '110px', align: 'right', cls: 'num', defaultDir: 'desc', sortValue: function (it) { var r = (it.x || {}).ramBytes; return typeof r === 'number' ? r : null; }, render: function (it) { var r = (it.x || {}).ramBytes; return typeof r === 'number' ? U.fmtBytes(r) : '—'; } },
          { key: 'sig', label: 'Signed by', width: 'minmax(140px, 1fr)', render: function (it) { return (it.x || {}).signer || 'Not signed'; } },
          flagsCol()], { label: 'Busy programs', sort: { key: 'ram', dir: 'desc' } });
      }
    }
  };

  var healthView = {
    title: 'Health', icon: 'health', group: 'main', accent: 'var(--acc-health)',
    mount: function (root, params) {
      var st = stabilityFacts(), sm = stabilityModel(), health = items('health'), registry = items('registry');
      var disk = health.filter(function (it) { return it.list === 'diskHealth'; });
      var downloads = health.filter(function (it) { return it.list === 'incompleteDownloads'; });
      var zero = health.filter(function (it) { return it.list === 'zeroByteFiles'; });
      var battery = items('startup').filter(function (it) { return it.list === 'battery'; })[0] || null;
      var physical = disk.filter(function (it) { return it.category === 'disk'; })[0] || null;
      var slowIo = disk.filter(function (it) { return (it.flags || []).indexOf('hardware_warning') >= 0; });
      var slowCount = slowIo.reduce(function (n, it) { return n + (Number((it.x || {}).count) || 0); }, 0);
      var broken = fact('health', 'brokenShortcuts');
      root.appendChild(pageHead('health', 'Health', 'How stable your PC is: crashes, blue screens, disk health, battery and leftovers. Click anything for advice.'));
      var tiles = el('div', { cls: 'sum-tiles', attrs: { 'data-bvs-section': 'health-summary' } });
      tiles.appendChild(summaryTile('#/health?section=stability', 'alert', st.bsodCount, 'Blue screens', 'in 90 days', st.bsodCount >= 5 ? 'bad' : st.bsodCount ? 'warn' : 'good', 'health-bsod'));
      tiles.appendChild(summaryTile('#/health?section=stability', 'power', st.restartCount, 'Unexpected restarts', 'in 90 days', st.restartCount ? 'warn' : 'good', 'health-restarts'));
      tiles.appendChild(summaryTile('#/health?section=crashes', 'activity', st.crashes.length, 'Apps that hung or crashed', 'in 90 days', st.crashes.length ? 'neutral' : 'good', 'health-crashes'));
      tiles.appendChild(summaryTile('#/health?section=disk', 'disk', physical ? str((physical.x || {}).healthStatus || 'Unknown') : '—', 'Disk health', slowCount ? slowCount + ' slow-disk warnings' : 'no warnings', slowCount ? 'warn' : 'good', 'health-disk'));
      if (battery) { tiles.appendChild(summaryTile('#/health?section=battery', 'battery', ((battery.x || {}).healthPct ? Math.round(battery.x.healthPct) + '%' : '—'), 'Battery health', 'of its original capacity', (battery.x || {}).healthPct < 80 ? 'warn' : 'good', 'health-battery')); }
      tiles.appendChild(summaryTile('#/health?section=leftovers', 'link', registry.length + downloads.length + (Array.isArray(broken) ? broken.length : 0), 'Leftovers', 'broken links and unfinished downloads', 'neutral', 'health-leftovers'));
      root.appendChild(tiles);
      var sections = {};
      // stability story
      var story = el('div', { cls: 'story' });
      story.appendChild(el('p', { cls: 'card-text', text: sm.plain }));
      if (sm.facts.length) { var fl = el('ul', { cls: 'tick-list plain' }); sm.facts.forEach(function (t) { fl.appendChild(el('li', null, [icon('dot'), el('span', { text: t })])); }); story.appendChild(fl); }
      if (st.codes.length) {
        var cl = el('div', { cls: 'code-list' });
        st.codes.forEach(function (c) { cl.appendChild(el('div', { cls: 'code-row' }, [el('code', { text: c.code }), el('span', { cls: 'code-count', text: c.count + 'x' }), el('span', { text: BUGCHECKS[c.code] ? upperFirst(BUGCHECKS[c.code]) : 'Less common code' })])); });
        story.appendChild(psection('Blue-screen codes, explained', 'info', cl));
      }
      if (sm.steps.length) { story.appendChild(psection('What to try', 'fix', stepsList(sm.steps))); }
      var sbtns = el('div', { cls: 'card-actions' });
      [st.bsod, st.restarts, st.dumpFail].forEach(function (it) { if (it) { sbtns.appendChild(el('button', { cls: 'btn small', attrs: bvs('storageItem', it.id, it.purpose, { type: 'button' }), on: { click: function () { openItemPanel(it); } } }, [icon('info'), el('span', { text: short(str((it.x || {}).meaning || it.purpose), 48) })])); } });
      story.appendChild(sbtns);
      sections.stability = card({ title: sm.title, icon: 'activity', section: 'health-stability', cls: 'story-card', accent: st.bsodCount ? 'var(--warn)' : 'var(--good)' }, story);
      root.appendChild(sections.stability);
      // crashes
      sections.crashes = card({ title: 'Apps that hung or crashed (' + st.crashes.length + ')', icon: 'activity', section: 'health-crashes', sub: 'Single apps freezing now and then is normal. Repeated crashes of the same app point to an update or add-in problem.' },
        st.crashes.length ? itemRows(st.crashes, function (it) { var x = it.x || {}; return (x.crashes || 0) + ' crashes, ' + (x.hangs || 0) + ' hangs · latest ' + fmtDay(x.latestUtc); }) : emptyState('No app crashes recorded.', 'checkCircle'));
      root.appendChild(sections.crashes);
      // disk
      sections.disk = card({ title: 'Disk health', icon: 'disk', section: 'health-disk', sub: physical ? str(physical.purpose) : null },
        disk.length ? itemRows(disk, function (it) { return it.purpose; }) : emptyState('Disk health was not checked yet.', 'disk'));
      root.appendChild(sections.disk);
      if (battery) {
        sections.battery = card({ title: 'Battery', icon: 'battery', section: 'health-battery' }, itemRows([battery], function (it) { return it.purpose; }));
        root.appendChild(sections.battery);
      }
      // leftovers
      var left = el('div', { cls: 'stack' });
      left.appendChild(el('h3', { cls: 'p-h' }, [icon('link'), el('span', { text: 'Broken registry references (' + registry.length + ')' })]));
      left.appendChild(el('p', { cls: 'p-note', text: 'Registry cleaners do not make Windows faster. These are listed only because they have a visible effect. Always back up before changing the registry.' }));
      left.appendChild(registry.length ? itemRows(registry, function (it) { return (it.x || {}).impact || it.purpose; }) : emptyState('No broken references found.', 'checkCircle'));
      left.appendChild(el('h3', { cls: 'p-h' }, [icon('link'), el('span', { text: 'Broken shortcuts' })]));
      left.appendChild(Array.isArray(broken) && broken.length ? el('ul', { cls: 'tick-list plain' }, broken.slice(0, 50).map(function (b) { return el('li', null, [icon('dot'), el('span', { text: privacy.text(typeof b === 'string' ? b : str(b.path || b.name || JSON.stringify(b))) })]); })) : emptyState('No broken shortcuts found.', 'checkCircle'));
      left.appendChild(el('h3', { cls: 'p-h' }, [icon('file'), el('span', { text: 'Unfinished downloads (' + downloads.length + ')' })]));
      left.appendChild(downloads.length ? itemRows(downloads, function (it) { return it.purpose; }) : emptyState('No unfinished downloads.', 'checkCircle'));
      left.appendChild(el('h3', { cls: 'p-h' }, [icon('file'), el('span', { text: 'Empty files (' + zero.length + ' listed)' })]));
      left.appendChild(el('p', { cls: 'p-note', text: 'Files of 0 bytes. Deleting them frees no space; they are only clutter, unless an app keeps them as placeholders.' }));
      if (zero.length) {
        var zh = el('div');
        left.appendChild(zh);
        vtable(zh, zero, [nameCol('File'), { key: 'newest', label: 'Last changed', width: '130px', cls: 'num', defaultDir: 'desc', sortValue: function (it) { var d = U.toDate(it.newest); return d ? d.getTime() : null; }, render: function (it) { return fmtDay(it.newest); } }, safetyCol()],
          { label: 'Empty files', height: '360px', rowHeight: 52, sort: { key: 'newest', dir: 'desc' } });
      }
      sections.leftovers = card({ title: 'Leftovers', icon: 'link', section: 'health-leftovers' }, left);
      root.appendChild(sections.leftovers);
      var target = sections[str(params.query.section)];
      if (target) { setTimeout(function () { target.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' }); }, 30); }
    }
  };

  function itemRows(list, subFn) {
    var wrap = el('div', { cls: 'item-rows' });
    list.forEach(function (it) {
      var flagsEl = (it.flags || []).length ? el('span', { cls: 'chip-row' }, it.flags.slice(0, 2).map(flagChip)) : null;
      wrap.appendChild(el('button', { cls: 'item-row', attrs: bvs('storageItem', it.id, pvItemLabel(it), { type: 'button' }), on: { click: function () { openItemPanel(it); } } }, [
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: pvItemLabel(it) }), el('span', { cls: 'mini-sub', text: privacy.label(it.path, str(subFn ? subFn(it) : it.purpose), pvKind(it)) })]),
        flagsEl, itemSafetyBadge(it), icon('chevron')
      ]));
    });
    return wrap;
  }

  // ================================================================== v3: Claude session pill (top bar)
  function syncSessionPill() {
    var b = $('bvs-session-pill');
    if (!b) { return; }
    var st = Bridge.live === null ? 'checking' : !Bridge.live ? 'off' : Bridge.session && Bridge.session.connected ? 'on' : 'idle';
    var text = { checking: 'Checking Claude…', on: 'Claude connected', idle: 'Claude not listening', off: 'Claude not listening' }[st];
    var tip = {
      checking: 'Checking whether your Claude session is listening…',
      on: 'Your Claude session is listening: buttons on this page reach it within seconds.',
      idle: "Ask Claude in your IDE: 'start the dashboard listener'",
      off: bridgeHint()
    }[st];
    U.clear(b);
    b.appendChild(el('span', { cls: 'session-dot', attrs: { 'aria-hidden': 'true' } }));
    b.appendChild(el('span', { cls: 'session-text', text: text }));
    b.className = 'session-pill st-' + st;
    b.title = tip;
    b.setAttribute('aria-label', text + '. ' + tip);
    b.hidden = false;
  }
  function openSessionPanel() {
    App.openPanel({
      kind: 'custom', id: 'claude-connection', title: 'Your Claude connection', kicker: 'Remote control',
      render: function (body) {
        var box = el('div', { cls: 'stack' });
        body.appendChild(box);
        liveWidget(box, function () {
          U.clear(box);
          if (Bridge.live && Bridge.session && Bridge.session.connected) {
            box.appendChild(callout('good', 'checkCircle', 'Claude connected', 'Your Claude session is listening. When you press a button here, Claude picks it up within a few seconds and replies in your chat.'));
          } else if (Bridge.live) {
            box.appendChild(callout('warn', 'plug', 'Claude is not listening right now', "Ask Claude in your IDE: 'start the dashboard listener'. Requests you send meanwhile wait in the queue and are handled oldest first."));
          } else {
            box.appendChild(callout('info', 'info', 'Needs the live dashboard', bridgeHint()));
          }
          if (Bridge.session && Bridge.session.beatAt) { box.appendChild(el('p', { cls: 'p-note', text: 'Last sign of life from Claude: ' + fmtWhen(Bridge.session.beatAt) })); }
        }, 'state');
        body.appendChild(psection('How the remote control works', 'list', stepsList([
          'You press a button here, for example "Run the admin checks".',
          'The dashboard leaves a request for your Claude session on this PC. Nothing goes to the internet.',
          'Claude picks it up and tells you in the chat what it will do.',
          'Anything that changes your PC (a fix, a deletion) waits until you confirm in the chat yourself. Claude never types a confirmation for you.'
        ])));
        body.appendChild(el('p', { cls: 'p-more' }, [goLink('#/checks', 'Open Checks & permissions')]));
      }
    });
  }

  // ================================================================== v3: signal tracker ("Your requests to Claude")
  function signalTitle(s) {
    var p = s.payload || (Bridge.sent.get(s.id) || {}).payload || {};
    if (s.type === 'run-admin') { return 'Run the admin checks'; }
    if (s.type === 'run-github-check') { return 'GitHub deep check'; }
    if (s.type === 'rerun-module') { return 'Re-run: ' + (p.module ? moduleName(p.module) : 'one area'); }
    if (s.type === 'refresh-report') { return 'Refresh the report'; }
    if (s.type === 'fix-request') {
      var f = p.findingId ? App.findingById(p.findingId) : null;
      return 'Fix request: ' + (f ? short(privacy.text(f.title), 80) : (p.findingId || 'a finding'));
    }
    if (s.type === 'delete-request') {
      var n = Array.isArray(p.items) ? p.items.length : typeof p.items === 'number' ? p.items : p.count;
      return 'Deletion request' + (n ? ': ' + n + ' ' + plural(n, 'item', 'items') : '');
    }
    return humanize(s.type) || 'Request';
  }
  function hhmmOf(v) {
    var d = U.toDate(v);
    if (!d) { return ''; }
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
  }
  function signalRow(s) {
    var st = SIGNAL_STATES[s.state] || { label: humanize(s.state) || 'Unknown', tone: 'neutral', icon: 'dot', plain: '' };
    var mine = Bridge.sent.has(s.id);
    var hint = s.state === 'awaiting-chat-confirmation' && s.type === 'delete-request'
      ? 'Your turn: in the Claude chat, type the "I confirm" line with the code shown on the Basket page.' : s.state === 'awaiting-chat-confirmation' || !s.message ? st.plain : '';
    return el('li', { cls: 'sig-row sig-st-' + st.tone + (ACTIVE_STATES[s.state] ? ' is-active' : ''), attrs: bvs('section', 'signal-' + s.id, signalTitle(s) + ': ' + st.label) }, [
      el('span', { cls: 'sig-ico tone-' + st.tone }, icon(st.icon)),
      el('span', { cls: 'sig-main' }, [
        el('span', { cls: 'sig-title', text: signalTitle(s) }),
        el('span', { cls: 'sig-state' }, [el('strong', { text: st.label }), s.message ? el('span', { text: ' · ' + privacy.text(s.message) }) : null]),
        hint ? el('span', { cls: 'sig-hint', text: hint }) : null
      ]),
      el('span', { cls: 'sig-time', text: (mine ? 'sent ' : '') + hhmmOf(s.createdAt) })
    ]);
  }
  // opts: {filter(sig) -> bool, limit, empty}
  function signalTracker(opts) {
    opts = opts || {};
    var wrap = el('div', { cls: 'sig-tracker', attrs: { 'aria-live': 'polite' } });
    var expanded = false;
    liveWidget(wrap, function () {
      U.clear(wrap);
      if (!Bridge.live && !Bridge.demo) {
        wrap.appendChild(el('p', { cls: 'sig-empty', text: bridgeHint() }));
        return;
      }
      var list = allSignals().filter(function (s) { return !opts.filter || opts.filter(s); });
      if (!list.length) { wrap.appendChild(el('p', { cls: 'sig-empty', text: opts.empty || 'No requests yet. When you press a button above, its progress appears here.' })); return; }
      var limit = expanded ? 30 : (opts.limit || 6);
      var ul = el('ul', { cls: 'sig-list', attrs: { role: 'list' } });
      list.slice(0, limit).forEach(function (s) { ul.appendChild(signalRow(s)); });
      wrap.appendChild(ul);
      if (list.length > limit) { wrap.appendChild(button('Show ' + Math.min(30, list.length) + ' recent requests', function () { expanded = true; refreshLive('signals'); }, { cls: 'small ghost' })); }
      if (Bridge.lastSignalsAt) { wrap.appendChild(el('p', { cls: 'sig-updated', text: 'Updated ' + hhmmOf(Bridge.lastSignalsAt) + ' · refreshes every few seconds while this page is open' })); }
    }, 'all');
    setTimeout(pollSignals, 50);
    return wrap;
  }
  function trackerCard() {
    return card({ title: 'Your requests to Claude', icon: 'send', section: 'signal-tracker', cls: 'tracker-card', sub: 'Live progress of what you asked Claude to do.' + (Bridge.demo ? ' (demo data)' : '') }, signalTracker());
  }
  function bridgeNotice() {
    var box = el('div', { cls: 'bridge-notice' });
    liveWidget(box, function () {
      U.clear(box);
      if (Bridge.live === null) { box.appendChild(callout('info', 'clock', 'Checking the connection…', 'One moment.')); return; }
      if (!Bridge.live) {
        box.appendChild(callout('info', 'plug', 'Needs the live dashboard (start-dashboard)', [
          el('p', { text: bridgeHint() + ' The buttons on this page only work there.' }),
          el('p', { text: 'Start it by double-clicking start-dashboard.cmd in the project folder, or ask Claude: "start the dashboard".' })
        ]));
        return;
      }
      if (!(Bridge.session && Bridge.session.connected)) {
        box.appendChild(callout('warn', 'plug', 'Claude is not listening yet', [
          el('p', { text: "Ask Claude in your IDE: 'start the dashboard listener'. You can press buttons already: the requests wait in the queue until Claude picks them up." })
        ]));
        return;
      }
      box.appendChild(callout('good', 'checkCircle', 'Claude connected', 'Press a button below and Claude picks it up within a few seconds. Watch your Claude chat: it explains each step there.'));
    }, 'state');
    return box;
  }

  // ================================================================== v3: Checks & permissions (#/checks)
  // Run from the scanner's own folder. bvs.ps1 github-login uses the scanner's separate GitHub CLI and settings folder.
  var GH_LOGIN_CMD = 'pwsh -NoProfile -ExecutionPolicy Bypass -File .\\bvs.ps1 github-login';
  var CHECK_GROUPS = [
    { key: 'ok', statuses: ['ok'], label: 'Ran fully', tone: 'good', icon: 'checkCircle', plain: 'These checks ran and saw everything they needed.' },
    { key: 'partial', statuses: ['partial'], label: 'Partly', tone: 'warn', icon: 'alert', plain: 'These ran but could only see part of what they look at, often because of missing admin rights or short Windows logs.' },
    { key: 'admin', statuses: ['needs_admin'], label: 'Needs your admin rights', tone: 'warn', icon: 'lock', plain: 'Windows only lets an administrator read these. One button runs them all, with 1 Windows Yes/No prompt.' },
    { key: 'login', statuses: ['needs_consent'], label: 'Needs your login', tone: 'info', icon: 'key', plain: 'These wait until you sign in, for example to GitHub. Nothing is read before you do.' },
    { key: 'na', statuses: ['not_applicable'], label: 'Not applicable', tone: 'neutral', icon: 'info', plain: 'Nothing to check on this PC, for example because Firefox is not installed.' },
    { key: 'problems', statuses: ['error', 'skipped'], label: 'Skipped or errors', tone: 'bad', icon: 'xCircle', plain: 'These did not run this time: a check crashed or something it needs was missing. Re-running that area usually helps.' }
  ];
  var LIST_ORDER = ['admin', 'login', 'problems', 'partial', 'na', 'ok'];
  function checkGroupOf(status) { return CHECK_GROUPS.filter(function (g) { return g.statuses.indexOf(status) >= 0; })[0] || CHECK_GROUPS[5]; }
  function allChecks() { return arr((S.coverage || {}).checks).filter(function (c) { return c && c.id; }); }

  function openCheckPanel(c) {
    var g = checkGroupOf(c.status), cs = COVERAGE_STATUS[c.status] || { label: humanize(c.status), plain: '' };
    App.openPanel({
      kind: 'custom', id: 'check-' + c.module + '-' + c.id, title: c.description || humanize(c.id), kicker: 'Check · ' + moduleName(c.module), subtitle: g.label,
      render: function (body) {
        body.appendChild(el('div', { cls: 'chip-row' }, [toneBadge(g.label, g.tone, g.icon), toneBadge(moduleName(c.module), 'neutral', MODULE_ICONS[c.module] || 'dot')]));
        body.appendChild(psection('What it checks', 'search', el('p', { cls: 'p-text', text: c.description || humanize(c.id) })));
        body.appendChild(psection('Result', g.icon, el('div', null, [el('p', { cls: 'p-text' }, [el('strong', { text: cs.label + ': ' }), el('span', { text: cs.plain })]),
          c.reason ? el('p', { cls: 'p-note', text: 'What the check reported: ' + privacy.text(c.reason) }) : null])));
        var todo = el('div', { cls: 'stack' });
        if (c.status === 'needs_admin') {
          todo.appendChild(el('p', { cls: 'p-text', text: 'Run the admin checks: Claude starts a read-only run and Windows asks you once (Yes/No).' }));
          todo.appendChild(signalButton('Run the admin checks now', 'run-admin', {}, { icon: 'lock' }));
        } else if (c.status === 'needs_consent') {
          todo.appendChild(el('p', { cls: 'p-text', text: 'Sign in to GitHub first (step 1 on the Checks page), then ask Claude to run the deep check.' }));
          todo.appendChild(signalButton("I've signed in, run it", 'run-github-check', {}, { icon: 'key' }));
        } else if (c.status !== 'ok' && c.status !== 'not_applicable' && RERUN_RE.test(str(c.module))) {
          todo.appendChild(el('p', { cls: 'p-text', text: 'Ask Claude to run this area again. It refreshes the report afterwards.' }));
          todo.appendChild(signalButton('Re-run ' + moduleName(c.module), 'rerun-module', { module: c.module }, { icon: 'refresh' }));
        } else {
          todo.appendChild(el('p', { cls: 'p-text', text: c.status === 'ok' ? 'Nothing to do: this check ran fully.' : 'Nothing to do: this check does not apply to this PC.' }));
        }
        body.appendChild(psection('What you can do', 'fix', todo));
        var tech = el('details', { cls: 'tech' });
        tech.appendChild(el('summary', null, [icon('code'), el('span', { text: 'Technical details (for experts)' })]));
        tech.appendChild(el('div', { cls: 'tech-body' }, kv([['Check ID', c.id], ['Area', moduleName(c.module) + ' (' + c.module + ')'], ['Status', c.status + (c.statusRaw ? ' (' + c.statusRaw + ')' : '')],
          ['Items found', typeof c.items === 'number' ? U.fmtNum(c.items) : null], ['Time taken', typeof c.ms === 'number' ? (c.ms >= 1000 ? (c.ms / 1000).toFixed(1) + ' s' : c.ms + ' ms') : null]])));
        body.appendChild(tech);
      }
    });
  }

  function checkRow(c) {
    var g = checkGroupOf(c.status);
    var row = el('button', { cls: 'check-row', attrs: bvs('section', 'check-' + c.module + '-' + c.id, c.description || c.id, { type: 'button' }), on: { click: function () { openCheckPanel(c); } } }, [
      el('span', { cls: 'check-dot tone-' + g.tone }, icon(g.icon)),
      el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: c.description || humanize(c.id) }),
        c.reason && c.status !== 'ok' ? el('span', { cls: 'mini-sub', text: short(privacy.text(c.reason), 150) }) : null]),
      icon('chevron')
    ]);
    return row;
  }

  function groupCard(g, checks, open) {
    var byMod = {}, mods = [];
    checks.forEach(function (c) { if (!byMod[c.module]) { byMod[c.module] = []; mods.push(c.module); } byMod[c.module].push(c); });
    mods.sort(function (a, b) { return moduleName(a).localeCompare(moduleName(b)); });
    var body = el('div', { cls: 'check-mods' });
    if (!checks.length) { body.appendChild(el('p', { cls: 'sig-empty', text: 'None.' })); }
    mods.forEach(function (m) {
      var d = el('details', { cls: 'check-mod' });
      if (open) { d.open = true; }
      d.appendChild(el('summary', null, [el('span', { cls: 'check-mod-ico' }, icon(MODULE_ICONS[m] || 'dot')), el('span', { cls: 'check-mod-name', text: moduleName(m) }),
        el('span', { cls: 'chip-count', text: String(byMod[m].length) })]));
      var list = el('div', { cls: 'check-list' });
      byMod[m].forEach(function (c) { list.appendChild(checkRow(c)); });
      d.appendChild(list);
      body.appendChild(d);
    });
    var c = card({ title: g.label + ' (' + checks.length + ')', icon: g.icon, section: 'checks-group-' + g.key, cls: 'check-group tone-' + g.tone, sub: g.plain }, body);
    c.id = 'checks-group-' + g.key;
    return c;
  }

  function adminActionCard(n) {
    var c = el('section', { cls: 'card action-card tone-warn', attrs: { 'data-bvs-section': 'action-admin' } }, [
      el('div', { cls: 'action-head' }, [el('span', { cls: 'action-ico' }, icon('lock')), el('div', null, [
        el('h2', { cls: 'action-title', text: 'Run the admin checks now' }),
        el('p', { cls: 'action-sub', text: '1 Windows Yes/No prompt · fills in ' + n + ' ' + plural(n, 'check', 'checks') })
      ])]),
      el('ol', { cls: 'action-steps' }, [
        el('li', { text: 'Press the button. Claude shows you the admin script and its fingerprint in the chat.' }),
        el('li', { text: 'Windows asks "Do you want to allow this app to make changes to your device?". Click Yes.' }),
        el('li', { text: 'The checks only read (for example the Windows Security log). They change nothing. The report refreshes when they finish.' })
      ]),
      el('div', { cls: 'action-foot' }, [signalButton('Run the admin checks now: 1 Windows Yes/No prompt', 'run-admin', {}, { icon: 'lock', cls: 'primary big' })])
    ]);
    return c;
  }

  function githubActionCard(n) {
    var copyStatus = el('span', { cls: 'copy-status', attrs: { 'aria-live': 'polite' } });
    var code = el('code', { cls: 'cmd-text', text: GH_LOGIN_CMD });
    var copyBtn = button('Copy the sign-in command', function () {
      U.copyText(GH_LOGIN_CMD).then(function (ok) {
        if (ok) { copyStatus.textContent = 'Copied. Paste it into PowerShell and press Enter.'; return; }
        try { var r = document.createRange(); r.selectNodeContents(code); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r); } catch (e) { /* ignore */ }
        copyStatus.textContent = 'Copy is not available here: the command is selected, press Ctrl+C.';
      });
    }, { cls: 'small', icon: 'copy' });
    return el('section', { cls: 'card action-card tone-info', attrs: { 'data-bvs-section': 'action-github' } }, [
      el('div', { cls: 'action-head' }, [el('span', { cls: 'action-ico' }, icon('key')), el('div', null, [
        el('h2', { cls: 'action-title', text: 'GitHub deep check' }),
        el('p', { cls: 'action-sub', text: 'Needs your GitHub login · ' + n + ' ' + plural(n, 'check', 'checks') + ' waiting · the scanner only reads' })
      ])]),
      el('div', { cls: 'gh-step' }, [el('span', { cls: 'gh-num', text: '1' }), el('div', { cls: 'gh-body' }, [
        el('strong', { text: 'Sign in to GitHub (once)' }),
        el('p', { text: 'Open PowerShell in the scanner folder (the one that contains bvs.ps1), paste this command and press Enter. Your browser opens: sign in and approve. GitHub CLI asks for its standard access plus read access to keys, hooks, profile and e-mail. The scanner itself only sends read requests, and "bvs.ps1 github-logout" signs you out again.' }),
        el('pre', { cls: 'cmd-box' }, code),
        el('div', { cls: 'card-actions' }, [copyBtn, copyStatus])
      ])]),
      el('div', { cls: 'gh-step' }, [el('span', { cls: 'gh-num', text: '2' }), el('div', { cls: 'gh-body' }, [
        el('strong', { text: 'Tell Claude to run it' }),
        el('p', { text: 'After signing in, press the button. If GitHub is not signed in yet, Claude tells you in the chat what is missing.' }),
        signalButton("I've signed in, run it", 'run-github-check', {}, { icon: 'send', cls: 'primary big' })
      ])])
    ]);
  }

  function modulesCard(checks) {
    var mods = arr((S.coverage || {}).modules);
    var grid = el('div', { cls: 'mod-rerun-list' });
    mods.forEach(function (m) {
      var mine = checks.filter(function (c) { return c.module === m.module; });
      var counts = {};
      mine.forEach(function (c) { var g = checkGroupOf(c.status); counts[g.key] = (counts[g.key] || 0) + 1; });
      var chips = el('span', { cls: 'chip-row' });
      CHECK_GROUPS.forEach(function (g) { if (counts[g.key] && g.key !== 'ok') { chips.appendChild(toneBadge(counts[g.key] + ' ' + g.label.toLowerCase(), g.tone)); } });
      var took = '';
      var a = U.toDate(m.started), b = U.toDate(m.finished);
      if (a && b && b > a) { var sec = Math.round((b - a) / 1000); took = 'Took ' + (sec >= 90 ? Math.round(sec / 60) + ' min' : sec + ' s') + ' last time'; }
      grid.appendChild(el('div', { cls: 'mod-rerun', attrs: bvs('section', 'module-' + m.module, moduleName(m.module)) }, [
        el('span', { cls: 'mt-ico' }, icon(MODULE_ICONS[m.module] || 'dot')),
        el('span', { cls: 'mini-main' }, [el('span', { cls: 'mini-title', text: moduleName(m.module) }),
          el('span', { cls: 'mini-sub', text: (counts.ok || 0) + ' of ' + mine.length + ' checks ran fully' + (took ? ' · ' + took : '') }), chips]),
        RERUN_RE.test(str(m.module)) ? signalButton('Re-run', 'rerun-module', { module: m.module }, { icon: 'refresh', cls: 'small', activeLabel: 'Requested' }) : null
      ]));
    });
    var refresh = signalButton('Refresh report', 'refresh-report', {}, { icon: 'refresh', cls: 'small', activeLabel: 'Refresh requested' });
    return card({ title: 'Areas', icon: 'shield', section: 'checks-modules', sub: 'Re-run one area if it had errors or you changed something. Claude refreshes the report afterwards; "Refresh report" only rebuilds this page from the saved results.', aside: refresh }, grid);
  }

  var checksView = {
    title: 'Checks & permissions', icon: 'key', group: 'main', parent: 'security', nav: false, accent: 'var(--acc-security)',
    mount: function (root, params) {
      var checks = allChecks(), want = str(params.query.group);
      root.appendChild(pageHead('key', 'Checks & permissions', 'Every check the scan ran, grouped by result. Some could not run without your permission: press a button and Claude runs them for you. Anything that would change your PC is always asked in your Claude chat first.'));
      root.appendChild(subNav('checks'));
      root.appendChild(bridgeNotice());
      var groups = {};
      CHECK_GROUPS.forEach(function (g) { groups[g.key] = checks.filter(function (c) { return g.statuses.indexOf(c.status) >= 0; }); });
      var tiles = el('div', { cls: 'check-tiles', attrs: { 'data-bvs-section': 'checks-summary' } });
      CHECK_GROUPS.forEach(function (g) {
        tiles.appendChild(link('#/checks?group=' + g.key, { cls: 'check-tile tone-' + g.tone + (want === g.key ? ' is-current' : ''), attrs: bvs('tile', 'checks-' + g.key, g.label + ': ' + groups[g.key].length) }, [
          el('span', { cls: 'check-tile-top' }, [icon(g.icon), el('span', { cls: 'check-tile-num', text: String(groups[g.key].length) })]),
          el('span', { cls: 'check-tile-label', text: g.label })
        ]));
      });
      root.appendChild(tiles);
      if (!checks.length) { root.appendChild(emptyState('This scan has no list of checks.', 'info')); return; }
      var actions = el('div', { cls: 'action-grid', attrs: { 'data-bvs-section': 'checks-actions' } });
      if (groups.admin.length) { actions.appendChild(adminActionCard(groups.admin.length)); }
      if (groups.login.length) { actions.appendChild(githubActionCard(groups.login.length)); }
      if (actions.firstChild) {
        root.appendChild(sectionHeading('Fill in the missing checks', 'Each button sends a request to your Claude session. Claude explains every step in the chat.'));
        root.appendChild(actions);
      }
      root.appendChild(trackerCard());
      root.appendChild(sectionHeading('All checks by result', 'Click any check to see what it does and why it ended up here.'));
      LIST_ORDER.forEach(function (k) {
        var g = CHECK_GROUPS.filter(function (x) { return x.key === k; })[0];
        if (!groups[k].length && k !== want) { return; }
        root.appendChild(groupCard(g, groups[k], k !== 'ok' && k !== 'na' ? true : want === k));
      });
      root.appendChild(modulesCard(checks));
      root.appendChild(el('p', { cls: 'p-more' }, [goLink('#/coverage', 'See how far back the Windows logs go, and what no scan can prove')]));
      if (want) {
        var target = document.getElementById('checks-group-' + want);
        if (target) { setTimeout(function () { target.classList.add('is-flash'); target.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' }); }, 40); }
      }
    }
  };

  // ================================================================== v3: deletion request (double confirmation)
  // Step 1 (here): the exact list + the user types "I confirm" -> POST /api/signal delete-request.
  // Step 2 (Claude chat): the user types "I confirm <CODE>". The code lives only in this page's memory.
  var CONFIRM_PHRASE = 'I confirm';
  var deleteRequests = []; // {id, code, count, bytes, ids[], createdAt, demo}
  var METHOD_LABEL = { recycle: 'Recycle Bin', recyclebin: 'Recycle Bin', holding: 'Holding folder (same drive)', uninstall: "Program's own uninstaller", uninstaller: "Program's own uninstaller", tool: "The app's own tool" };
  function methodLabel(m) { return METHOD_LABEL[str(m).toLowerCase()] || humanize(m) || 'Recycle Bin'; }
  function fmtCode(code) {
    var c = str(code).toUpperCase().replace(/[^A-Z0-9]/g, '');
    return c.length === 8 ? c.slice(0, 4) + '-' + c.slice(4) : c;
  }
  function codeCard(req) {
    var line = CONFIRM_PHRASE + ' ' + fmtCode(req.code);
    var status = el('span', { cls: 'copy-status', attrs: { 'aria-live': 'polite' } });
    var codeEl = el('code', { cls: 'code-line-text', text: line });
    var tracker = signalTracker({ filter: function (s) { return s.id === req.id; }, empty: req.demo ? 'Demo: progress appears here.' : 'Waiting for the first update…', limit: 1 });
    return el('section', { cls: 'code-card', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'delete-code', 'data-bvs-label': 'Step 2: confirm in your Claude chat' } }, [
      el('p', { cls: 'code-kicker', text: 'Step 2 of 2' + (req.demo ? ' · demo' : '') }),
      el('h3', { cls: 'code-title', text: 'Step 2: type this in your Claude chat:' }),
      el('div', { cls: 'code-line' }, [codeEl, button('Copy', function () {
        U.copyText(line).then(function (ok) {
          if (ok) { status.textContent = 'Copied. Paste it into your Claude chat when Claude shows the final list.'; return; }
          try { var r = document.createRange(); r.selectNodeContents(codeEl); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r); } catch (e) { /* ignore */ }
          status.textContent = 'Copy is not available here: the line is selected, press Ctrl+C.';
        });
      }, { cls: 'small', icon: 'copy' })]),
      status,
      callout('warn', 'hand', 'Claude will never type this for you; it only works when you type it.', 'Claude first re-checks every item live and shows you the final list in the chat. Only then, if you agree, type the line above. Changed your mind? Do nothing: the request expires after 60 minutes.'),
      el('p', { cls: 'p-note', text: req.count + ' ' + plural(req.count, 'item', 'items') + ' · ' + U.fmtBytes(req.bytes) + '. This code is kept only in this page\'s memory: it is gone if you reload, and then you simply request again.' }),
      tracker
    ]);
  }
  function openDeleteModal(items, opts) {
    opts = opts || {};
    // The same file can sit in two lists (for example "big" and "old"): one request lists each path once.
    var seenPaths = {}, merged = 0;
    items = arr(items).filter(function (it) {
      var k = str(it.path).toLowerCase();
      if (!k) { return true; }
      if (seenPaths[k]) { merged++; return false; }
      seenPaths[k] = true;
      return true;
    });
    var tooMany = items.length > 200;
    var total = items.reduce(function (n, it) { return n + (typeof it.bytes === 'number' ? it.bytes : 0); }, 0);
    var input, hint, errBox, sending = false;
    function step2(api, req) {
      api.setTitle('Confirm in your Claude chat', 'Request deletion · step 2 of 2');
      U.clear(api.body);
      api.body.appendChild(callout('good', 'checkCircle', 'Step 1 done: your request was sent to Claude', 'Nothing has been deleted. Claude now re-checks every item.'));
      api.body.appendChild(codeCard(req));
      api.setActions([{ label: 'Close (the Basket page keeps showing this)', primary: true, onClick: function (a) { a.close('done'); } }]);
    }
    var m = App.modal({
      kicker: 'Request deletion · step 1 of 2', title: 'Check the list, then type "I confirm"', icon: 'trash', cls: 'del-modal', section: 'delete-request',
      render: function (body) {
        if (opts.demo) { body.appendChild(callout('info', 'info', 'Demo', 'Sample items only: nothing is sent from this demo.')); }
        var steps = el('div', { cls: 'del-steps' }, [
          el('div', { cls: 'del-step is-now' }, [el('span', { cls: 'gh-num', text: '1' }), el('div', null, [el('strong', { text: 'Here, now' }),
            el('p', { text: 'Check the list and type I confirm. This only sends a request: nothing is deleted yet.' })])]),
          el('div', { cls: 'del-step' }, [el('span', { cls: 'gh-num', text: '2' }), el('div', null, [el('strong', { text: 'In your Claude chat' }),
            el('p', { text: 'Claude re-checks every item live and shows the final list. Only when you type "I confirm" plus the code shown next does anything happen.' })])])
        ]);
        body.appendChild(steps);
        body.appendChild(el('p', { cls: 'del-summary' }, [el('strong', { text: items.length + ' ' + plural(items.length, 'item', 'items') }), el('span', { text: ' · ' + U.fmtBytes(total) + ' in total' }),
          merged ? el('span', { cls: 'muted', text: ' · ' + merged + ' ' + plural(merged, 'entry was', 'entries were') + ' the same file as another one and ' + plural(merged, 'was', 'were') + ' merged' }) : null]));
        var wrap = el('div', { cls: 'table-wrap del-table-wrap' });
        var t = el('table', { cls: 'simple del-table' });
        t.appendChild(el('thead', null, el('tr', null, ['Name', 'Where', 'Size', 'How'].map(function (h, i) { return el('th', { text: h, cls: i === 2 ? 'num' : '', attrs: { scope: 'col' } }); }))));
        var tb = el('tbody');
        items.forEach(function (it) {
          tb.appendChild(el('tr', null, [el('td', { cls: 'del-name', text: it.label || fileName(it.path) }), el('td', { cls: 'break del-path', text: it.path }),
            el('td', { cls: 'num nowrap', text: U.fmtBytes(it.bytes) }), el('td', { cls: 'nowrap', text: methodLabel(it.method) })]));
        });
        t.appendChild(tb);
        wrap.appendChild(t);
        body.appendChild(wrap);
        body.appendChild(el('p', { cls: 'p-note', text: 'Real names are shown here, even in privacy mode, so you can check exactly what would be removed. Items go to the Recycle Bin when they fit, otherwise to a holding folder on the same drive; programs use their own uninstaller. Protected places (Windows, Program Files, your main folders) are always refused.' }));
        if (tooMany) { body.appendChild(callout('bad', 'alert', 'Too many items', 'One request can hold at most 200 items. Remove ' + (items.length - 200) + ' from the basket and try again.')); }
        input = el('input', { cls: 'confirm-input', attrs: { type: 'text', autocomplete: 'off', spellcheck: 'false', 'aria-describedby': 'del-confirm-hint', placeholder: 'Type: I confirm' } });
        input.maxLength = 40;
        hint = el('p', { cls: 'confirm-hint', attrs: { id: 'del-confirm-hint' }, text: 'Type the two words exactly, with a capital I: I confirm' });
        body.appendChild(el('label', { cls: 'confirm-box' }, [el('span', { cls: 'confirm-label', text: 'To send the request, type exactly: I confirm' }), input, hint]));
        errBox = el('div', { cls: 'del-error', attrs: { 'aria-live': 'assertive' } });
        body.appendChild(errBox);
        input.addEventListener('input', sync);
        input.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); send(); } });
      },
      actions: [
        { label: 'Cancel', onClick: function (api) { api.close('cancel'); } },
        { label: 'Send deletion request', id: 'send', primary: true, icon: 'send', disabled: true, onClick: function () { send(); } }
      ]
    });
    var sendBtn = m.buttons.send;
    function canSend() { return input && input.value === CONFIRM_PHRASE && !tooMany && items.length > 0 && !sending && (opts.demo || Bridge.live); }
    function sync() {
      var v = input.value, ok = v === CONFIRM_PHRASE;
      input.classList.toggle('is-ok', ok);
      input.classList.toggle('is-near', !ok && v.trim().toLowerCase() === 'i confirm');
      hint.textContent = ok ? 'Matches. You can send the request now.' : v.trim().toLowerCase() === 'i confirm' ? 'Almost: it must be exactly "I confirm" (capital I, one space, nothing else).' : 'Type the two words exactly, with a capital I: I confirm';
      if (sendBtn) { sendBtn.disabled = !canSend(); }
      if (!Bridge.live && !opts.demo) { errBox.textContent = bridgeHint(); }
    }
    function send() {
      if (!canSend()) { sync(); return; }
      sending = true;
      sync();
      errBox.textContent = '';
      var sl = sendBtn && sendBtn.querySelector('span');
      if (sl) { sl.textContent = 'Sending…'; }
      if (opts.demo) {
        var dreq = { id: 'demo-' + Date.now(), code: 'K7Q2M9XP', count: items.length, bytes: total, ids: [], createdAt: new Date().toISOString(), demo: true };
        step2(m, dreq);
        return;
      }
      var payload = { items: items.map(function (it) { return { id: str(it.id), path: str(it.path), bytes: typeof it.bytes === 'number' && isFinite(it.bytes) && it.bytes >= 0 ? Math.round(it.bytes) : null, method: str(it.method || 'recycle'), label: U.safeText(it.label).slice(0, 300) }; }) };
      App.bridge.send('delete-request', payload, { typedConfirmation: input.value }).then(function (res) {
        sending = false;
        if (sl) { sl.textContent = 'Send deletion request'; }
        if (res.ok && res.code) {
          var req = { id: res.id, code: res.code, count: items.length, bytes: total, ids: items.map(function (it) { return it.id; }), createdAt: new Date().toISOString() };
          deleteRequests.unshift(req);
          refreshLive('signals');
          step2(m, req);
        } else if (res.ok) {
          errBox.textContent = 'The request was sent, but the server did not return a confirmation code. Ask Claude in the chat what to do next.';
        } else {
          errBox.textContent = res.message || 'The request could not be sent.';
          sync();
        }
      });
    }
    if (opts.demoStep2) {
      step2(m, { id: 'demo', code: 'K7Q2M9XP', count: items.length, bytes: total, ids: [], createdAt: new Date().toISOString(), demo: true });
    } else {
      sync();
    }
    return m;
  }
  // Other views may open the same dialog; the user still has to type both confirmations.
  App.requestDeletion = function (items, opts) { return openDeleteModal(items, opts && opts.demo ? { demo: true } : {}); };
  function deletionCard() {
    var box = el('div', { cls: 'stack' });
    liveWidget(box, function () {
      U.clear(box);
      var shown = deleteRequests.filter(function (r) {
        var s = allSignals().filter(function (x) { return x.id === r.id; })[0];
        return !s || ACTIVE_STATES[s.state] || s.state === 'done';
      });
      if (!shown.length) {
        box.appendChild(el('p', { cls: 'sig-empty', text: 'No open deletion request from this page. After you press "Request deletion", the step 2 code and the progress appear here.' }));
      }
      shown.forEach(function (r) {
        var s = allSignals().filter(function (x) { return x.id === r.id; })[0];
        if (s && s.state === 'done') {
          box.appendChild(callout('good', 'checkCircle', 'Deletion request finished', [
            el('p', { text: 'Claude reported it as done. Check your Claude chat for the details; everything is logged in logs\\deletions.jsonl.' }),
            button('Take these items out of the basket', function () { r.ids.forEach(function (id) { if (S.basket) { S.basket.remove(id); } }); deleteRequests = deleteRequests.filter(function (x) { return x !== r; }); refreshLive('signals'); }, { cls: 'small', icon: 'basket' })
          ]));
        } else {
          box.appendChild(codeCard(r));
        }
      });
      var others = allSignals().filter(function (s) { return s.type === 'delete-request' && !deleteRequests.some(function (r) { return r.id === s.id; }); });
      if (others.length) {
        box.appendChild(el('h3', { cls: 'p-h' }, [icon('history'), el('span', { text: 'Earlier deletion requests' })]));
        var ul = el('ul', { cls: 'sig-list', attrs: { role: 'list' } });
        others.slice(0, 5).forEach(function (s) { ul.appendChild(signalRow(s)); });
        box.appendChild(ul);
      }
    }, 'all');
    setTimeout(pollSignals, 50);
    return card({ title: 'Deletion requests', icon: 'trash', section: 'delete-requests', sub: 'Two confirmations, both typed by you: "I confirm" here, then "I confirm" + code in your Claude chat.' }, box);
  }

  // ================================================================== v3: Privacy & AI (#/privacy)
  function bulletList(items, iconName) {
    var ul = el('ul', { cls: 'tick-list' + (iconName ? '' : ' plain') });
    items.forEach(function (t) { ul.appendChild(el('li', null, [icon(iconName || 'dot'), el('span', { text: t })])); });
    return ul;
  }
  function privacySwitch() {
    var b = el('button', { cls: 'switch big-switch', attrs: { type: 'button', 'data-bvs-type': 'tile', 'data-bvs-id': 'privacy-mode-switch', 'data-bvs-label': 'Privacy mode' }, on: { click: function () { privacy.toggle(); } } },
      [el('span', { cls: 'switch-track', attrs: { 'aria-hidden': 'true' } }, el('span', { cls: 'switch-knob' })), el('span', { text: 'Privacy mode' })]);
    b.setAttribute('aria-pressed', String(privacy.on));
    return b;
  }
  function consentControl() {
    var box = el('div', { cls: 'stack' });
    liveWidget(box, function () {
      U.clear(box);
      var rec = App.aiConsent.record(), c = App.aiConsent.get();
      if (c === 'yes') {
        box.appendChild(callout('good', 'checkCircle', 'AI answers are allowed', 'Since ' + (rec && rec.at ? fmtWhen(rec.at) : 'this visit') + '. Questions you ask INFOSEC or the scanner go to Claude, with personal names hidden first.'));
        box.appendChild(el('div', { cls: 'card-actions' }, [button('Withdraw consent: offline answers only', function () { App.aiConsent.set('no'); App.toast('Done. INFOSEC now answers offline only; nothing is sent to Claude.', 'good', 'lock'); }, { cls: '', icon: 'lock' })]));
      } else if (c === 'no') {
        box.appendChild(callout('info', 'lock', 'Offline answers only', 'Nothing is sent to Claude. INFOSEC and the scanner use their built-in explanations.' + (rec && rec.at ? ' Chosen ' + fmtWhen(rec.at) + '.' : '')));
        box.appendChild(el('div', { cls: 'card-actions' }, [button('Allow AI answers', function () { App.aiConsent.set('yes'); }, { cls: 'primary', icon: 'check' }), button('Ask me next time', function () { App.aiConsent.set(null); }, { cls: 'ghost small' })]));
      } else {
        box.appendChild(callout('neutral', 'question', 'Not decided yet', 'You will be asked the first time INFOSEC could use Claude. Until then nothing is sent.'));
        box.appendChild(el('div', { cls: 'card-actions' }, [button('Allow AI answers', function () { App.aiConsent.set('yes'); }, { cls: 'primary', icon: 'check' }), button('Only offline answers', function () { App.aiConsent.set('no'); }, { icon: 'lock' })]));
      }
    }, 'state');
    return box;
  }
  var privacyView = {
    title: 'Privacy & AI', icon: 'lock', group: 'tools', accent: 'var(--acc-privacy)',
    mount: function (root) {
      root.appendChild(pageHead('lock', 'Privacy & AI', 'What this tool looks at, what it never touches, where your data stays and when AI is used. In short: it checks your PC\'s settings, not your private life.'));
      var controls = el('div', { cls: 'two-col', attrs: { 'data-bvs-section': 'privacy-controls' } });
      controls.appendChild(card({ title: 'Privacy mode', icon: privacy.on ? 'eyeOff' : 'eye', section: 'privacy-mode', aside: privacySwitch() }, [
        el('p', { cls: 'card-text', text: privacy.on ? 'On: the names of your personal files and folders (Documents, Desktop, Downloads, Pictures, Videos, Music, OneDrive) are hidden on screen, for example "[personal file · .pdf]". Good for screenshots and screen sharing.' :
          'Off: personal file and folder names are visible. Switch it on before you share your screen.' }),
        el('p', { cls: 'p-note', text: 'You can still see one real name at a time: open the item and press "Show name" in its side panel.' })
      ]));
      controls.appendChild(card({ title: 'AI answers (INFOSEC)', icon: 'infosec', section: 'privacy-ai-consent' }, consentControl()));
      root.appendChild(controls);

      var grid = el('div', { cls: 'privacy-grid', attrs: { 'data-bvs-section': 'privacy-sections' } });
      grid.appendChild(card({ title: 'What this tool checks', icon: 'search', section: 'privacy-checks' }, [
        bulletList(['Technical settings: firewall, antivirus, accounts, updates, network.', 'Programs: what is installed, what starts with Windows, what is running.',
          'File details: name, size, date and digital signature. Not what is inside.', 'Security logs: what happened on the PC and when.'], 'check'),
        el('p', { cls: 'p-note', text: 'A few security checks read masked snippets, for example a command-history line that looks like an attack, or a password lying around in plain text (shown as npm_…a1b2, never the full value).' })
      ]));
      grid.appendChild(card({ title: 'What it never reads', icon: 'eyeOff', section: 'privacy-never' }, bulletList([
        'Browser history, cookies and saved passwords.', 'Your e-mails and messages.', 'What is inside your documents, photos, videos and music.',
        'Private keys and password stores (only "is this key protected?" is checked).', 'Wi-Fi passwords.'], 'xCircle')));
      grid.appendChild(card({ title: 'Where your data lives', icon: 'disk', section: 'privacy-where' }, [
        el('p', { cls: 'card-text', text: 'Only on this PC, in the project\'s data folder (baby-virus-scanner\\data\\<scan>). No account, no tracking. The dashboard runs only on 127.0.0.1, so no other computer can open it.' }),
        el('p', { cls: 'card-text', text: 'Nothing is uploaded, except:' }),
        bulletList(['During a scan: package names and versions, extension IDs and your GitHub/npm user name go to public security databases. Never file contents, paths or fingerprints.',
          'When you ask INFOSEC (and allowed it): see "What goes to AI".', 'GitHub deep check: read-only requests to GitHub, only after you sign in.'])
      ]));
      grid.appendChild(card({ title: 'What goes to AI, and when', icon: 'infosec', section: 'privacy-ai' }, [
        el('p', { cls: 'card-text', text: 'Only when you ask INFOSEC or use the scanner, and only after you said yes.' }),
        bulletList(['Sent: your question, the text you selected and the findings it is about.', 'Hidden first: your Windows user name becomes <user>, personal file names become [personal file .ext].',
          'Sent through your own Claude Code login to Anthropic (USA), under your account\'s terms.'])
      ]));
      grid.appendChild(card({ title: 'How long it is kept', icon: 'clock', section: 'privacy-retention' }, [
        bulletList(['Scan results: until you delete them. Keeping the latest 2–3 scans is plenty.', 'In this browser: the basket and your answers stay until you clear them; the INFOSEC chat is gone when you close the tab.',
          'Deletion codes are never stored anywhere.']),
        el('p', { cls: 'card-text' }, [el('strong', { text: 'To delete scan data: ' }), el('span', { text: 'put it in the Basket, press "Request deletion", type I confirm, then type the code in your Claude chat.' })]),
        el('div', { cls: 'card-actions' }, [goLink('#/basket', 'Open the Basket')])
      ]));
      grid.appendChild(card({ title: 'Your rights', icon: 'users', section: 'privacy-rights' }, [
        bulletList(['See and take your data: everything is plain files in the data folder.', 'Delete it: through the Basket, with the double confirmation.',
          'Say no to AI at any time: the switch above, or start the server with --no-ai.', 'Less data by default: privacy mode starts switched on.',
          'For anything sent to Claude: Anthropic\'s privacy policy and your Claude account settings apply.'], 'check'),
        el('p', { cls: 'p-note', text: 'On your own PC this is personal use (GDPR household exemption). In an organisation, the organisation is responsible: see docs\\PRIVACY.md.' })
      ]));
      grid.appendChild(card({ title: 'AI transparency', icon: 'bot', section: 'privacy-ai-act', cls: 'span-2' }, [
        el('p', { cls: 'card-text', text: 'INFOSEC is an AI system: Claude, made by Anthropic. When you chat with INFOSEC you are talking to an AI, not a person, and its answers are labelled "AI-generated (Claude)".' }),
        bulletList(['Answers can be wrong. Double-check important steps.', 'It never acts by itself: it only explains.',
          'Changes to your PC happen only through Claude Code in your chat, after you type the confirmation yourself. Deletions need two: "I confirm" here, then "I confirm" + code in the chat.'], 'info')
      ]));
      root.appendChild(grid);
      root.appendChild(el('p', { cls: 'p-note privacy-foot', text: 'Full details: docs\\PRIVACY.md in the project folder. This page summarises it.' }));
    }
  };

  // ================================================================== views: Basket, placeholders
  var basketView = {
    title: 'Basket', icon: 'basket', group: 'tools', accent: 'var(--acc-basket)',
    mount: function (root) {
      root.appendChild(pageHead('basket', 'Clean-up basket', 'Collect things you want to remove. This page never deletes anything: it sends a request to Claude, and nothing happens until you confirm twice, once here and once in your Claude chat.'));
      root.appendChild(bridgeNotice());
      var inner = el('div', { cls: 'basket-host', attrs: { 'data-bvs-section': 'basket' } });
      root.appendChild(inner);
      if (!S.basket) { inner.appendChild(emptyState('The basket is not available.', 'basket')); return; }
      var view = new window.BVSUI.BasketView(inner, S.basket, {
        scanId: S.scanId, findItem: function (id) { return S.itemsById.get(id) || null; }, onOpen: function (it) { openItemPanel(it); },
        privacy: privacy, maxItems: 200,
        live: function () { return Bridge.live === true; }, liveHint: bridgeHint,
        onRequestDeletion: function (list) { openDeleteModal(list); }
      });
      liveWidget(inner, function () { if (view && typeof view.render === 'function' && view.renderedLive !== Bridge.live) { view.render(); } }, 'state');
      root.appendChild(deletionCard());
    }
  };

  var PLACEHOLDERS = {
    storage: {
      title: 'Storage', icon: 'storage', group: 'main', accent: 'var(--acc-storage)', placeholder: true,
      mount: function (root) {
        root.appendChild(pageHead('storage', 'Storage', 'Where your disk space goes and what can be cleaned safely.'));
        root.appendChild(callout('info', 'info', 'The interactive storage map is not available in this copy', 'Its file (storage-view.js) did not load. Here is a short summary instead; every row still opens the details.'));
        var ss = storageSummary();
        root.appendChild(card({ title: 'At a glance', icon: 'storage', section: 'storage-glance' }, storageBars(ss)));
        var top = items('storage').filter(function (it) { return it.safety === 'safe' || it.safety === 'safe_after_check'; }).sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0); }).slice(0, 15);
        root.appendChild(card({ title: 'Biggest things that are safe to clean', icon: 'trash', section: 'storage-top', sub: 'Add them to the basket from their details panel.' },
          top.length ? itemRows(top, function (it) { return U.fmtBytes(it.bytes) + ' · ' + (it.purpose || humanize(it.category)); }) : emptyState('Nothing found.', 'checkCircle')));
      }
    },
    infosec: {
      title: 'INFOSEC', icon: 'infosec', group: 'tools', accent: '#F5C518', placeholder: true,
      mount: function (root) {
        root.appendChild(pageHead('infosec', 'INFOSEC assistant', 'Your security helper that explains findings in simple words.'));
        root.appendChild(callout('warn', 'info', 'INFOSEC is not installed in this copy', 'Its file (infosec.js) did not load. You can still open any item for a plain-English explanation, or paste your question into Claude Code.'));
        var pend = App.pendingInfosec;
        if (pend && (pend.prefill || pend.context)) {
          var ctx = pend.context || {};
          root.appendChild(card({ title: 'Your question', icon: 'question', section: 'infosec-question' }, [
            el('p', { cls: 'card-lead', text: str(pend.prefill) }),
            el('p', { cls: 'card-text', text: offlineAnswer(pend.prefill, ctx) }),
            ctx.kind === 'finding' && ctx.id ? el('div', { cls: 'card-actions' }, [goLink('#/finding/' + encodeURIComponent(ctx.id), 'Back to the finding')]) : null
          ]));
        }
      }
    }
  };

  PLACEHOLDERS.agents = {
    title: 'Agent map', icon: 'bot', group: 'tools', accent: '#4B1D6B', placeholder: true,
    mount: function (root) {
      root.appendChild(pageHead('bot', 'Agent map', 'Which AI agents built this scan and dashboard, and how hard each job was.'));
      root.appendChild(callout('info', 'info', 'The agent map is not available in this copy', 'Its file (agents-view.js) did not load. Reloading the page usually fixes this.'));
    }
  };

  var NOT_FOUND = {
    title: 'Not found', icon: 'question',
    mount: function (root) {
      root.appendChild(pageHead('question', 'Page not found', 'This link does not lead anywhere in the dashboard.'));
      root.appendChild(el('div', { cls: 'card-actions' }, [goLink('#/overview', 'Go to the overview')]));
    }
  };

  // register UI-A's own views (UI-B / UI-C register theirs from their own files)
  App.registerView('overview', overviewView);
  App.registerView('security', makeSecurityView());
  App.registerView('questions', questionsView);
  App.registerView('suspicious', suspiciousView);
  App.registerView('why', whyView);
  App.registerView('fixes', fixesView);
  App.registerView('performance', performanceView);
  App.registerView('health', healthView);
  App.registerView('coverage', coverageView);
  App.registerView('basket', basketView);
  App.registerView('checks', checksView);
  App.registerView('privacy', privacyView);

  // ================================================================== boot
  function pickScan() {
    var q = null;
    try { q = new URLSearchParams(window.location.search).get('scan'); } catch (e) { q = null; }
    if (q && ID_RE.test(q)) { return q; }
    var latest = window.BVS_LATEST;
    return typeof latest === 'string' && ID_RE.test(latest) ? latest : null;
  }

  function bootError(title, lines) {
    var msg = $('boot-message');
    U.clear(msg);
    msg.hidden = false;
    var c = card({ title: title, icon: 'alert' });
    var ul = el('ul', { cls: 'tick-list plain' });
    lines.forEach(function (l) { ul.appendChild(el('li', null, [icon('dot'), el('code', { text: l })])); });
    c.appendChild(ul);
    msg.appendChild(c);
    $('scan-info').textContent = 'No data loaded';
  }

  function initPanelChrome() {
    var p = P();
    if (!p.root) { return; }
    p.close.appendChild(icon('close'));
    p.back.appendChild(icon('back'));
    p.close.addEventListener('click', function () { App.closePanel(); });
    p.back.addEventListener('click', panelBack);
    p.backdrop.addEventListener('click', function () { App.closePanel(); });
    p.body.addEventListener('click', function (ev) {
      var a = ev.target.closest('a[href^="#/"]');
      if (a) { App.closePanel({ navigate: false }); }
    });
    p.root.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Tab' || !panel.open) { return; }
      var f = Array.prototype.filter.call(p.root.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, summary, [tabindex]:not([tabindex="-1"])'), function (n) { return n.offsetParent !== null; });
      if (!f.length) { return; }
      var first = f[0], last = f[f.length - 1];
      if (ev.shiftKey && (document.activeElement === first || document.activeElement === p.title)) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Escape') { return; }
      if (panel.open) { ev.preventDefault(); App.closePanel(); }
      else if (document.body.classList.contains('side-open') && App._closeMobileNav) { App._closeMobileNav(); }
    });
  }

  function initTopbarExtras() {
    var pb = $('bvs-privacy-toggle');
    if (pb) { syncPrivacyButton(); pb.addEventListener('click', function () { privacy.toggle(); }); }
    var sp = $('bvs-session-pill');
    if (sp) { syncSessionPill(); sp.addEventListener('click', openSessionPanel); }
    document.addEventListener('visibilitychange', function () { if (!document.hidden && S.ready) { pollSession().then(function () { if (hasLiveTrackers()) { pollSignals(); } }); } });
  }

  // Demo flags for headless screenshots only (?demo=consent | delete | delete-code | signals). They only
  // show UI: nothing is stored, sent or added to the basket.
  function runDemo() {
    var d = null;
    try { d = new URLSearchParams(window.location.search).get('demo'); } catch (e) { d = null; }
    if (!d) { return; }
    var sample = function () {
      return items('storage').filter(function (it) { return S.basket && S.basket.canAdd(it) && it.path; }).sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0); }).slice(0, 4);
    };
    if (d === 'consent') { App.aiConsent.open(); }
    else if (d === 'delete') { openDeleteModal(sample(), { demo: true }); }
    else if (d === 'delete-code') { openDeleteModal(sample(), { demo: true, demoStep2: true }); }
    else if (d === 'signals') {
      Bridge.demo = true;
      var now = Date.now();
      [['run-admin', 'awaiting-chat-confirmation', 'Claude showed the admin script fingerprint in the chat', {}, 2],
        ['rerun-module', 'running', 'Collecting', { module: 'S07' }, 5], ['run-github-check', 'queued', '', {}, 1],
        ['refresh-report', 'done', 'Report rebuilt', {}, 12], ['fix-request', 'error', 'Could not reach the finding', { findingId: (S.findings[0] || {}).id }, 30]
      ].forEach(function (r, i) {
        var id = 'demo-' + i;
        Bridge.sent.set(id, { id: id, type: r[0], state: r[1], message: r[2], payload: r[3], createdAt: new Date(now - r[4] * 60000).toISOString() });
      });
      Bridge.lastSignalsAt = now;
      refreshLive('signals');
    }
  }

  function boot() {
    initTheme();
    initSidebar();
    initPanelChrome();
    var dirId = pickScan();
    var help = [
      'Build the dashboard data:  python -I -B src/core/build_datajs.py --scan <scan folder or ID>',
      'Then start the local server:  start-dashboard.cmd  (or  python -I -B src/server/serve.py)',
      'Opening dashboard/index.html directly also works once data/latest.js exists.'
    ];
    if (!dirId) { bootError('No scan data found.', help); return; }
    S.dirId = dirId;
    S.base = '../../data/' + dirId + '/js/';
    BVS.loadScript(S.base + 'manifest.js').then(function () {
      var m = BVS.get('manifest');
      if (!m || !Array.isArray(m.datasets)) { throw new Error('manifest.js is not valid'); }
      S.manifest = m;
      // Sequential, most important first: an antivirus web shield can cut off many parallel loopback
      // downloads (reproducible with python -m http.server); one at a time they get through.
      var PRIORITY = ['summary', 'guide', 'findings', 'coverage', 'storage', 'programs', 'startup', 'health', 'registry', 'duplicates', 'treemap'];
      var names = m.datasets.map(function (d) { return d && d.name; }).filter(function (n) { return typeof n === 'string' && ID_RE.test(n) && n !== 'manifest'; });
      names.sort(function (a, b) { var ia = PRIORITY.indexOf(a), ib = PRIORITY.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
      function loadOne(name) {
        var src = S.base + name + '.js';
        // Retries: a cut-off load must not leave the shell silently without its data. Still missing -> a visible reload banner.
        function retry() { return new Promise(function (res) { setTimeout(res, 400); }).then(function () { return BVS.loadScript(src); }); }
        return BVS.loadScript(src).catch(retry).catch(retry).catch(function () { S.failed.push(name); return null; });
      }
      return names.reduce(function (p, name) { return p.then(function () { return loadOne(name); }); }, Promise.resolve());
    }).then(function () {
      start();
    }).catch(function (err) {
      if (window.console) { console.error(err); }
      bootError('Could not load the data of scan "' + dirId + '".', help);
    });
  }

  function start() {
    S.summary = BVS.get('summary') || {};
    S.findings = (BVS.get('findings') || {}).items || [];
    S.findings.forEach(function (f) { if (f && f.id) { S.findingsById.set(f.id, f); } });
    S.coverage = BVS.get('coverage') || S.summary.coverage || {};
    var guide = BVS.get('guide');
    S.guide = guide && typeof guide === 'object' && !Array.isArray(guide) ? guide : null;
    ['storage', 'duplicates', 'programs', 'startup', 'registry', 'health'].forEach(function (name) {
      var d = BVS.get(name);
      if (d && Array.isArray(d.items)) {
        S.datasets[name] = d;
        d.items.forEach(function (it) {
          if (!it || !it.id) { return; }
          it.__ds = name;
          if (!S.itemsById.has(it.id)) { S.itemsById.set(it.id, it); }
        });
      }
    });
    S.scanId = S.summary.scanId || (S.manifest && S.manifest.scanId) || S.dirId;
    App.scan = { id: S.scanId, dirId: S.dirId, base: S.base, host: S.summary.host || null, generatedAt: S.summary.generatedAt || null };
    var info = $('scan-info');
    var bits = [];
    if (S.summary.host) { bits.push(S.summary.host); }
    if (S.summary.auditStartUtc) { bits.push('scanned ' + fmtWhen(S.summary.auditStartUtc)); }
    bits.push('scan ' + S.scanId);
    info.textContent = U.safeText(bits.join(' · '));
    info.title = info.textContent;
    S.basket = new window.BVSUI.Basket(S.dirId);
    App.basket = S.basket;
    S.basket.onChange(function () { updateBadges(); });
    S.ready = true;
    App.ready = true;
    $('boot-message').hidden = true;
    if (S.failed.length) {
      var names = { findings: 'security findings', summary: 'verdict summary', storage: 'storage lists', guide: 'plain-English guide', programs: 'programs', startup: 'startup items', health: 'health checks', coverage: 'coverage', duplicates: 'duplicates', registry: 'registry', treemap: 'storage map' };
      var banner = callout('warn', 'alert', 'Part of the scan data did not load', 'Missing: ' + S.failed.map(function (n) { return names[n] || n; }).join(', ') +
        '. Some pages may look empty. Reloading the page usually fixes this.');
      banner.classList.add('load-banner');
      banner.appendChild(button('Reload', function () { window.location.reload(); }, { cls: 'small', icon: 'refresh' }));
      $('main').insertBefore(banner, $('bvs-view'));
    }
    renderNav();
    readyFns.splice(0).forEach(function (fn) { try { fn(App); } catch (e) { if (window.console) { console.error(e); } } });
    try { document.dispatchEvent(new CustomEvent('bvs:ready', { detail: { scanId: S.scanId } })); } catch (e) { /* ignore */ }
    window.addEventListener('hashchange', route);
    initTopbarExtras();
    route();
    signalLoop();
    pollSession().then(function () { if (hasLiveTrackers()) { pollSignals(); } });
    setTimeout(runDemo, 400);
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', boot); } else { boot(); }
})();

// ==================================================================================================
// UI-D motion layer (decorative only): entrance stagger, number count-up, pointer tilt, asset slots and
// pause-when-offscreen. It never reads scan data and never changes routes, data or wording: a count-up
// always ends on the exact original text. Every effect is off under prefers-reduced-motion (the CSS
// switches animations off there too). Nothing here can break the shell: all work is wrapped in try/catch.
(function () {
  'use strict';
  var doc = document, SVGNS = 'http://www.w3.org/2000/svg';
  var mqReduce = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  var mqFine = window.matchMedia ? window.matchMedia('(hover: hover) and (pointer: fine)') : null;
  function reduced() { return !!(mqReduce && mqReduce.matches); }
  function each(list, fn) { Array.prototype.forEach.call(list || [], fn); }
  function safe(fn) { return function () { try { return fn.apply(this, arguments); } catch (e) { if (window.console) { console.warn('ui-d fx:', e); } } }; }
  var raf = window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : function (f) { return setTimeout(function () { f(Date.now()); }, 16); };
  function weakSet() {
    if (typeof WeakSet === 'function') { return new WeakSet(); }
    var list = [];
    return { has: function (o) { return list.indexOf(o) >= 0; }, add: function (o) { list.push(o); } };
  }
  var seenRise = weakSet(), seenNum = weakSet(), seenIo = weakSet();

  // ---- asset slots: optional images in dashboard/assets replace or add to the code-built fallbacks ----
  // data-fx-slot holds a base name from the fixed list below; the loader tries <name>.png, then <name>.webp.
  // <img data-fx-slot> swaps its src. <span class="fx-slot" data-fx-slot> gets an <img>, and its parent the
  // classes "has-slot" and "has-slot-<name>" (CSS then hides the sibling .fx-fallback or makes room). An SVG
  // <g data-fx-slot> gets an <image> centred on data-fx-x/-y with data-fx-size. A 404 keeps the fallback.
  var ASSET_BASE = '../dashboard/assets/';
  var ASSET_NAMES = { 'logo-mark': 1, 'hero-shield': 1, 'storage-core': 1, 'agent-core': 1, 'bg-nebula': 1 };
  var ASSET_EXTS = ['png', 'webp'];
  var probes = {};
  function loads(src) {
    return new Promise(function (resolve) {
      var img = new Image();
      img.onload = function () { resolve(img.naturalWidth > 0 ? src : null); };
      img.onerror = function () { resolve(null); };
      img.src = src;
    });
  }
  function probe(name) { // -> Promise<url or null>, once per page load
    if (!Object.prototype.hasOwnProperty.call(ASSET_NAMES, name)) { return Promise.resolve(null); }
    if (!probes[name]) {
      probes[name] = ASSET_EXTS.reduce(function (p, ext) {
        return p.then(function (found) { return found || loads(ASSET_BASE + name + '.' + ext); });
      }, Promise.resolve(null));
    }
    return probes[name];
  }
  var fillSlots = safe(function (scope) {
    each((scope || doc).querySelectorAll('[data-fx-slot]'), function (slot) {
      if (slot.getAttribute('data-fx-state')) { return; }
      slot.setAttribute('data-fx-state', 'probing');
      var name = String(slot.getAttribute('data-fx-slot') || '').replace(/\.(png|webp|jpg)$/, '');
      probe(name).then(safe(function (src) {
        slot.setAttribute('data-fx-state', src ? 'loaded' : 'fallback');
        if (!src || !slot.isConnected) { return; }
        if (String(slot.tagName).toLowerCase() === 'img') { slot.src = src; slot.classList.add('is-art'); return; }
        if (slot.namespaceURI === SVGNS) {
          var size = Number(slot.getAttribute('data-fx-size')) || 100;
          var im = doc.createElementNS(SVGNS, 'image');
          im.setAttribute('href', src);
          im.setAttribute('x', String((Number(slot.getAttribute('data-fx-x')) || 0) - size / 2));
          im.setAttribute('y', String((Number(slot.getAttribute('data-fx-y')) || 0) - size / 2));
          im.setAttribute('width', String(size));
          im.setAttribute('height', String(size));
          im.setAttribute('class', 'fx-slot-img');
          slot.appendChild(im);
        } else {
          var img = doc.createElement('img');
          img.className = 'fx-slot-img';
          img.alt = '';
          img.decoding = 'async';
          img.src = src;
          slot.appendChild(img);
        }
        if (slot.parentNode && slot.parentNode.classList) { slot.parentNode.classList.add('has-slot', 'has-slot-' + name); }
      }));
    });
  });

  // ---- number count-up (ends on the exact original text) -------------------------------------------
  var NUM_SEL = '.tile-num, .stat-num, .sum-num, .check-tile-num, .ag-tile-value, .sv-disk .sv-big, .sv-reclaim .sv-big, .sv-win-size';
  var NUM_RE = /^(\D*?)(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?(\D*)$/;
  function grouped(s) { return s.replace(/\B(?=(\d{3})+$)/g, ','); }
  function countUp(node) {
    var t = null;
    for (var c = node.firstChild; c; c = c.nextSibling) { if (c.nodeType === 3 && /\d/.test(c.nodeValue)) { t = c; break; } }
    if (!t) { return; }
    var orig = t.nodeValue, m = NUM_RE.exec(orig);
    if (!m) { return; }
    var comma = m[2].indexOf(',') >= 0, dec = m[3] ? m[3].length - 1 : 0;
    var target = parseFloat(m[2].replace(/,/g, '') + (m[3] || ''));
    if (!isFinite(target) || target <= 0) { return; }
    var w = node.getBoundingClientRect().width;
    if (w) { node.style.minWidth = Math.ceil(w) + 'px'; } // no reflow of neighbours while digits grow
    var dur = Math.min(900, 420 + String(Math.round(target)).length * 70), start = 0, finished = false;
    function fmt(v) {
      var s = v.toFixed(dec), i = s.indexOf('.'), ip = i < 0 ? s : s.slice(0, i);
      return m[1] + (comma ? grouped(ip) : ip) + (i < 0 ? '' : s.slice(i)) + m[4];
    }
    function finish() { if (finished) { return; } finished = true; if (t.parentNode) { t.nodeValue = orig; } node.style.minWidth = ''; }
    function step(ts) {
      if (finished) { return; }
      if (!t.parentNode) { finish(); return; }
      if (!start) { start = ts; }
      var k = Math.min(1, (ts - start) / dur), e = 1 - Math.pow(1 - k, 3);
      if (k < 1) { t.nodeValue = fmt(target * e); raf(step); } else { finish(); }
    }
    t.nodeValue = fmt(0);
    raf(step);
    setTimeout(finish, dur + 1500); // background tabs throttle rAF: the real text always comes back
  }

  // ---- entrance stagger (transform/opacity only, fill-mode backwards so hover styles keep working) ----
  var RISE_SEL = '.hero, .page-head, .health-card, .sev-tile, .ov-card, .sum-tile, .check-tile, .action-card, .card, .f-card, ' +
    '.sv-nav, .sv-disk, .sv-reclaim, .sv-win, .sv-hero, .svm-head, .svm-layout, .ag-head, .ag-tile, .ag-legend, .ag-map-card, .ag-acard';
  function rise(scope, navOnly) {
    var n = 0;
    each(scope.querySelectorAll(RISE_SEL), function (node) {
      if (n >= 30 || seenRise.has(node)) { return; }
      seenRise.add(node);
      if (navOnly && node.classList.contains('f-card')) { return; } // filter clicks re-list findings: no replay
      if (node.closest('.svm-box, .drawer, .bvs-modal') || (node.parentElement && node.parentElement.closest('.fx-rise'))) { return; }
      node.style.setProperty('--fx-i', String(Math.min(n, 12)));
      node.classList.add('fx-rise');
      n++;
      node.addEventListener('animationend', function done(ev) {
        if (ev.target !== node) { return; }
        node.classList.remove('fx-rise');
        node.style.removeProperty('--fx-i');
        node.removeEventListener('animationend', done);
      });
    });
  }

  // ---- pointer tilt (max 6 degrees, transform only, follows the pointer) ---------------------------
  var TILT_SEL = '.health-card, .sev-tile, .sv-win, .sv-disk, .ag-tile, .check-tile, .sum-tile';
  var tilt = { el: null, rect: null, x: 0, y: 0, frame: 0 };
  function untilt() {
    if (tilt.el) { tilt.el.style.transform = ''; tilt.el.classList.remove('is-tilting'); }
    tilt.el = null;
    tilt.rect = null;
  }
  var applyTilt = safe(function () {
    tilt.frame = 0;
    var node = tilt.el, r = tilt.rect;
    if (!node || !r || !node.isConnected || !r.width || !r.height) { return; }
    var nx = Math.max(-0.5, Math.min(0.5, (tilt.x - r.left) / r.width - 0.5));
    var ny = Math.max(-0.5, Math.min(0.5, (tilt.y - r.top) / r.height - 0.5));
    node.style.transform = 'perspective(900px) rotateX(' + (-ny * 8).toFixed(2) + 'deg) rotateY(' + (nx * 12).toFixed(2) + 'deg) translateY(-4px)';
    node.style.setProperty('--fx-mx', ((nx + 0.5) * 100).toFixed(1) + '%');
    node.style.setProperty('--fx-my', ((ny + 0.5) * 100).toFixed(1) + '%');
    node.classList.add('is-tilting');
  });
  doc.addEventListener('pointermove', safe(function (ev) {
    if (ev.pointerType && ev.pointerType !== 'mouse') { return; }
    if (reduced() || (mqFine && !mqFine.matches)) { if (tilt.el) { untilt(); } return; }
    var target = ev.target && ev.target.closest ? ev.target.closest(TILT_SEL) : null;
    if (target !== tilt.el) {
      untilt();
      if (!target) { return; }
      tilt.el = target;
      tilt.rect = target.getBoundingClientRect();
    }
    tilt.x = ev.clientX;
    tilt.y = ev.clientY;
    if (!tilt.frame) { tilt.frame = raf(applyTilt); }
  }), { passive: true });
  doc.documentElement.addEventListener('pointerleave', untilt);
  window.addEventListener('blur', untilt);
  window.addEventListener('scroll', untilt, { passive: true });

  // ---- pause looping decorations while they are off screen ----------------------------------------
  var io = window.IntersectionObserver ? new IntersectionObserver(function (entries) {
    entries.forEach(function (e) { e.target.classList.toggle('fx-paused', !e.isIntersecting); });
  }) : null;
  var watched = [];
  function watchOffscreen(scope) {
    if (!io) { return; }
    watched = watched.filter(function (n) { if (n.isConnected) { return true; } io.unobserve(n); return false; });
    each(scope.querySelectorAll('.hero, .ag-map-card, .sv-disk'), function (n) {
      if (!seenIo.has(n)) { seenIo.add(n); io.observe(n); watched.push(n); }
    });
  }

  // ---- run after every view mount and route change -------------------------------------------------
  var pass = safe(function (navOnly) {
    fillSlots(doc);
    var host = doc.getElementById('bvs-view');
    if (!host) { return; }
    watchOffscreen(host);
    if (reduced()) { return; }
    rise(host, navOnly);
    each(host.querySelectorAll(NUM_SEL), function (n) { if (!seenNum.has(n)) { seenNum.add(n); countUp(n); } });
  });
  var timers = [];
  function schedule(navOnly) {
    timers.forEach(clearTimeout);
    pass(navOnly);
    timers = [setTimeout(function () { pass(navOnly); }, 160), setTimeout(function () { pass(navOnly); }, 700)];
  }
  var hostEl = doc.getElementById('bvs-view');
  if (hostEl && window.MutationObserver) {
    new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) { if (muts[i].addedNodes.length) { schedule(false); return; } }
    }).observe(hostEl, { childList: true });
  }
  window.addEventListener('hashchange', function () { setTimeout(function () { schedule(true); }, 0); });
  fillSlots(doc);
  // views that re-render a part in place (agent map, storage summary) ask for their new slots here
  window.BVSFx = Object.freeze({ slots: function (scope) { fillSlots(scope && scope.querySelectorAll ? scope : doc); } });
})();
