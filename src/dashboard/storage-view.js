/* baby-virus-scanner dashboard: the Storage view (agent UI-B).
 * Registers the "storage" view with window.BVSApp (docs/ui-contract.md):
 *   #/storage                      -> map of the whole disk (default section)
 *   #/storage/<section>[?filters]  -> map | junk | big | old | duplicates | projects | system
 *   #/storage/map?path=<folder>    -> the map opened at that folder (a file opens its folder)
 *   list filters: ?cat=<category>&safety=<level>&group=<colour group>&q=<text>&path=<folder>
 * Layout: its own left sub-sidebar (sections with count/size badges), a clickable summary strip
 * (disk ring, reclaimable space by safety, biggest wins) and the active section.
 * SAFETY: scan data reaches the DOM only as text (util.js el()/textContent). There is no innerHTML,
 * no inline markup style (JS sets element.style only) and no delete action: allowed items can only
 * go into the shared Basket, which composes a DELETE REQUEST for Claude. Works from file:// because
 * treemap chunks load through <script> tags. */
(function () {
  'use strict';
  var BVSUI = window.BVSUI || {};
  var U = BVSUI.util;
  if (!U || !window.BVS) { return; }
  var el = U.el;
  var B = U.fmtBytes;
  var SVGNS = 'http://www.w3.org/2000/svg';
  var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
  var MAX_PER_LEVEL = 400, MAX_TILES = 1100, MAX_DEPTH = 3, HEADER_H = 20, PAGE = 60;

  // ------------------------------------------------------------------ icons (24x24 strokes)
  var ICONS = {
    grid: 'M3 3h8v10H3z M13 3h8v6h-8z M13 11h8v10h-8z M3 15h8v6H3z',
    sparkles: 'M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z M19 15.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z M5 3.5l.6 1.4 1.4.6-1.4.6-.6 1.4-.6-1.4L3 5.5l1.4-.6z',
    bigfile: 'M6 2h8l5 5v15H6z M14 2v5h5 M12 18v-7 M9 14l3-3 3 3',
    clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M12 7v5l3 2',
    copy: 'M9 9h11v11H9z M5 15V4h11',
    branch: 'M6 3v12 M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M18 9a9 9 0 0 1-9 9',
    lock: 'M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4',
    check: 'M5 12.5l4.5 4.5L19 7.5',
    checkEye: 'M3 12.5l4 4L15 8 M17.5 20a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z M19.4 19.4l2.1 2.1',
    eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    wrench: 'M14.5 6.5a4 4 0 0 0-5.3 5.3L3.5 17.5l3 3 5.7-5.7a4 4 0 0 0 5.3-5.3l-2.6 2.6-2.4-.6-.6-2.4z',
    info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M12 11v5 M12 8h.01',
    chevron: 'M9 6l6 6-6 6',
    back: 'M19 12H5 M11 6l-6 6 6 6',
    search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z M20 20l-4-4',
    basket: 'M3 10h18l-2 10H5z M8 10l4-6 4 6 M9 14v3 M15 14v3',
    disk: 'M3 6h18v12H3z M3 13h18 M7 15.5h.01 M11 15.5h.01',
    pin: 'M12 21s-7-6.2-7-11.5a7 7 0 0 1 14 0C19 14.8 12 21 12 21z M12 12a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z',
    shield: 'M12 3l8 3v6c0 4.8-3.4 8-8 9-4.6-1-8-4.2-8-9V6z M9 12l2 2 4-4',
    warning: 'M12 3.5l9.5 16.5h-19z M12 10v4.5 M12 17.5h.01',
    package: 'M12 2.5l8.5 4.75v9.5L12 21.5l-8.5-4.75v-9.5z M3.5 7.25L12 12l8.5-4.75 M12 12v9.5',
    download: 'M12 3v12 M7 10l5 5 5-5 M4 20h16',
    user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M4.5 21a7.5 7.5 0 0 1 15 0',
    windows: 'M3 5.5l7.5-1v7H3z M12.5 4.2L21 3v8.5h-8.5z M3 12.5h7.5v7L3 18.5z M12.5 12.5H21V21l-8.5-1.2z',
    apps: 'M4 4h6.5v6.5H4z M13.5 4H20v6.5h-6.5z M4 13.5h6.5V20H4z M13.5 13.5H20V20h-6.5z',
    dots: 'M5.5 12h.01 M12 12h.01 M18.5 12h.01',
    refresh: 'M20 11a8 8 0 0 0-14.3-4.9L4 8 M4 4v4h4 M4 13a8 8 0 0 0 14.3 4.9L20 16 M20 20v-4h-4',
    layers: 'M12 3l9 5-9 5-9-5z M3 13l9 5 9-5',
    folder: 'M3 6.5h6l2 2h10V19H3z',
    question: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M9.5 9.5a2.5 2.5 0 1 1 3.3 2.4c-.5.2-.8.7-.8 1.2v.9 M12 16.8h.01',
    close: 'M6 6l12 12 M18 6L6 18',
    plus: 'M12 5v14 M5 12h14',
    up: 'M12 19V5 M6 11l6-6 6 6'
  };

  // ------------------------------------------------------------------ shared wording
  var SAFETY_ORDER = ['safe', 'safe_after_check', 'use_tool', 'review', 'do_not_touch'];
  var SAFETY_INFO = {
    safe: { label: 'Safe to remove', short: 'Safe', icon: 'check', plain: 'Nothing needs it. Removing it does no harm.' },
    safe_after_check: { label: 'Safe after a quick check', short: 'Safe after check', icon: 'checkEye', plain: 'Usually fine to remove. Take a quick look that you do not need it any more.' },
    use_tool: { label: 'Clean with the app\'s own tool', short: 'Clean with app\'s tool', icon: 'wrench', plain: 'Do not delete it by hand. The app that owns it has its own clean-up button or command.' },
    review: { label: 'Look before deleting', short: 'Look first', icon: 'eye', plain: 'It could matter to you. Open it and decide yourself.' },
    do_not_touch: { label: 'System: leave alone', short: 'System', icon: 'lock', plain: 'Windows or an app needs it to work. Never delete it by hand.' }
  };
  var NOT_RATED = { label: 'Not rated', short: 'Not rated', icon: 'dots', plain: 'The scan has no clean-up rule for this one.' };
  function safetyInfo(s) { return SAFETY_INFO[s] || NOT_RATED; }

  var GROUP_ORDER = ['caches', 'dev', 'installers', 'personal', 'apps', 'system', 'other'];
  var GROUPS = {
    caches: { label: 'Caches & temp', icon: 'refresh', plain: 'Data apps keep so they work faster. Apps can download or re-create it, so it comes back over time.' },
    dev: { label: 'Dev & build', icon: 'package', plain: 'Programming tools: project dependencies, build output, virtual machines and Docker.' },
    installers: { label: 'Installers & leftovers', icon: 'download', plain: 'Setup files you already used and things left behind by old programs or the PC maker.' },
    personal: { label: 'Personal files', icon: 'user', plain: 'Your own documents, downloads, photos, videos and backups. Only you can decide what goes.' },
    apps: { label: 'Apps', icon: 'apps', plain: 'Installed programs and the settings and data they keep.' },
    system: { label: 'System', icon: 'windows', plain: 'Windows itself. The PC needs it to start and run, so leave it alone.' },
    other: { label: 'Other', icon: 'dots', plain: 'Everything that does not fit the groups above, or could not be identified.' }
  };
  var AGE_LABELS = ['Changed in the last year', 'Changed 1-2 years ago', 'Untouched 2-5 years', 'Untouched 5+ years'];
  var AGE_SHORT = ['< 1 year', '1-2 years', '2-5 years', '5+ years'];

  // category -> [colour group, friendly name, plain explanation]
  var CAT = {
    'dev-deps': ['dev', 'Old project dependencies', 'Code libraries downloaded into your projects (node_modules, .venv). One command (npm install, pip install) downloads them again when you need the project.'],
    'package-cache': ['caches', 'Package caches', 'Spare copies of downloaded code packages (npm, pip, NuGet...) kept to make future installs faster. Clear them with the tool\'s own clean command.'],
    'old-installer': ['installers', 'Old installers', 'Setup files you already ran. The program is installed; you only need the setup file to install it again, and you can download it again.'],
    'installer': ['installers', 'Installers', 'Setup files (.exe, .msi). Once the program is installed they are only needed to install it again.'],
    'installer-cache': ['installers', 'Installer cache', 'Copies of setup files that programs keep so they can repair or uninstall themselves.'],
    'system-installer-cache': ['system', 'Windows installer cache', 'Setup files Windows keeps to repair, update and uninstall programs. Deleting them breaks uninstalls.'],
    'windows-package': ['installers', 'Windows update packages', 'Downloaded Windows update or feature packages (.msu, .cab).'],
    'disk-image': ['installers', 'Disk images', 'Whole-disc images (.iso, .img), usually used once to install something.'],
    'oem-files': ['installers', 'PC maker files', 'Drivers, tools and recovery files left by the company that made the PC.'],
    'vendor-remnant': ['installers', 'Leftovers of old programs', 'Folders left behind after a program was uninstalled.'],
    'vm-disk': ['dev', 'Virtual machine & Docker disks', 'A whole virtual computer stored as one big file (Docker, WSL, VirtualBox). Shrink it from inside that program.'],
    'build-output': ['dev', 'Build output', 'Files produced when a project is built. The next build makes them again.'],
    'project-copy': ['dev', 'Project copies', 'Extra copies of the same programming project.'],
    'agent-worktrees': ['dev', 'AI agent work folders', 'Extra working copies of projects made by AI coding agents.'],
    'agent-worktree': ['dev', 'AI agent work folder', 'An extra working copy of a project made by an AI coding agent.'],
    'git-worktree': ['dev', 'Git work folder', 'An extra working folder linked to a main git project.'],
    'runtime-versions': ['dev', 'Extra runtime versions', 'Older versions of programming runtimes (Node, Python...) kept side by side.'],
    'git-objects': ['dev', 'Git history', 'The stored history of a git project.'],
    'browser-cache': ['caches', 'Browser caches', 'Pages and pictures your browser saved to open websites faster. Clear it from the browser\'s settings.'],
    'app-cache': ['caches', 'App caches', 'Data apps saved to start and work faster. The app downloads or rebuilds it when needed.'],
    'editor-cache': ['caches', 'Code editor caches', 'Caches and old extension versions of VS Code, Cursor and similar editors.'],
    'temp': ['caches', 'Temporary files', 'Scratch files apps create while working. They should delete them, but often forget.'],
    'leftover-temp': ['caches', 'Leftover temp file', 'A temporary file that was left behind.'],
    'crash-dumps': ['caches', 'Crash dumps', 'Memory snapshots saved when an app crashed. Only useful to developers.'],
    'shader-cache': ['caches', 'Graphics cache', 'Pre-built graphics programs for games and apps. Rebuilt automatically.'],
    'error-reports': ['caches', 'Error reports', 'Reports Windows saved about problems.'],
    'windows-update-cache': ['caches', 'Windows Update cache', 'Update files Windows already installed. Clear them with Disk Cleanup.'],
    'office-lock': ['caches', 'Office lock file', 'A small marker file Office leaves while a document is open.'],
    'log': ['caches', 'Log file', 'A diary file where an app records what it did.'],
    'database': ['apps', 'Database file', 'A data file an app uses.'],
    'ai-models': ['apps', 'AI models', 'Downloaded AI model files used by an app.'],
    'program-files': ['apps', 'Installed programs', 'Files of an installed program. Remove it from Settings > Apps, never by deleting the folder.'],
    'system-components': ['system', 'Windows components', 'Parts of Windows itself.'],
    'system-paging': ['system', 'Windows memory file', 'Windows uses this file as extra memory (page file / swap file).'],
    'system-hibernation': ['system', 'Hibernation file', 'Windows saves the memory here when the PC hibernates or fast-starts.'],
    'personal-data': ['personal', 'Personal files', 'Your own files.'],
    'video': ['personal', 'Videos', 'Video files.'],
    'archive': ['personal', 'Archives', 'Packed files (.zip, .rar, .7z).'],
    'document': ['personal', 'Documents', 'Documents such as PDFs.'],
    'backup': ['personal', 'Backups', 'Saved copies of files or settings.'],
    'duplicate': ['personal', 'Duplicate files', 'The same file stored more than once.'],
    'large-file': ['other', 'Large files', 'A large file without a more specific type.'],
    'cold-data': ['other', 'Rarely used data', 'Data that has not changed for 2+ years. It may belong to an app you no longer use.'],
    'zero-byte': ['other', 'Empty files', 'Files with no content.']
  };
  var FAMILY_GROUP = ['caches', 'dev', 'installers', 'other'];
  var CAT_ICON = { 'dev-deps': 'package', 'vm-disk': 'layers', 'package-cache': 'refresh', 'old-installer': 'download', 'installer': 'download', 'browser-cache': 'refresh', 'video': 'user', 'duplicate': 'copy', 'project-copy': 'branch', 'agent-worktree': 'branch', 'git-worktree': 'branch', 'agent-worktrees': 'branch', 'cold-data': 'clock', 'personal-data': 'user' };

  // well-known folder names -> what they are
  var KNOWN = {
    'users': 'The home folders of the people who use this PC. Your documents, downloads and app data are in here.',
    'windows': 'Windows itself: the operating system. Never delete anything here by hand.',
    'winsxs': 'The Windows component store: system files and updates. Much of it is shared with other Windows folders, so it looks bigger than it really is. Trim it only with Disk Cleanup or DISM.',
    'system32': 'Core Windows programs and drivers. Leave it alone.',
    'syswow64': 'Windows files for older 32-bit programs. Leave it alone.',
    'softwaredistribution': 'Windows Update\'s download folder. Clean it with Disk Cleanup, not by hand.',
    'program files': 'Where installed programs live. Remove programs from Settings > Apps, never by deleting their folders.',
    'program files (x86)': 'Where older 32-bit programs live. Remove programs from Settings > Apps, never by deleting their folders.',
    'programdata': 'A hidden folder with data and settings that programs share between all users.',
    'appdata': 'A hidden folder where your apps keep their settings, caches and data. Many caches live here.',
    'local': 'App data kept only on this PC. Most caches live here.',
    'roaming': 'App settings that can follow your account to another PC.',
    'locallow': 'Data of apps that run with extra restrictions (for example browser add-ons).',
    'temp': 'Temporary files. Apps should clean these up but often forget. Windows Disk Cleanup can empty it.',
    'tmp': 'Temporary files.',
    'documents': 'Your Documents folder.',
    'desktop': 'Everything on your desktop.',
    'downloads': 'Files you downloaded from the internet. Old installers and duplicates often pile up here.',
    'pictures': 'Your photos and pictures.',
    'videos': 'Your videos.',
    'music': 'Your music.',
    'onedrive': 'Files synced with Microsoft OneDrive. Online-only files use no space on this PC.',
    'node_modules': 'Code libraries downloaded for a JavaScript project. "npm install" downloads them again.',
    '.git': 'The project\'s saved history (git). Deleting it loses the history.',
    '.venv': 'A Python project\'s private set of libraries. It can be rebuilt with pip install.',
    'venv': 'A Python project\'s private set of libraries. It can be rebuilt with pip install.',
    'virtualbox vms': 'Virtual computers from VirtualBox. Each one stores a whole computer in one big file.',
    'docker': 'Docker Desktop\'s data: images, containers and the virtual disk they live on.',
    '.docker': 'Docker settings and small caches.',
    '.vscode': 'VS Code extensions and settings.',
    '.cursor': 'Cursor editor extensions and settings.',
    '.rustup': 'The Rust programming toolchain.',
    '.cargo': 'Rust packages and tools.',
    '.cache': 'A shared cache folder used by developer tools. Its contents can be downloaded again.',
    '.npm': 'npm\'s download cache. Clear it with "npm cache clean --force".',
    'npm-cache': 'npm\'s download cache. Clear it with "npm cache clean --force".',
    'pip': 'Python pip\'s download cache. Clear it with "pip cache purge".',
    'packages': 'Data of apps installed from the Microsoft Store.',
    'google': 'Data of Google apps such as Chrome.',
    'chrome': 'Google Chrome\'s data: your profiles, history, passwords and caches.',
    'user data': 'Browser profiles: bookmarks, passwords, history and caches.',
    'microsoft': 'Data of Microsoft apps (Edge, Office, Teams, OneDrive...).',
    '$recycle.bin': 'The Recycle Bin: files you deleted that can still be restored. Empty it from the desktop icon.',
    'recovery': 'Windows recovery tools. Leave it alone.',
    'system volume information': 'Windows restore points and system data. Windows does not let anyone open it.',
    'esupport': 'Driver installers and recovery files left by ASUS (the PC maker).',
    'perflogs': 'Windows performance logs (usually empty).',
    'cache': 'Saved data an app can download or rebuild again.',
    'code cache': 'Pre-compiled website code your browser or app saved to run faster.',
    'gpucache': 'Graphics data saved to draw faster. Rebuilt automatically.',
    'crashdumps': 'Memory snapshots from crashed apps. Only useful to developers.',
    'logs': 'Diary files where apps write what they did.'
  };

  var GUESS = {
    system: ['windows', 'winsxs', 'system32', 'syswow64', 'recovery', 'system volume information', 'boot', 'efi', 'perflogs', '$windows.~bt', '$winreagent', 'config.msi', 'servicing', 'documents and settings'],
    apps: ['program files', 'program files (x86)', 'programdata', 'appdata', 'windowsapps', 'common files', 'packages', 'avast! sandbox', '$av_asw'],
    personal: ['users', 'documents', 'desktop', 'downloads', 'pictures', 'videos', 'music', 'dropbox', 'google drive', 'contacts', 'favorites', 'saved games', '3d objects', 'links', 'searches', 'camera roll', 'screenshots'],
    dev: ['node_modules', '.git', '.venv', 'venv', 'site-packages', '__pycache__', '.gradle', '.m2', '.cargo', '.rustup', '.nuget', 'virtualbox vms', 'docker', '.docker', 'wsl', '.next', '.nuxt', '.turbo', 'dist', 'build', 'target', 'source', 'repos', 'projects', '.android', 'android', 'sdk', 'go', 'nodejs', 'msys64', '.pyenv', '.conda', 'anaconda3', 'miniconda3', '.vscode', '.cursor', '.codex', '.claude', 'worktrees', 'nvm4w', 'jetbrains', '.rustup', '.local'],
    caches: ['cache', 'caches', '.cache', 'temp', 'tmp', 'crashdumps', 'crashpad', 'inetcache', 'webcache', 'npm-cache', '.npm', 'pip', 'yarn', '.pnpm-store', 'pnpm-store', 'service worker', 'cachestorage', 'd3dscache', 'squirreltemp', 'logs', 'onedrivetemp', 'softwaredistribution'],
    installers: ['installer', 'installers', 'setup', 'package cache', 'windows.old', 'esupport', 'drivers', 'swsetup', 'intel', 'amd', 'nvidia', 'downloaded installations', 'msocache', '$windows.~ws']
  };
  var GUESS_MAP = {};
  Object.keys(GUESS).forEach(function (g) { GUESS[g].forEach(function (n) { GUESS_MAP[n] = g; }); });

  var GLOSSARY = {
    cache: ['cache', 'Data an app saved so it can work faster. The app can download or rebuild it, so removing it is usually harmless; it slowly comes back.'],
    temp: ['temporary files', 'Scratch files apps make while working and should delete afterwards.'],
    deps: ['dependencies', 'Ready-made code libraries a programming project downloads (node_modules, .venv). One command downloads them again.'],
    installer: ['installer', 'The setup file you run to install a program. Afterwards you only need it to install the program again.'],
    duplicate: ['duplicate', 'The same file, byte for byte, stored in more than one place.'],
    commit: ['commit', 'Saving your changes into a project\'s git history. Work that is not committed exists only in that one folder.'],
    worktree: ['worktree', 'An extra working folder linked to the same git project.'],
    stash: ['stash', 'Changes git put aside for later. They live only on this PC.'],
    vdisk: ['virtual disk', 'One big file that holds a whole virtual computer (Docker, WSL, VirtualBox).'],
    reclaim: ['reclaimable', 'Space you could get back by cleaning the items the scan found.'],
    basket: ['basket', 'Your clean-up list. Nothing is deleted from here: you copy a request to Claude, which re-checks every item and only acts after you type "I confirm".'],
    treemap: ['box', 'Each box is a folder. The bigger the box, the more space it uses. Boxes inside boxes are folders inside folders.'],
    holding: ['holding folder', 'Instead of deleting right away, the item is first moved to a holding folder, so it can be put back.'],
    hardlink: ['hard link', 'One file that appears in two places. It is counted twice here but stored only once.'],
    unaccounted: ['unaccounted space', 'Space Windows reports as used that the scan could not look into: restore points, file-system bookkeeping and locked folders.']
  };

  var FLAG_TEXT = {
    hardlinks_overcount: 'The size looks bigger than it is: many files are shared (hard links) with other Windows folders.',
    only_files_older_than_7d: 'Only files older than 7 days are counted.',
    project_idle_90d: 'The project has not been touched for 90+ days.',
    recently_used: 'Used recently, so it may still be needed.',
    shadowed_on_path: 'Another version of this program is used first, so this one may be unused.',
    grouped: 'Several similar items are grouped into this one.',
    partly_inaccessible: 'Some files could not be read, so the real size may be higher.',
    different_names: 'The copies have different names.',
    cross_folder: 'The copies are in different folders.',
    not_a_git_repo: 'Not a git project, so unsaved changes cannot be checked automatically: compare the copies by hand.',
    work_at_risk: 'Has work that exists only in this copy (not committed or not pushed).',
    worktree: 'A git "worktree": an extra working folder linked to a main project.',
    refs_shared_with_main_repo: 'Shares its history with the main project folder.',
    size_unknown: 'The size could not be measured.',
    onedrive_copy: 'One of the copies is in OneDrive.'
  };
  var NODE_FLAG_TEXT = {
    'hardlink-heavy': 'Many files here are shared with other Windows folders (hard links), so the real disk use is lower.',
    'onedrive': 'OneDrive folder: online-only files use no space on this PC.',
    'inaccessible': 'Windows did not let the scan open this folder, so its size is unknown.',
    'reparse': 'This is a shortcut to another folder (a junction), so its contents are counted elsewhere.',
    'user-writable-root': 'Every user account on this PC can write here.'
  };

  var SECTIONS = [
    { id: 'map', label: 'Map', icon: 'grid', blurb: 'Your whole disk as colourful boxes' },
    { id: 'junk', label: 'Junk & caches', icon: 'sparkles', blurb: 'Temporary files apps can re-create' },
    { id: 'big', label: 'Big files', icon: 'bigfile', blurb: 'The largest single files' },
    { id: 'old', label: 'Old files', icon: 'clock', blurb: 'Not touched in 2+ years' },
    { id: 'duplicates', label: 'Duplicates', icon: 'copy', blurb: 'The same file stored twice' },
    { id: 'projects', label: 'Projects at risk', icon: 'branch', blurb: 'Project copies with unsaved work' },
    { id: 'system', label: 'System (leave alone)', icon: 'lock', blurb: 'Windows needs these' }
  ];
  var SECTION_BY_ID = {};
  SECTIONS.forEach(function (s) { SECTION_BY_ID[s.id] = s; });

  // ------------------------------------------------------------------ state
  var S = {
    mounted: false, root: null, shell: null, navEl: null, navList: null, navFoot: null, sumEl: null, contentEl: null,
    model: null, section: 'map', query: {}, routeKey: '', list: null, listBody: null,
    waitTimer: 0, hookedBasket: null, sumCollapsed: !!U.storage.get('bvs.storage.sumCollapsed', false)
  };
  var M = {
    root: null, meta: {}, stack: [], mode: U.storage.get('bvs.storage.mode', 'category'), hl: null, info: null,
    box: null, sideEl: null, crumbs: null, legend: null, note: null, banner: null, backBtn: null, modeBtns: [],
    target: null, remain: [], clickT: 0, ro: null, prefetched: false, chunkP: {}, chain: [], lastTipDiv: null, error: ''
  };
  if (['category', 'safety', 'age'].indexOf(M.mode) < 0) { M.mode = 'category'; }

  // ------------------------------------------------------------------ small helpers
  function app() { return window.BVSApp || null; }
  function basket() { var a = app(); return a && a.basket && typeof a.basket.has === 'function' ? a.basket : null; }
  function nav(hash) {
    var a = app();
    if (a && typeof a.navigate === 'function') { a.navigate(hash); } else { window.location.hash = hash; }
  }
  function closePanel() { var a = app(); if (a && typeof a.closePanel === 'function') { a.closePanel(); } }
  function mapHash(path) { return '#/storage/map' + (path ? '?path=' + encodeURIComponent(path) : ''); }

  function svg(tag, attrs) {
    var n = document.createElementNS(SVGNS, tag);
    if (attrs) { Object.keys(attrs).forEach(function (k) { n.setAttribute(k, String(attrs[k])); }); }
    return n;
  }
  function icon(name, cls) {
    var s = svg('svg', {
      viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': name === 'dots' ? 3.2 : 2,
      'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false',
      'class': 'sv-ico' + (cls ? ' ' + cls : '')
    });
    s.appendChild(svg('path', { d: ICONS[name] || ICONS.dots }));
    return s;
  }
  function link(children, hash, cls, attrs) {
    var a = document.createElement('a');
    a.className = cls || 'sv-link';
    a.href = hash;
    if (attrs) { Object.keys(attrs).forEach(function (k) { if (attrs[k] !== null && attrs[k] !== undefined) { a.setAttribute(k, String(attrs[k])); } }); }
    U.append(a, children);
    return a;
  }
  function button(children, onClick, cls, attrs) {
    attrs = Object.assign({ type: 'button' }, attrs || {});
    var title = attrs.title;
    delete attrs.title;
    var b = el('button', { cls: 'sv-btn' + (cls ? ' ' + cls : ''), attrs: attrs, title: title || null }, children);
    if (onClick) { b.addEventListener('click', onClick); }
    return b;
  }
  // v3 privacy mode (agent L, docs/ui-contract-v3.md section 2): displayed names under personal folders go
  // through BVSApp.privacy when it exists; otherwise they are shown unchanged.
  function pvName(path, name) { var P = window.BVSApp && window.BVSApp.privacy; return P && typeof P.label === 'function' ? P.label(path, name) : name; }
  function pvPath(path) { var P = window.BVSApp && window.BVSApp.privacy; return P && typeof P.path === 'function' ? P.path(path) : path; }
  function bvs(node, type, id, label) {
    node.setAttribute('data-bvs-type', type);
    if (id) { node.setAttribute('data-bvs-id', String(id)); }
    if (label) { node.setAttribute('data-bvs-label', U.safeText(label)); }
    return node;
  }
  function shortText(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1).replace(/\s+\S*$/, '') + '…' : s; }

  function keyOf(p) {
    var s = String(p || '').replace(/[\\/]+$/, '');
    return S.model && S.model.ci === false ? s : s.toLowerCase();
  }
  function parentKeyOf(p) { return keyOf(p).replace(/[\\/][^\\/]*$/, ''); }
  function inside(key, folderKey) {
    if (!folderKey) { return true; }
    return key === folderKey || key.indexOf(folderKey + '\\') === 0 || key.indexOf(folderKey + '/') === 0;
  }
  function joinPath(base, name, sep) {
    if (!base) { return name; }
    return base.charAt(base.length - 1) === sep ? base + name : base + sep + name;
  }
  function sameName(a, b) {
    if (S.model && S.model.ci === false) { return String(a) === String(b); }
    return String(a).toLowerCase() === String(b).toLowerCase();
  }
  function sumBytes(items) { return items.reduce(function (s, it) { return s + (typeof it.bytes === 'number' ? it.bytes : 0); }, 0); }
  // Total size without counting a folder and something inside it twice.
  function sumDedup(items) {
    var keyed = items.filter(function (it) { return it.path && typeof it.bytes === 'number'; })
      .map(function (it) { return { k: keyOf(it.path), b: it.bytes }; })
      .sort(function (a, b) { return a.k < b.k ? -1 : a.k > b.k ? 1 : 0; });
    var total = 0, last = null;
    keyed.forEach(function (e) {
      if (last !== null && inside(e.k, last)) { return; }
      total += e.b;
      last = e.k;
    });
    return total;
  }
  function uniqByPath(items) {
    var seen = {}, out = [];
    items.forEach(function (it) {
      var k = keyOf(it.path) || it.id;
      if (seen[k]) { return; }
      seen[k] = true;
      out.push(it);
    });
    return out;
  }
  function refMs() {
    var r = S.model && S.model.ageRef;
    return r ? r * 1000 : Date.now();
  }
  function ageDays(value) {
    var d = U.toDate(value);
    if (!d) { return null; }
    return Math.max(0, (refMs() - d.getTime()) / 86400000);
  }
  function plainAge(value) {
    var days = ageDays(value);
    if (days === null) { return 'unknown'; }
    if (days < 1) { return 'today'; }
    if (days < 2) { return 'yesterday'; }
    if (days < 14) { return Math.round(days) + ' days ago'; }
    if (days < 60) { return Math.round(days / 7) + ' weeks ago'; }
    if (days < 730) { return Math.round(days / 30.44) + ' months ago'; }
    return (days / 365.25).toFixed(1).replace(/\.0$/, '') + ' years ago';
  }
  function ageBucket(value) {
    var d = ageDays(value);
    if (d === null) { return -1; }
    var y = d / 365.25;
    return y < 1 ? 0 : y < 2 ? 1 : y < 5 ? 2 : 3;
  }
  function catInfo(cat, cIdx) {
    var c = CAT[cat];
    if (c) { return { group: c[0], label: c[1], plain: c[2] }; }
    var fam = M.meta && M.meta.catFamily && cIdx !== undefined && cIdx !== null ? M.meta.catFamily[cIdx] : null;
    var label = cat ? String(cat).replace(/[-_]+/g, ' ').replace(/^./, function (ch) { return ch.toUpperCase(); }) : 'Other';
    return { group: FAMILY_GROUP[fam] || 'other', label: label, plain: '' };
  }
  function catLabel(cat) { return catInfo(cat).label; }
  function groupOfItem(it) { return catInfo(it.category).group; }
  function itemIcon(it) { return CAT_ICON[it.category] || GROUPS[groupOfItem(it)].icon; }
  function gitRisk(it) { return it && it.gitRisk && typeof it.gitRisk === 'object' ? it.gitRisk : null; }
  function atRisk(it) {
    if ((it.flags || []).indexOf('work_at_risk') >= 0) { return true; }
    var g = gitRisk(it);
    return !!(g && ((g.uncommitted || 0) > 0 || (g.unpushed || 0) > 0));
  }
  function isDupGroup(it) { return !!(it && it.x && Array.isArray(it.x.copies)) || it.list === 'duplicateGroups'; }
  function wasted(it) {
    var x = it.x || {};
    if (typeof x.wastedBytes === 'number') { return x.wastedBytes; }
    if (typeof x.sizeEach === 'number' && typeof it.bytes === 'number') { return Math.max(0, it.bytes - x.sizeEach); }
    return 0;
  }
  function pctDisk(b) { return U.pct(b, S.model ? S.model.used : 0); }

  // ------------------------------------------------------------------ visual atoms
  function term(textValue, key) {
    var g = GLOSSARY[key];
    if (!g) { return U.text(textValue); }
    return el('span', { cls: 'sv-term', text: textValue, attrs: { tabindex: '0', 'data-sv-tip': g[1], 'data-sv-term': g[0] } });
  }
  function safetyBadge(s, big) {
    var info = safetyInfo(s);
    return el('span', {
      cls: 'sv-safety sv-s-' + (SAFETY_INFO[s] ? s : 'none') + (big ? ' big' : ''),
      attrs: { tabindex: '0', 'data-sv-tip': info.plain, 'data-sv-term': info.label }
    }, [icon(info.icon), el('span', { text: info.label })]);
  }
  function catChip(cat) {
    var info = catInfo(cat);
    return el('span', { cls: 'sv-chip-cat sv-g-' + info.group, attrs: info.plain ? { tabindex: '0', 'data-sv-tip': info.plain, 'data-sv-term': info.label } : null }, [
      el('span', { cls: 'sv-dot', attrs: { 'aria-hidden': 'true' } }), info.label
    ]);
  }
  function sizeBar(bytes, max, cls) {
    var bar = el('span', { cls: 'sv-bar' + (cls ? ' ' + cls : ''), attrs: { 'aria-hidden': 'true' } });
    var fill = el('span', { cls: 'sv-bar-fill' });
    fill.style.width = (max > 0 ? Math.max(1.5, Math.min(100, bytes / max * 100)) : 0) + '%';
    bar.appendChild(fill);
    return bar;
  }
  function ageChip(value) {
    var bucket = ageBucket(value);
    return el('span', {
      cls: 'sv-age sv-a-' + (bucket >= 0 ? bucket : 'none'),
      attrs: { tabindex: '0', 'data-sv-tip': bucket >= 0 ? 'Last changed ' + U.fmtDate(value) + '. ' + AGE_LABELS[bucket] + '.' : 'No date known.', 'data-sv-term': 'Last changed' }
    }, [icon('clock'), el('span', { text: plainAge(value) })]);
  }
  function ring(frac, label, cls) {
    var wrap = el('span', { cls: 'sv-ring' + (cls ? ' ' + cls : '') });
    var s = svg('svg', { viewBox: '0 0 36 36', 'aria-hidden': 'true', focusable: 'false' });
    var p = Math.max(0, Math.min(100, (frac || 0) * 100));
    if (p > 0 && p < 1.5) { p = 1.5; }
    s.appendChild(svg('circle', { cx: 18, cy: 18, r: 15.915, fill: 'none', 'class': 'sv-ring-bg', 'stroke-width': 3.8 }));
    s.appendChild(svg('circle', {
      cx: 18, cy: 18, r: 15.915, fill: 'none', 'class': 'sv-ring-fg', 'stroke-width': 3.8,
      'stroke-dasharray': p.toFixed(2) + ' ' + (100 - p).toFixed(2), 'stroke-dashoffset': 25
    }));
    wrap.appendChild(s);
    wrap.appendChild(el('span', { cls: 'sv-ring-label', text: label }));
    return wrap;
  }
  function swatch(cls, ic) {
    return el('span', { cls: 'sv-swatch ' + cls, attrs: { 'aria-hidden': 'true' } }, ic ? icon(ic) : null);
  }

  // ------------------------------------------------------------------ floating tooltip (map tiles + terms)
  var tipEl = null;
  function tip() {
    if (!tipEl || !tipEl.isConnected) {
      tipEl = el('div', { cls: 'sv-tooltip', attrs: { role: 'tooltip' }, hidden: true });
      document.body.appendChild(tipEl);
    }
    return tipEl;
  }
  function hideTip() { if (tipEl) { tipEl.hidden = true; } M.lastTipDiv = null; }
  function placeTipAtPoint(x, y) {
    var t = tip(), pad = 14, vw = window.innerWidth, vh = window.innerHeight;
    var r = t.getBoundingClientRect();
    var left = x + pad, top = y + pad;
    if (left + r.width > vw - 8) { left = x - r.width - pad; }
    if (top + r.height > vh - 8) { top = y - r.height - pad; }
    t.style.left = Math.max(8, left) + 'px';
    t.style.top = Math.max(8, top) + 'px';
  }
  function showTermTip(target) {
    var t = tip();
    U.clear(t);
    t.classList.add('term');
    var name = target.getAttribute('data-sv-term');
    if (name) { t.appendChild(el('div', { cls: 'sv-tt-name', text: name })); }
    t.appendChild(el('div', { cls: 'sv-tt-what', text: target.getAttribute('data-sv-tip') || '' }));
    t.hidden = false;
    var r = target.getBoundingClientRect(), tr = t.getBoundingClientRect();
    var left = Math.min(window.innerWidth - tr.width - 8, Math.max(8, r.left));
    var top = r.bottom + 8;
    if (top + tr.height > window.innerHeight - 8) { top = r.top - tr.height - 8; }
    t.style.left = left + 'px';
    t.style.top = Math.max(8, top) + 'px';
  }
  var termTipsReady = false;
  function initTermTips() {
    if (termTipsReady) { return; }
    termTipsReady = true;
    function find(node) { return node && node.closest ? node.closest('[data-sv-tip]') : null; }
    document.addEventListener('pointerover', function (ev) { var t = find(ev.target); if (t) { showTermTip(t); } });
    document.addEventListener('pointerout', function (ev) {
      var t = find(ev.target);
      if (t && !(ev.relatedTarget && t.contains(ev.relatedTarget))) { hideTip(); }
    });
    document.addEventListener('focusin', function (ev) { var t = find(ev.target); if (t) { showTermTip(t); } });
    document.addEventListener('focusout', function (ev) { if (find(ev.target)) { hideTip(); } });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { hideTip(); } });
    window.addEventListener('scroll', function () { if (tipEl && tipEl.classList.contains('term')) { hideTip(); } }, true);
  }

  // ------------------------------------------------------------------ data model
  function itemsOf(name) { var d = window.BVS.get(name); return d && Array.isArray(d.items) ? d.items : []; }
  var NEEDED = ['storage', 'duplicates', 'treemap'];
  function dataSig() { return NEEDED.concat(['guide']).map(function (n) { return window.BVS.has(n) ? '1' : '0'; }).join(''); }
  function missingDatasets() { return NEEDED.filter(function (n) { return !window.BVS.has(n); }); }
  // If the shell could not load a storage dataset (slow disk, server hiccup), try once more ourselves
  // and re-render when it arrives; otherwise say plainly what is missing.
  function ensureDatasets() {
    var miss = missingDatasets();
    if (!miss.length || S.loadingMissing) { S.missing = miss; return; }
    S.loadingMissing = true;
    if (S.mounted && S.shell) { renderSummary(); }
    Promise.all(miss.map(function (n) { return loadChunk(n).catch(function () { return null; }); })).then(function () {
      S.loadingMissing = false;
      S.missing = missingDatasets();
      if (S.model && S.model.sig !== dataSig()) {
        S.model = buildModel();
        if (S.mounted && S.shell) { S.routeKey = ''; renderNavFooter(); renderSummary(); applyRoute(readRoute()); }
      } else if (S.mounted && S.shell) { renderSummary(); }
    });
  }

  function buildModel() {
    var st = window.BVS.get('storage'), du = window.BVS.get('duplicates'), tm = window.BVS.get('treemap');
    if (!st && !du && !tm) { return null; }
    var meta = (tm && tm.meta) || {};
    var model = { tm: tm && tm.root ? tm : null, meta: meta, ci: meta.caseInsensitive !== false, sep: meta.sep || '\\' };
    S.model = model;  // keyOf() needs ci while building
    var facts = {};
    ((st && st.facts) || []).forEach(function (f) { if (f && f.key) { facts[f.key] = f.value; } });
    var sum = facts.storageSummary || {};
    var vol = sum.volume || {};
    model.sum = sum;
    model.ageRef = meta.ageRef || Math.floor(Date.now() / 1000);
    model.used = vol.usedBytes || meta.usedBytes || (tm && tm.root ? tm.root.b : 0) || 1;
    model.size = vol.sizeBytes || 0;
    model.free = typeof vol.freeBytes === 'number' ? vol.freeBytes : (model.size ? Math.max(0, model.size - model.used) : 0);
    model.volRoot = vol.root || meta.rootPath || '';
    var sitems = itemsOf('storage'), ditems = itemsOf('duplicates');
    function inTab(it, tab, list) { return (it.tabs || []).indexOf(tab) >= 0 || it.list === list; }
    var junkAll = sitems.filter(function (it) { return inTab(it, 'junk', 'junkItems'); });
    var big = sitems.filter(function (it) { return inTab(it, 'big', 'bigFiles'); });
    var oldF = sitems.filter(function (it) { return inTab(it, 'old', 'oldFolders'); });
    model.junkAll = junkAll;
    model.junk = junkAll.filter(function (it) { return it.safety !== 'do_not_touch'; });
    model.big = big;
    var oldKeys = oldF.map(function (it) { return keyOf(it.path); });
    var oldExtra = uniqByPath(big.concat(model.junk).filter(function (it) {
      if (it.safety === 'do_not_touch' || !it.newest) { return false; }
      var d = ageDays(it.newest);
      if (d === null || d < 730.5) { return false; }
      var k = keyOf(it.path);
      return !oldKeys.some(function (ok) { return inside(k, ok); });
    }));
    oldF.forEach(function (it) { it.__oldKind = 'folder'; });
    oldExtra.forEach(function (it) { it.__oldKind = 'file'; });
    model.oldFolders = oldF;
    model.oldExtra = oldExtra;
    model.old = oldF.concat(oldExtra);
    model.system = uniqByPath(sitems.filter(function (it) { return it.safety === 'do_not_touch'; }));
    model.dups = ditems.filter(isDupGroup);
    model.projects = ditems.filter(function (it) { return !isDupGroup(it) && (it.list === 'projectCopies' || /project|worktree/.test(it.category || '')); });

    // path -> item (the most informative list first); files directly in a folder by parent path
    model.byPath = new Map();
    model.filesByParent = new Map();
    [junkAll, oldF, model.projects, big].forEach(function (list) {
      list.forEach(function (it) {
        if (!it.path) { return; }
        var k = keyOf(it.path);
        if (!model.byPath.has(k)) { model.byPath.set(k, it); }
      });
    });
    var seenId = {};
    model.all = [];
    junkAll.concat(oldF, big, model.projects).forEach(function (it) {
      if (!it.path || seenId[it.id]) { return; }
      seenId[it.id] = true;
      it.__key = keyOf(it.path);
      model.all.push(it);
      if (it.kind === 'file') {
        var pk = parentKeyOf(it.path);
        if (!model.filesByParent.has(pk)) { model.filesByParent.set(pk, []); }
        model.filesByParent.get(pk).push(it);
      }
    });

    var risky = model.projects.filter(atRisk);
    model.stats = {
      map: { bytes: meta.treemapBytes || (tm && tm.root ? tm.root.b : 0) },
      junk: { count: model.junk.length, bytes: sumDedup(model.junk) },
      big: { count: big.length, bytes: sumBytes(big) },
      old: { count: model.old.length, bytes: sumDedup(model.old) },
      duplicates: { count: model.dups.length, bytes: model.dups.reduce(function (s, it) { return s + wasted(it); }, 0) },
      projects: { count: risky.length, total: model.projects.length, bytes: sumBytes(risky) },
      system: { count: model.system.length, bytes: sumDedup(model.system) }
    };
    model.split = reclaimSplit(model);
    model.wins = computeWins(model);
    model.guide = window.BVS.get('guide') || null;
    model.sig = dataSig();
    return model;
  }

  function reclaimSplit(model) {
    var out = {};
    var by = model.sum && model.sum.bySafety;
    SAFETY_ORDER.forEach(function (s) {
      var v = by && by[s];
      out[s] = v && typeof v === 'object' ? (v.bytes || 0) : (typeof v === 'number' ? v : null);
    });
    if (SAFETY_ORDER.every(function (s) { return out[s] === null; })) {
      SAFETY_ORDER.forEach(function (s) { out[s] = sumDedup(model.junkAll.filter(function (it) { return it.safety === s; })); });
    }
    SAFETY_ORDER.forEach(function (s) { out[s] = out[s] || 0; });
    out.reclaimable = typeof model.sum.reclaimableBytes === 'number' ? model.sum.reclaimableBytes : out.safe + out.safe_after_check + out.use_tool;
    return out;
  }

  function safeHash(h) { return typeof h === 'string' && /^#\/[A-Za-z0-9\/?=&%._~+-]*$/.test(h) ? h : null; }

  function computeWins(model) {
    var computed = computeCatWins(model);
    var g = window.BVS.get('guide');
    if (!(g && Array.isArray(g.storageHighlights) && g.storageHighlights.length)) { return computed.slice(0, 4); }
    // Plain wording from the guide; the link goes to the matching category (same size), so the card opens its section filtered.
    var used = {};
    return g.storageHighlights.filter(function (h) { return h && typeof h.bytes === 'number' && h.bytes > 0; }).slice(0, 4).map(function (h) {
      var catM = /[?&]cat=([A-Za-z0-9_-]+)/.exec(String(h.link || ''));
      var match = null;
      if (catM) { match = computed.filter(function (c) { return c.cat === catM[1]; })[0] || null; }
      if (!match) {
        match = computed.filter(function (c) { return !used[c.cat] && Math.abs(c.bytes - h.bytes) <= 0.03 * h.bytes; })[0] || null;
      }
      var link = safeHash(h.link) || '#/storage/junk', cat = null, group = 'other';
      if (match) {
        used[match.cat] = true;
        link = match.link; cat = match.cat; group = match.group;
      } else {
        var one = model.all.filter(function (it) { return typeof it.bytes === 'number' && Math.abs(it.bytes - h.bytes) <= 0.03 * h.bytes; })[0];
        if (one) {
          var sec = one.__oldKind ? 'old' : (one.tabs || [])[0] || 'junk';
          link = '#/storage/' + (SECTION_BY_ID[sec] ? sec : 'junk') + '?item=' + encodeURIComponent(one.id);
          cat = one.category; group = groupOfItem(one);
        }
      }
      return { title: String(h.title || ''), bytes: h.bytes, plain: String(h.plain || ''), link: link, cat: cat, group: group };
    });
  }
  function computeCatWins(model) {
    var cats = Array.isArray(model.sum.topCategories) ? model.sum.topCategories.slice() : null;
    if (!cats) {
      var by = {};
      model.junk.forEach(function (it) {
        var c = by[it.category] || (by[it.category] = { category: it.category, items: 0, list: [], safety: [] });
        c.items++;
        c.list.push(it);
        if (c.safety.indexOf(it.safety) < 0) { c.safety.push(it.safety); }
      });
      cats = Object.keys(by).map(function (k) { by[k].bytes = sumDedup(by[k].list); return by[k]; });
    }
    return cats.filter(function (c) {
      var saf = c.safety || [];
      return c.bytes > 0 && !(saf.length && saf.every(function (s) { return s === 'do_not_touch'; })) && catInfo(c.category).group !== 'system';
    }).sort(function (a, b) { return b.bytes - a.bytes; }).slice(0, 8).map(function (c) {
      var info = catInfo(c.category);
      var title = info.label;
      var inCat = model.junk.filter(function (it) { return it.category === c.category; });
      if (c.category === 'vm-disk' && inCat.length && inCat.every(function (it) { return /docker/i.test((it.owner || '') + ' ' + it.path); })) { title = 'Docker disk'; }
      return {
        title: title, bytes: c.bytes, plain: info.plain, cat: c.category, group: info.group, items: c.items,
        link: '#/storage/junk?cat=' + encodeURIComponent(c.category)
      };
    });
  }

  // ------------------------------------------------------------------ routing
  var QUERY_KEYS = ['path', 'cat', 'safety', 'group', 'q', 'item'];
  function parseQS(qs) {
    var out = {};
    String(qs || '').split('&').forEach(function (pair) {
      if (!pair) { return; }
      var i = pair.indexOf('=');
      var k = i >= 0 ? pair.slice(0, i) : pair, v = i >= 0 ? pair.slice(i + 1) : '';
      try { k = decodeURIComponent(k); v = decodeURIComponent(v); } catch (e) { return; }
      out[k] = v;
    });
    return out;
  }
  function cleanQuery(q) {
    var out = {};
    QUERY_KEYS.forEach(function (k) {
      var v = q && q[k];
      if (typeof v !== 'string' || !v || v.length > 2048) { return; }
      if (k === 'safety' && !SAFETY_INFO[v]) { return; }
      if (k === 'group' && !GROUPS[v]) { return; }
      if ((k === 'cat' || k === 'item') && !/^[A-Za-z0-9_-]{1,64}$/.test(v)) { return; }
      out[k] = v;
    });
    return out;
  }
  function readRoute(params) {
    var h = String(window.location.hash || '');
    var mm = /^#\/storage(?:\/([^?#]*))?(?:\?(.*))?$/.exec(h);
    var section = '', query = {};
    if (mm) {
      section = (mm[1] || '').split('/')[0];
      query = parseQS(mm[2] || '');
    } else if (typeof params === 'string') {
      var pm = /^\/?([^?]*)(?:\?(.*))?$/.exec(params) || [];
      section = String(pm[1] || '').split('/')[0];
      query = parseQS(pm[2] || '');
    } else if (params && typeof params === 'object') {
      section = params.section || params.sub || (Array.isArray(params.parts) ? params.parts[0] : '') || (Array.isArray(params) ? params[0] : '') || '';
      var src = params.query || params.params || params;
      QUERY_KEYS.forEach(function (k) { if (typeof src[k] === 'string') { query[k] = src[k]; } });
    }
    if (!SECTION_BY_ID[section]) { section = 'map'; }
    return { section: section, query: cleanQuery(query) };
  }
  function routeKeyOf(r) {
    return r.section + '|' + QUERY_KEYS.map(function (k) { return r.query[k] ? k + '=' + r.query[k] : ''; }).join('&');
  }
  function onHashChange() {
    if (S.mounted && /^#\/storage(\/|\?|$)/.test(String(window.location.hash || ''))) { applyRoute(readRoute()); }
  }
  function replaceHash(h) {
    if (window.location.hash === h) { return; }
    try { window.history.replaceState(window.history.state, '', h); } catch (e) { /* some file:// setups refuse; harmless */ }
  }
  function applyRoute(r) {
    if (!S.mounted || !S.shell) { return; }
    var key = routeKeyOf(r);
    if (key === S.routeKey) { return; }
    var changedSection = r.section !== S.section;
    S.routeKey = key;
    S.section = r.section;
    S.query = r.query;
    S.list = null;
    hideTip();
    renderNav();
    renderSection();
    if (r.query.item) { openDeepLinkedItem(r); }
    if (changedSection && S.shell.getBoundingClientRect().top < 0 && S.shell.scrollIntoView) {
      S.shell.scrollIntoView({ block: 'start' });
    }
  }

  function buildHash(section, query) {
    var qs = QUERY_KEYS.filter(function (k) { return query[k]; }).map(function (k) { return k + '=' + encodeURIComponent(query[k]); }).join('&');
    return '#/storage/' + section + (qs ? '?' + qs : '');
  }
  // #/storage/<section>?item=<id> opens that item's panel once, then drops the parameter from the URL.
  function openDeepLinkedItem(r) {
    var id = r.query.item, m = S.model;
    var it = m.all.concat(m.dups, m.system).filter(function (x) { return x.id === id; })[0];
    var rest = Object.assign({}, r.query);
    delete rest.item;
    S.query = rest;
    var h = buildHash(r.section, rest);
    replaceHash(h);
    S.routeKey = routeKeyOf({ section: r.section, query: rest });
    if (it) { setTimeout(function () { openItemPanel(it); }, 0); }
  }

  // ------------------------------------------------------------------ mount / unmount
  function mount(root, params) {
    if (!root) { return; }
    if (S.mounted && S.root === root && S.shell && S.shell.parentNode === root) { applyRoute(readRoute(params)); return; }
    if (S.mounted) { unmount(); }
    S.root = root;
    S.mounted = true;
    S.routeKey = '';
    initTermTips();
    if (!S.model || S.model.sig !== dataSig()) { S.model = buildModel(); }
    if (!S.model) { showWaiting(root, params, 0); return; }
    hookBasket();
    buildShell(root);
    window.addEventListener('hashchange', onHashChange);
    applyRoute(readRoute(params));
    ensureDatasets();
  }

  function showWaiting(root, params, tries) {
    U.clear(root);
    var card = el('div', { cls: 'sv-host' }, el('div', { cls: 'sv-card sv-empty', attrs: { 'data-bvs-section': 'storage' } }, [
      icon('disk'), el('h2', { cls: 'sv-h2', text: tries > 40 ? 'No storage data in this scan' : 'Loading storage data…' }),
      el('p', { cls: 'sv-muted', text: tries > 40 ? 'The storage modules (G0/G1/G2) have not produced data for this scan yet.' : 'One moment.' })
    ]));
    root.appendChild(card);
    if (tries > 40) { return; }
    S.waitTimer = setTimeout(function () {
      if (!S.mounted || S.root !== root) { return; }
      S.model = buildModel();
      if (S.model) { S.mounted = false; U.clear(root); mount(root, params); } else { showWaiting(root, params, tries + 1); }
    }, 250);
  }

  function unmount() {
    S.mounted = false;
    window.removeEventListener('hashchange', onHashChange);
    clearTimeout(S.waitTimer);
    clearTimeout(M.clickT);
    if (M.ro) { M.ro.disconnect(); M.ro = null; }
    hideTip();
    if (S.shell && S.shell.parentNode) { S.shell.parentNode.removeChild(S.shell); }
    S.shell = null;
    M.box = null;
  }

  function hookBasket() {
    var b = basket();
    if (!b || S.hookedBasket === b || typeof b.onChange !== 'function') { return; }
    S.hookedBasket = b;
    b.onChange(function () {
      syncAllBasket();
      if (S.mounted) { renderNavFooter(); }
    });
  }

  // ------------------------------------------------------------------ shell: sub-sidebar + summary
  function buildShell(root) {
    var shell = el('div', { cls: 'sv-host', attrs: { 'data-bvs-section': 'storage' } });
    var grid = el('div', { cls: 'sv' });
    var navEl = el('nav', { cls: 'sv-nav', attrs: { 'aria-label': 'Storage sections', 'data-bvs-section': 'storage-menu' } });
    var main = el('div', { cls: 'sv-main' });
    var sum = el('section', { cls: 'sv-summary', attrs: { 'aria-label': 'Storage summary', 'data-bvs-section': 'storage-summary' } });
    var content = el('div', { cls: 'sv-content' });
    main.appendChild(sum);
    main.appendChild(content);
    grid.appendChild(navEl);
    grid.appendChild(main);
    shell.appendChild(grid);
    root.appendChild(shell);
    S.shell = shell; S.navEl = navEl; S.sumEl = sum; S.contentEl = content;

    navEl.appendChild(el('div', { cls: 'sv-nav-head' }, [
      // UI-D (decorative): optional storage-core art (.png/.webp) replaces the icon medallion when it exists
      el('span', { cls: 'sv-nav-art', attrs: { 'aria-hidden': 'true' } }, [
        el('span', { cls: 'sv-nav-head-ico fx-fallback' }, icon('disk')),
        el('span', { cls: 'fx-slot sv-nav-art-slot', attrs: { 'data-fx-slot': 'storage-core' } })
      ]),
      el('div', null, [el('div', { cls: 'sv-nav-title', text: 'Storage' }), el('div', { cls: 'sv-nav-sub', text: 'Find what fills your disk' })])
    ]));
    S.navList = el('ul', { cls: 'sv-nav-list', attrs: { role: 'list' } });
    navEl.appendChild(S.navList);
    S.navFoot = el('div', { cls: 'sv-nav-foot' });
    navEl.appendChild(S.navFoot);
    renderNavFooter();
    renderSummary();
  }

  function navBadges(id) {
    var st = S.model.stats[id] || {};
    var out = [];
    if (id === 'map') {
      out.push(el('span', { cls: 'sv-badge', text: B(st.bytes) }));
      out.push(el('span', { cls: 'sv-badge soft', text: 'whole disk' }));
    } else if (id === 'projects') {
      out.push(el('span', { cls: 'sv-badge' + (st.count ? ' warn' : ''), text: st.count + ' at risk' }));
      out.push(el('span', { cls: 'sv-badge soft', text: st.total + ' copies' }));
    } else if (id === 'duplicates') {
      out.push(el('span', { cls: 'sv-badge', text: String(st.count) }));
      out.push(el('span', { cls: 'sv-badge soft', text: B(st.bytes) + ' extra' }));
    } else {
      out.push(el('span', { cls: 'sv-badge', text: String(st.count) }));
      out.push(el('span', { cls: 'sv-badge soft', text: B(st.bytes) }));
    }
    return out;
  }

  function renderNav() {
    if (!S.navList) { return; }
    U.clear(S.navList);
    SECTIONS.forEach(function (sec) {
      var st = S.model.stats[sec.id] || {};
      var a = link([
        el('span', { cls: 'sv-nav-ico' }, icon(sec.icon)),
        el('span', { cls: 'sv-nav-text' }, [
          el('span', { cls: 'sv-nav-label', text: sec.label }),
          el('span', { cls: 'sv-nav-badges' }, navBadges(sec.id))
        ])
      ], '#/storage/' + sec.id, 'sv-nav-item sv-acc-' + sec.id, {
        'aria-current': S.section === sec.id ? 'page' : null,
        title: sec.blurb
      });
      bvs(a, 'tile', null, sec.label + ': ' + (st.count !== undefined ? st.count + ' items, ' : '') + B(st.bytes));
      S.navList.appendChild(el('li', null, a));
    });
  }

  function renderNavFooter() {
    var f = S.navFoot;
    if (!f) { return; }
    U.clear(f);
    var b = basket();
    if (b) {
      var n = b.count();
      var a = link([
        el('span', { cls: 'sv-basket-ico' }, icon('basket')),
        el('span', { cls: 'sv-basket-text' }, [
          el('strong', { text: 'Basket: ' + n + ' item' + (n === 1 ? '' : 's') }),
          el('span', { text: B(b.totalBytes ? b.totalBytes() : 0) + ' · nothing is deleted here' })
        ])
      ], '#/basket', 'sv-basket-card', { title: 'Open the clean-up basket' });
      bvs(a, 'tile', null, 'Basket: ' + n + ' items');
      f.appendChild(a);
    }
    var help = button([icon('question'), 'What do the colours mean?'], openHelpPanel, 'sv-help-btn ghost');
    f.appendChild(help);
  }

  function renderSummary() {
    var host = S.sumEl, m = S.model;
    if (!host) { return; }
    U.clear(host);
    host.classList.toggle('collapsed', S.sumCollapsed);
    var toggle = button([icon(S.sumCollapsed ? 'chevron' : 'up'), S.sumCollapsed ? 'Show summary' : 'Hide summary'], function () {
      S.sumCollapsed = !S.sumCollapsed;
      U.storage.set('bvs.storage.sumCollapsed', S.sumCollapsed);
      renderSummary();
      if (S.section === 'map') { renderMapAll(); }
    }, 'ghost small sv-sum-toggle', { 'aria-expanded': String(!S.sumCollapsed) });
    var usedFrac = m.size ? m.used / m.size : 0;
    if (S.loadingMissing || (S.missing && S.missing.length)) {
      var names = { storage: 'clean-up lists', duplicates: 'duplicates', treemap: 'disk map' };
      var miss = (S.missing && S.missing.length ? S.missing : missingDatasets()).map(function (n) { return names[n] || n; }).join(', ');
      host.appendChild(el('p', { cls: 'sv-notice', attrs: { role: 'status' } }, [icon(S.loadingMissing ? 'refresh' : 'warning'),
        el('span', { text: S.loadingMissing ? 'Loading the rest of the storage data (' + miss + ')…' : 'Part of the storage data could not be loaded (' + miss + '). Reload the page to try again.' })]));
    }

    if (S.sumCollapsed) {
      var line = el('div', { cls: 'sv-sum-line' });
      line.appendChild(link([ring(usedFrac, m.size ? Math.round(usedFrac * 100) + '%' : '?', 'sv-ring-disk tiny'),
        el('span', { text: B(m.used) + ' used · ' + B(m.free) + ' free' })], '#/storage/map', 'sv-sum-mini'));
      line.appendChild(stackBar(m.split, true));
      line.appendChild(toggle);
      host.appendChild(line);
      return;
    }

    var grid = el('div', { cls: 'sv-sum-grid' });
    // disk
    var disk = button(null, function () { nav('#/storage/map'); }, 'sv-card sv-disk');
    bvs(disk, 'tile', null, 'Disk ' + m.volRoot + ': ' + B(m.used) + ' used, ' + B(m.free) + ' free');
    disk.appendChild(ring(usedFrac, m.size ? Math.round(usedFrac * 100) + '%' : '?', 'sv-ring-disk'));
    disk.appendChild(el('span', { cls: 'sv-disk-text' }, [
      el('span', { cls: 'sv-kicker', text: 'Disk ' + (m.volRoot || '') + ' · used' }),
      el('span', { cls: 'sv-big', text: B(m.used) }),
      el('span', { cls: 'sv-muted', text: B(m.free) + ' free' + (m.size ? ' of ' + B(m.size) : '') }),
      el('span', { cls: 'sv-cta' }, ['Open the map', icon('chevron')])
    ]));
    grid.appendChild(disk);

    // reclaimable split by safety
    var rec = el('div', { cls: 'sv-card sv-reclaim' });
    bvs(rec, 'tile', null, 'Space you could get back: up to ' + B(m.split.reclaimable));
    rec.appendChild(el('div', { cls: 'sv-reclaim-head' }, [
      el('span', { cls: 'sv-kicker' }, ['Space you could get back']),
      el('span', { cls: 'sv-big', text: 'Up to ' + B(m.split.reclaimable) }),
      el('span', {
        cls: 'sv-term sv-reclaim-help', text: 'What do the colours mean?',
        attrs: { tabindex: '0', 'data-sv-term': 'Space you could get back', 'data-sv-tip': 'Junk the scan found, split by how safe it is to clean. Green and blue parts can be cleaned. Amber needs your decision. Grey is Windows: shown only so you know. Click a colour to see those items.' }
      }),
      m.wins.length ? null : toggle
    ]));
    rec.appendChild(stackBar(m.split, false));
    grid.appendChild(rec);
    host.appendChild(grid);

    // biggest wins
    if (m.wins.length) {
      var wins = el('div', { cls: 'sv-wins', attrs: { 'aria-label': 'Biggest wins: click one to see the items' } });
      wins.appendChild(el('div', { cls: 'sv-wins-head' }, [icon('sparkles'), el('span', { text: 'Biggest wins' }),
        el('span', { cls: 'sv-muted', text: '· click one to see the items' }), toggle]));
      m.wins.forEach(function (w) {
        var card = button(null, function () { nav(w.link); }, 'sv-win sv-g-' + (w.group || 'other'), { 'data-sv-tip': w.plain, 'data-sv-term': w.title });
        bvs(card, 'tile', null, 'Biggest win: ' + w.title + ' ' + B(w.bytes));
        card.appendChild(el('span', { cls: 'sv-win-ico' }, icon(CAT_ICON[w.cat] || GROUPS[w.group || 'other'].icon)));
        card.appendChild(el('span', { cls: 'sv-win-body' }, [
          el('span', { cls: 'sv-win-size', text: B(w.bytes) }),
          el('span', { cls: 'sv-win-title', text: w.title })
        ]));
        card.appendChild(icon('chevron', 'sv-win-go'));
        wins.appendChild(card);
      });
      host.appendChild(wins);
    }
    if (window.BVSFx && typeof window.BVSFx.slots === 'function') { window.BVSFx.slots(S.shell || host); } // UI-D: optional art
  }

  var SAFETY_LINK = {
    safe: '#/storage/junk?safety=safe', safe_after_check: '#/storage/junk?safety=safe_after_check',
    use_tool: '#/storage/junk?safety=use_tool', review: '#/storage/junk?safety=review', do_not_touch: '#/storage/system'
  };
  function stackBar(split, compact) {
    var wrap = el('div', { cls: 'sv-stack-wrap' + (compact ? ' compact' : '') });
    var total = SAFETY_ORDER.reduce(function (s, k) { return s + (split[k] || 0); }, 0) || 1;
    var bar = el('div', { cls: 'sv-stack', attrs: { role: 'group', 'aria-label': 'Space by clean-up safety' } });
    SAFETY_ORDER.forEach(function (s) {
      var v = split[s] || 0;
      if (!v) { return; }
      var info = SAFETY_INFO[s];
      var seg = link(compact ? null : el('span', { cls: 'sv-seg-label', text: v / total > 0.07 ? B(v) : '' }),
        SAFETY_LINK[s], 'sv-seg sv-s-' + s, { 'aria-label': info.label + ': ' + B(v) + '. Show these.', title: info.label + ': ' + B(v) });
      seg.style.flexGrow = String(Math.max(v / total, 0.012));
      bvs(seg, 'tile', null, info.label + ' ' + B(v));
      bar.appendChild(seg);
    });
    wrap.appendChild(bar);
    if (!compact) {
      var legend = el('div', { cls: 'sv-stack-legend' });
      SAFETY_ORDER.forEach(function (s) {
        var info = SAFETY_INFO[s];
        var chip = link([swatch('sv-s-' + s, info.icon), el('span', { cls: 'sv-leg-text' }, [
          el('span', { cls: 'sv-leg-label', text: info.short }), el('span', { cls: 'sv-leg-size', text: B(split[s] || 0) })
        ])], SAFETY_LINK[s], 'sv-leg-chip', { 'data-sv-tip': info.plain, 'data-sv-term': info.label });
        bvs(chip, 'tile', null, info.label + ' ' + B(split[s] || 0));
        legend.appendChild(chip);
      });
      wrap.appendChild(legend);
    }
    return wrap;
  }

  // ------------------------------------------------------------------ sections
  function renderSection() {
    var host = S.contentEl;
    if (!host) { return; }
    if (M.ro) { M.ro.disconnect(); M.ro = null; }
    M.box = null;
    U.clear(host);
    host.setAttribute('data-bvs-section', 'storage-' + S.section);
    if (S.section === 'map') { renderMapSection(host); } else { renderListSection(host, S.section); }
  }

  // ================================================================== MAP
  function squarify(values, x, y, w, h) {
    var n = values.length, out = new Array(n);
    if (!n || w <= 0 || h <= 0) { return out; }
    var total = 0, t;
    for (t = 0; t < n; t++) { total += values[t]; }
    if (total <= 0) { return out; }
    var scale = (w * h) / total;
    var areas = values.map(function (v) { return v * scale; });
    var i = 0, rx = x, ry = y, rw = w, rh = h;
    function worst(sum, min, max, side) {
      var s2 = sum * sum, w2 = side * side;
      return Math.max((w2 * max) / s2, s2 / (w2 * min));
    }
    while (i < n) {
      var side = Math.min(rw, rh);
      if (side <= 0) { for (; i < n; i++) { out[i] = { x: rx, y: ry, w: 0, h: 0 }; } break; }
      var sum = areas[i], min = areas[i], max = areas[i];
      var best = worst(sum, min, max, side);
      var j = i + 1;
      while (j < n) {
        var a = areas[j], s2 = sum + a, mn = Math.min(min, a), mx = Math.max(max, a);
        var wst = worst(s2, mn, mx, side);
        if (wst > best) { break; }
        sum = s2; min = mn; max = mx; best = wst; j++;
      }
      var k;
      if (rw >= rh) {
        var stripW = sum / rh, cy = ry;
        for (k = i; k < j; k++) { var hh = areas[k] / stripW; out[k] = { x: rx, y: cy, w: stripW, h: hh }; cy += hh; }
        rx += stripW; rw -= stripW;
      } else {
        var stripH = sum / rw, cx = rx;
        for (k = i; k < j; k++) { var ww = areas[k] / stripH; out[k] = { x: cx, y: ry, w: ww, h: stripH }; cx += ww; }
        ry += stripH; rh -= stripH;
      }
      i = j;
    }
    return out;
  }

  function current() { return M.stack[M.stack.length - 1]; }
  function rootLabel() { return 'This PC (' + String(M.meta.rootPath || (M.root && M.root.n) || '').replace(/[\\/]+$/, '') + ')'; }
  function pathAt(index) {
    var p = M.meta.rootPath || '';
    for (var i = 1; i <= index; i++) { p = joinPath(p, M.stack[i].n, M.meta.sep || '\\'); }
    return p || (M.root ? M.root.n : '');
  }
  function drillable(node) { return !!node && !node.y && ((node.x && node.x.length > 0) || !!node.k || !!node.e); }
  function displayName(node) {
    if (node.y === 'f') { return 'Files in this folder' + (node.f ? ' (' + U.fmtNum(node.f) + ')' : ''); }
    if (node.y === 'm') { return String(node.n || 'Smaller items').replace(/^\((.*)\)$/, '$1'); }
    return node === M.root ? rootLabel() : node.n;
  }
  function visibleKids(node) {
    return (node.x || []).filter(function (c) { return c.b > 0; }).sort(function (a, b) { return b.b - a.b; });
  }
  function safetyFromIdx(i) {
    var levels = M.meta.safetyLevels || ['safe', 'safe_after_check', 'review', 'use_tool', 'do_not_touch'];
    return levels[i] || null;
  }
  function guessGroup(name) {
    var n = String(name || '').toLowerCase();
    if (GUESS_MAP[n]) { return GUESS_MAP[n]; }
    if (/cache/.test(n)) { return 'caches'; }
    if (/^onedrive/.test(n)) { return 'personal'; }
    if (/^python\d+$/.test(n) || /^jdk/.test(n)) { return 'dev'; }
    if (/\.(exe|msi|msix)$/.test(n)) { return 'installers'; }
    return null;
  }
  function filesInfo(parentPath, node) {
    var list = S.model.filesByParent.get(keyOf(parentPath)) || [];
    if (!list.length) { return null; }
    var total = sumBytes(list);
    if (total < 0.3 * node.b) { return { items: list, item: null }; }
    var top = list.slice().sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0); })[0];
    var allSame = list.every(function (it) { return it.safety === top.safety; });
    return { items: list, item: top, allSame: allSame };
  }
  // What a node is: colour group, category, safety, matched storage item.
  function classify(node, path, ctx, parentPath) {
    var r = { group: null, cat: null, safety: null, item: null, strong: false, files: null };
    if (node.y === 'f') {
      var f = filesInfo(parentPath, node);
      r.files = f;
      if (f && f.item) { r.cat = f.item.category; r.group = catInfo(r.cat).group; r.safety = f.allSame ? f.item.safety : null; r.strong = true; }
      if (!r.safety) { r.safety = ctx.safety || null; }
      if (!r.group) { r.group = ctx.group || 'other'; }
      return r;
    }
    if (node.y) { r.group = ctx.group || 'other'; r.cat = ctx.cat; r.safety = ctx.safety || null; return r; }
    r.item = S.model.byPath.get(keyOf(path)) || null;
    if (r.item) { r.safety = r.item.safety; }
    else if (node.s !== undefined && node.s !== null) { r.safety = safetyFromIdx(node.s); }
    else { r.safety = ctx.safety || null; }
    var cat = r.item ? r.item.category : null;
    if (!cat && node.c !== undefined && node.c !== null) {
      cat = (M.meta.cats || [])[node.c] || null;
      if (cat === 'zero-byte' && node.b > 1048576) { cat = null; }
    }
    if (cat) { r.cat = cat; r.group = catInfo(cat, node.c).group; r.strong = true; return r; }
    if (ctx.strong) { r.group = ctx.group; r.cat = ctx.cat; r.strong = true; return r; }
    r.group = guessGroup(node.n) || ctx.group || 'other';
    return r;
  }
  function childCtx(cls) { return { group: cls.group, cat: cls.cat, strong: cls.strong, safety: cls.safety }; }
  function chainInfo() {
    var out = [], ctx = { group: null, cat: null, strong: false, safety: null };
    for (var i = 0; i < M.stack.length; i++) {
      var node = M.stack[i], cls;
      if (i === 0) { cls = { group: 'other', cat: null, safety: null, item: null, strong: false, isRoot: true }; }
      else { cls = classify(node, pathAt(i), ctx, pathAt(i - 1)); ctx = childCtx(cls); }
      out.push({ node: node, path: pathAt(i), cls: cls, ctx: ctx, parentNode: i > 0 ? M.stack[i - 1] : null, chain: [], depth: 0, isCurrent: i === M.stack.length - 1 });
    }
    return out;
  }
  function colourClass(node, cls) {
    if (M.mode === 'safety') { return 'sv-s-' + (SAFETY_INFO[cls.safety] ? cls.safety : 'none'); }
    if (M.mode === 'age') { return 'sv-a-' + (node.a >= 0 && node.a <= 3 ? node.a : 'none'); }
    return 'sv-g-' + (cls.group || 'other');
  }
  function modeKey(node, cls) {
    if (M.mode === 'safety') { return SAFETY_INFO[cls.safety] ? cls.safety : 'none'; }
    if (M.mode === 'age') { return node.a >= 0 && node.a <= 3 ? String(node.a) : 'none'; }
    return cls.group || 'other';
  }
  function legendEntries() {
    if (M.mode === 'safety') {
      return SAFETY_ORDER.map(function (s) { var i = SAFETY_INFO[s]; return { key: s, cls: 'sv-s-' + s, label: i.short, icon: i.icon, tip: i.plain, term: i.label }; })
        .concat([{ key: 'none', cls: 'sv-s-none', label: 'Not rated', icon: 'dots', tip: NOT_RATED.plain, term: 'Not rated' }]);
    }
    if (M.mode === 'age') {
      return [0, 1, 2, 3].map(function (a) { return { key: String(a), cls: 'sv-a-' + a, label: AGE_SHORT[a], icon: 'clock', tip: AGE_LABELS[a] + ' (when most of the data inside last changed).', term: AGE_LABELS[a] }; })
        .concat([{ key: 'none', cls: 'sv-a-none', label: 'Unknown', icon: 'dots', tip: 'No date known.', term: 'Unknown age' }]);
    }
    return GROUP_ORDER.map(function (g) { var i = GROUPS[g]; return { key: g, cls: 'sv-g-' + g, label: i.label, icon: i.icon, tip: i.plain, term: i.label }; });
  }
  function explainFolder(node, path, cls) {
    if (node.y === 'f') {
      var fi = cls.files && cls.files.item;
      return 'Files stored directly in this folder, not in a sub-folder.' + (fi ? ' The biggest is ' + fi.label + ' (' + B(fi.bytes) + '): ' + (fi.purpose || catLabel(fi.category)) : '');
    }
    if (node.y === 'm') { return 'Many smaller folders grouped together so the map stays readable.'; }
    if (node === M.root) { return 'Your whole disk. Each box is a folder; the bigger the box, the more space it uses.'; }
    if (cls.item && cls.item.purpose) { return cls.item.purpose; }
    var k = KNOWN[String(node.n || '').toLowerCase()];
    if (k) { return k; }
    if (cls.cat && catInfo(cls.cat).plain) { return catInfo(cls.cat).plain; }
    var g = GROUPS[cls.group || 'other'];
    return 'A folder in the "' + g.label + '" group. ' + g.plain;
  }
  function genericHow(cls) {
    switch (cls.group) {
      case 'system': return 'Leave this folder alone. Windows needs it.';
      case 'personal': return 'These are your own files. Keep them, or copy them to an external drive or cloud first and then remove them yourself.';
      case 'apps': return 'Remove programs from Settings > Apps (or the program\'s own settings), never by deleting the folder.';
      case 'caches': return 'Caches are cleared from the app that made them. Look at the clean-up items inside, if any.';
      case 'dev': return 'Developer data. Dependencies and build output can usually be rebuilt; look at the clean-up items inside.';
      case 'installers': return 'Check the items inside: setup files you already used can usually go.';
      default: return 'The scan has no clean-up rule for this folder. Look inside before deciding anything.';
    }
  }

  function renderMapSection(host) {
    var tm = S.model.tm;
    var head = el('header', { cls: 'svm-head sv-acc-map' }, [
      el('span', { cls: 'svm-head-ico' }, icon('grid')),
      el('div', { cls: 'svm-head-text' }, [
        el('h2', { cls: 'sv-h2', text: 'Map of your disk' }),
        el('p', { cls: 'svm-hint' }, ['Each ', term('box', 'treemap'), ' is a folder; a bigger box uses more space. ',
          el('strong', { text: 'Click' }), ' a box to learn what it is, ', el('strong', { text: 'double-click' }), ' to look inside.'])
      ])
    ]);
    host.appendChild(head);
    if (!tm) {
      host.appendChild(el('div', { cls: 'sv-card sv-empty' }, [icon('grid'), el('p', { text: 'No storage map yet: it is built from the folder inventory once that module has run.' })]));
      return;
    }
    if (M.root !== tm.root) { M.root = tm.root; M.meta = tm.meta || {}; M.stack = [tm.root]; M.prefetched = false; }

    var toolbar = el('div', { cls: 'svm-toolbar' });
    M.backBtn = button([icon('back'), 'Back'], function () { up(); }, 'small', { 'aria-label': 'Back to the folder above' });
    M.crumbs = el('nav', { cls: 'svm-crumbs', attrs: { 'aria-label': 'Folder path' } });
    var modes = el('div', { cls: 'sv-seg-ctl', attrs: { role: 'group', 'aria-label': 'Colour the boxes by' } });
    M.modeBtns = [['category', 'What it is', 'apps'], ['safety', 'Safe to clean?', 'check'], ['age', 'How old', 'clock']].map(function (mo) {
      var b = button([icon(mo[2]), mo[1]], function () {
        M.mode = mo[0];
        M.hl = null;
        U.storage.set('bvs.storage.mode', M.mode);
        renderMapAll();
      }, 'seg', { 'aria-pressed': String(M.mode === mo[0]) });
      b.setAttribute('data-mode', mo[0]);
      modes.appendChild(b);
      return b;
    });
    head.appendChild(el('span', { cls: 'svm-colour-by' }, [el('span', { cls: 'sv-muted', text: 'Colour by' }), modes]));
    toolbar.appendChild(M.backBtn);
    toolbar.appendChild(M.crumbs);
    host.appendChild(toolbar);

    M.banner = el('div', { cls: 'svm-banner', hidden: true, attrs: { 'aria-live': 'polite' } });
    host.appendChild(M.banner);

    var layout = el('div', { cls: 'svm-layout' });
    var left = el('div', { cls: 'svm-left' });
    var box = el('div', { cls: 'svm-box', attrs: { role: 'img' } });
    left.appendChild(box);
    M.note = el('p', { cls: 'sv-muted svm-note' });
    left.appendChild(M.note);
    var side = el('aside', { cls: 'svm-side', attrs: { 'aria-label': 'Colours and folder details' } });
    M.legendTitle = el('h3', { cls: 'sv-h3', text: 'What the colours mean' });
    M.legend = el('div', { cls: 'svm-legend', attrs: { role: 'group', 'aria-label': 'Legend: click a colour to highlight it' } });
    side.appendChild(el('section', { cls: 'sv-card svm-legend-card' }, [M.legendTitle, M.legend]));
    M.sideEl = el('div', { cls: 'svm-side-dyn' });
    side.appendChild(M.sideEl);
    layout.appendChild(left);
    layout.appendChild(side);
    host.appendChild(layout);
    M.box = box;

    box.addEventListener('pointermove', onTileHover);
    box.addEventListener('pointerleave', hideTip);
    box.addEventListener('click', function (ev) {
      var div = ev.target.closest ? ev.target.closest('.svm-tile') : null;
      var info = div && M.info ? M.info.get(div) : null;
      if (!info) { return; }
      clearTimeout(M.clickT);
      M.clickT = setTimeout(function () { hideTip(); openFolderPanel(info); }, 240);
    });
    box.addEventListener('dblclick', function (ev) {
      // UI-D (decorative): remember where the user double-clicked, so the zoom transition grows from there
      var br = box.getBoundingClientRect();
      M.fxOrigin = (ev.clientX - br.left).toFixed(0) + 'px ' + (ev.clientY - br.top).toFixed(0) + 'px';
      clearTimeout(M.clickT);
      var div = ev.target.closest ? ev.target.closest('.svm-tile') : null;
      var info = div && M.info ? M.info.get(div) : null;
      if (!info) { return; }
      hideTip();
      if (drillable(info.node) || info.chain.slice(0, -1).some(drillable)) {
        drillChain(info.chain).then(function (pushed) { if (!pushed) { openFolderPanel(info); } });
      } else { openFolderPanel(info); }
    });
    if (window.ResizeObserver) {
      var lastW = 0, lastH = 0;
      var onResize = U.debounce(function () {
        if (!M.box) { return; }
        var w = M.box.clientWidth, h = M.box.clientHeight;
        if (w !== lastW || h !== lastH) { lastW = w; lastH = h; renderMap(); }
      }, 120);
      M.ro = new ResizeObserver(onResize);
      M.ro.observe(box);
    }

    if (S.query.path) { drillToPath(S.query.path); }
    else {
      M.stack = [M.root];
      M.target = null; M.remain = [];
      renderMapAll();
    }
  }

  function renderMapAll() {
    if (!M.box) { return; }
    M.chain = chainInfo();
    M.modeBtns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-mode') === M.mode)); });
    renderCrumbs();
    renderMap();
    renderBanner();
    renderLegend();
    renderMapSide();
    prefetch();
  }

  function renderCrumbs() {
    U.clear(M.crumbs);
    M.stack.forEach(function (node, i) {
      if (i > 0) { M.crumbs.appendChild(el('span', { cls: 'svm-sep', text: '›', attrs: { 'aria-hidden': 'true' } })); }
      var last = i === M.stack.length - 1;
      var b = button(i === 0 ? [icon('disk'), rootLabel()] : pvName(pathAt(i), node.n), last ? null : function () {
        M.stack.length = i + 1;
        M.target = null; M.remain = [];
        renderMapAll();
        syncHash();
      }, 'crumb', { 'aria-current': last ? 'location' : null });
      M.crumbs.appendChild(b);
    });
    M.backBtn.disabled = M.stack.length <= 1;
  }

  function renderBanner() {
    var bn = M.banner;
    U.clear(bn);
    if (!M.target) { bn.hidden = true; return; }
    var item = S.model.byPath.get(M.target.key) || null;
    var msg;
    if (!M.remain.length) { msg = 'You are looking inside the folder you picked.'; }
    else if (M.remain.length === 1 && M.highlighted === 'files') { msg = 'It is one of the files stored directly in this folder: the highlighted box.'; }
    else if (M.remain.length === 1 && M.highlighted) { msg = 'It is the highlighted box below.'; }
    else { msg = 'The map does not split folders this small, so it shows the closest folder that contains it' + (M.highlighted ? ' (highlighted).' : '.'); }
    bn.appendChild(icon('pin'));
    bn.appendChild(el('div', { cls: 'svm-banner-text' }, [el('strong', { text: item ? item.label : M.target.path.split(/[\\/]/).filter(Boolean).pop() || M.target.path }),
      el('span', { cls: 'sv-muted', text: ' · ' + msg }), el('div', { cls: 'svm-banner-path', text: M.target.path })]));
    if (item) { bn.appendChild(button(['Details', icon('chevron')], function () { openItemPanel(item); }, 'small')); }
    bn.appendChild(button(icon('close'), function () { M.target = null; M.remain = []; renderMapAll(); }, 'ghost small icon-only', { 'aria-label': 'Hide this note' }));
    bn.hidden = false;
  }

  function renderMap() {
    var box = M.box;
    if (!box) { return; }
    var node = current();
    var W = box.clientWidth, H = box.clientHeight;
    U.clear(box);
    hideTip();
    M.info = new WeakMap();
    M.highlighted = false;
    M.viewBytes = {};
    var kids = visibleKids(node);
    box.setAttribute('aria-label', 'Map of ' + U.safeText(displayName(node)) + ': ' + kids.length + ' items. The list next to it has the same information.');
    if (!W || !H) { return; }
    if (M.error) { M.note.textContent = M.error; M.error = ''; } else { M.note.textContent = ''; }
    if (!kids.length) {
      box.appendChild(el('div', { cls: 'svm-empty', text: node.h ? 'This folder has ' + node.h + ' sub-folders, but all are too small to show separately.' : 'Nothing inside is big enough to show.' }));
      return;
    }
    var cur = M.chain[M.chain.length - 1];
    var budget = { lv: [0, 0, 0, 0, 0, 0, 0], total: 0, hidden: 0 };
    layoutInto(box, kids, 0, 0, W, H, 1, 1, cur.ctx, cur.path, [], node, budget);
    if (budget.hidden) { M.note.textContent = budget.hidden + ' small items are too small to draw: they are in the list on the right.'; }
    applyHighlight();
    fxZoom(box);
  }

  // UI-D (decorative): one zoom transition on the whole map box when the folder level changes (never one
  // animation per tile). Off under prefers-reduced-motion (the CSS has no animation there either).
  function fxZoom(box) {
    var depth = M.stack.length, prev = M.fxDepth;
    M.fxDepth = depth;
    if (!prev || prev === depth) { return; }
    try { if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) { return; } } catch (e) { return; }
    box.classList.remove('svm-zoom-in', 'svm-zoom-out');
    box.style.transformOrigin = depth > prev && M.fxOrigin ? M.fxOrigin : '50% 50%';
    void box.offsetWidth; // restart the animation
    box.classList.add(depth > prev ? 'svm-zoom-in' : 'svm-zoom-out');
    M.fxOrigin = null;
  }

  // Draws kids into container and returns the bytes it accounted for in the legend (every visible
  // box, plus the part of a nested box that its drawn children do not cover). `level` is the visual
  // nesting level: a folder that is almost entirely one sub-folder (Users -> you) does not use one up.
  function layoutInto(container, kids, x, y, w, h, depth, level, ctx, parentPath, chain, parentNode, budget) {
    var rects = squarify(kids.map(function (c) { return c.b; }), x, y, w, h);
    var sep = M.meta.sep || '\\';
    var minSide = depth === 1 ? 3 : 12;
    var accounted = 0;
    function add(node, cls, bytes) { var k = modeKey(node, cls); M.viewBytes[k] = (M.viewBytes[k] || 0) + bytes; }
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i], r = rects[i];
      var path = c.y ? parentPath : joinPath(parentPath, c.n, sep);
      var lvIdx = Math.min(depth, budget.lv.length - 1);
      if (!r || r.w < minSide || r.h < minSide || budget.lv[lvIdx] >= MAX_PER_LEVEL || budget.total >= MAX_TILES) {
        if (depth === 1) { budget.hidden++; add(c, classify(c, path, ctx, parentPath), c.b); accounted += c.b; }
        continue;
      }
      var cls = classify(c, path, ctx, parentPath);
      var kids2 = (!c.y && depth < 6 && r.w >= 120 && r.h >= 80) ? visibleKids(c) : null;
      var single = !!(kids2 && kids2.length && kids2[0].b >= 0.9 * c.b);
      if (kids2 && level >= MAX_DEPTH && !single) { kids2 = null; }
      var nest = !!(kids2 && kids2.length);
      var info = { node: c, path: path, cls: cls, chain: chain.concat([c]), parentNode: parentNode, depth: depth };
      var div = makeTile(info, r, nest);
      container.appendChild(div);
      budget.lv[lvIdx]++;
      budget.total++;
      accounted += c.b;
      var covered = 0;
      if (nest) {
        var iw = r.w - 2 - 6, ih = r.h - 2 - HEADER_H - 3;
        if (iw > 16 && ih > 16) {
          covered = layoutInto(div, kids2, 3, HEADER_H, iw, ih, depth + 1, single ? level : level + 1, childCtx(cls), path, info.chain, c, budget);
        }
      }
      add(c, cls, Math.max(0, c.b - covered));
    }
    return accounted;
  }

  function isTarget(info) {
    if (!M.remain.length || info.depth !== 1) { return false; }
    var want = M.remain[0];
    if (!info.node.y && sameName(info.node.n, want)) { return true; }
    if (info.node.y === 'f' && M.remain.length === 1) {
      return !(current().x || []).some(function (k) { return !k.y && sameName(k.n, want); });
    }
    return false;
  }

  function makeTile(info, r, nest) {
    var node = info.node, cls = info.cls;
    var div = document.createElement('div');
    var locked = cls.safety === 'do_not_touch' || (M.mode === 'category' && cls.group === 'system');
    div.className = 'svm-tile d' + info.depth + ' ' + colourClass(node, cls) + (node.y ? ' pseudo' : '') + (nest ? ' nest' : '') + (locked ? ' locked' : '');
    var w = Math.max(0, r.w - 2), h = Math.max(0, r.h - 2);
    div.style.left = (r.x + 1) + 'px';
    div.style.top = (r.y + 1) + 'px';
    div.style.width = w + 'px';
    div.style.height = h + 'px';
    var item = cls.item;
    var shownName = pvName(info.path, displayName(node));
    bvs(div, item ? 'storageItem' : 'tile', item ? item.id : null, shownName + ' (' + B(node.b) + ')');
    if (w >= 54 && h >= 18) {
      var lab = el('div', { cls: 'svm-label', attrs: { 'aria-hidden': 'true' } });
      if (locked && w >= 80) { lab.appendChild(icon('lock', 'svm-lock')); }
      lab.appendChild(el('span', { cls: 'svm-name', text: shownName }));
      if (nest || (h < 36 && w >= 100)) { lab.appendChild(el('span', { cls: 'svm-size inline', text: B(node.b) })); }
      else if (h >= 36) { lab.appendChild(el('span', { cls: 'svm-size', text: B(node.b) })); }
      div.appendChild(lab);
    }
    if (item && !nest && w >= 64 && h >= 44) {
      var flag = el('span', { cls: 'svm-flag sv-s-' + (SAFETY_INFO[item.safety] ? item.safety : 'none'), attrs: { 'aria-hidden': 'true' } }, icon(safetyInfo(item.safety).icon));
      div.appendChild(flag);
    }
    if (isTarget(info)) { div.classList.add('target'); M.highlighted = node.y === 'f' ? 'files' : 'box'; }
    M.info.set(div, info);
    return div;
  }

  function applyHighlight() {
    if (!M.box) { return; }
    var tiles = M.box.querySelectorAll('.svm-tile');
    for (var i = 0; i < tiles.length; i++) {
      var info = M.info.get(tiles[i]);
      var k = info ? modeKey(info.node, info.cls) : null;
      tiles[i].classList.toggle('dim', !!M.hl && k !== M.hl);
      tiles[i].classList.toggle('hl', !!M.hl && k === M.hl);
    }
    if (M.legend) {
      Array.prototype.forEach.call(M.legend.querySelectorAll('[data-key]'), function (b) {
        b.setAttribute('aria-pressed', String(M.hl === b.getAttribute('data-key')));
      });
      M.legend.classList.toggle('filtering', !!M.hl);
      var hint = M.legend.querySelector('.svm-leg-hint');
      if (hint) { hint.textContent = M.hl ? 'Click it again to show all colours.' : 'Click a colour to highlight those boxes.'; }
    }
  }

  function renderLegend() {
    var lg = M.legend;
    U.clear(lg);
    var cur = current();
    M.legendTitle.textContent = M.mode === 'safety' ? 'Safe to clean?' : M.mode === 'age' ? 'How old is the data?' : 'What the colours mean';
    var entries = legendEntries();
    var max = entries.reduce(function (mx, e) { return Math.max(mx, M.viewBytes[e.key] || 0); }, 0);
    entries.forEach(function (e) {
      var bytes = M.viewBytes[e.key] || 0;
      var b = button([swatch(e.cls, e.icon), el('span', { cls: 'svm-leg-label', text: e.label }),
        el('span', { cls: 'svm-leg-size', text: bytes ? U.pct(bytes, cur.b) : '—' }),
        sizeBar(bytes, max, e.cls)
      ], function () {
        M.hl = M.hl === e.key ? null : e.key;
        applyHighlight();
      }, 'svm-leg' + (bytes ? '' : ' empty'), {
        'aria-pressed': String(M.hl === e.key), 'data-key': e.key, 'data-sv-tip': e.tip + (bytes ? ' Here: ' + B(bytes) + '.' : ''), 'data-sv-term': e.term
      });
      bvs(b, 'tile', null, 'Legend: ' + e.label + (bytes ? ' ' + B(bytes) : ''));
      lg.appendChild(b);
    });
    lg.appendChild(el('p', { cls: 'svm-leg-hint sv-muted', text: M.hl ? 'Click it again to show all colours.' : 'Click a colour to highlight those boxes.' }));
  }

  function onTileHover(ev) {
    var div = ev.target.closest ? ev.target.closest('.svm-tile') : null;
    var info = div && M.info ? M.info.get(div) : null;
    if (!info) { hideTip(); return; }
    var t = tip();
    if (M.lastTipDiv !== div) {
      M.lastTipDiv = div;
      t.classList.remove('term');
      U.clear(t);
      var node = info.node, cls = info.cls;
      var head = el('div', { cls: 'sv-tt-head' });
      if (M.mode === 'safety') {
        var si = safetyInfo(cls.safety);
        head.appendChild(swatch('sv-s-' + (SAFETY_INFO[cls.safety] ? cls.safety : 'none'), si.icon));
        head.appendChild(el('span', { text: si.label }));
      } else if (M.mode === 'age') {
        var a = node.a >= 0 && node.a <= 3 ? node.a : -1;
        head.appendChild(swatch('sv-a-' + (a >= 0 ? a : 'none'), 'clock'));
        head.appendChild(el('span', { text: a >= 0 ? AGE_LABELS[a] : 'Age unknown' }));
      } else {
        var g = GROUPS[cls.group || 'other'];
        head.appendChild(swatch('sv-g-' + (cls.group || 'other'), g.icon));
        head.appendChild(el('span', { text: g.label + (cls.cat ? ' · ' + catLabel(cls.cat) : '') }));
      }
      t.appendChild(head);
      t.appendChild(el('div', { cls: 'sv-tt-name', text: pvName(info.path, displayName(node)) }));
      var parent = info.parentNode;
      t.appendChild(el('div', { cls: 'sv-tt-size' }, [el('strong', { text: B(node.b) }),
        parent && parent.b ? ' · ' + U.pct(node.b, parent.b) + ' of ' + displayName(parent) : '']));
      if (node.t) {
        t.appendChild(el('div', { cls: 'sv-tt-row' }, [icon('clock'), 'Last changed ' + plainAge(node.t) + (node.a >= 0 && node.a <= 3 ? ' · most of it ' + AGE_SHORT[node.a] + ' old' : '')]));
      }
      t.appendChild(el('div', { cls: 'sv-tt-what' }, [el('span', { cls: 'sv-tt-k', text: 'What it is: ' }), shortText(pvName(info.path, explainFolder(node, info.path, cls)), 180)]));
      if (cls.safety) { t.appendChild(el('div', { cls: 'sv-tt-row' }, [icon(safetyInfo(cls.safety).icon), 'Clean-up: ' + safetyInfo(cls.safety).label])); }
      t.appendChild(el('div', { cls: 'sv-tt-hint', text: drillable(node) ? 'Click for details · double-click to look inside' : 'Click for details' }));
      t.hidden = false;
    }
    placeTipAtPoint(ev.clientX, ev.clientY);
  }

  // ---------------------------------------------------------------- map navigation
  function dataBase() {
    var a = app() || {};
    var cand = a.dataBase || a.base;
    if (typeof cand === 'string' && /\/$/.test(cand)) { return cand; }
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
      var src = scripts[i].getAttribute('src') || '';
      var mm = /^(.*\/js\/)(manifest|treemap|storage|summary|duplicates|findings)\.js(?:[?#].*)?$/.exec(src);
      if (mm) { return mm[1]; }
    }
    var latest = window.BVS_LATEST;
    if (typeof latest === 'string' && NAME_RE.test(latest)) { return '../data/' + latest + '/js/'; }
    return '../data/';
  }
  function loadChunk(name) {
    if (!NAME_RE.test(String(name))) { return Promise.reject(new Error('bad chunk name')); }
    if (window.BVS.get(name)) { return Promise.resolve(); }
    var a = app();
    if (a && typeof a.loadChunk === 'function') { return Promise.resolve(a.loadChunk(name)); }
    if (!M.chunkP[name]) {
      M.chunkP[name] = window.BVS.loadScript(dataBase() + name + '.js').catch(function (e) { delete M.chunkP[name]; throw e; });
    }
    return M.chunkP[name];
  }
  function ensureLoaded(node) {
    if (!node || !node.pv || !node.k) { return Promise.resolve(node); }
    if (M.box) { M.box.classList.add('loading'); }
    return loadChunk(node.k).then(function () {
      var chunk = window.BVS.get(node.k);
      if (chunk && Array.isArray(chunk.x)) { node.x = chunk.x; delete node.pv; }
      if (M.box) { M.box.classList.remove('loading'); }
      return node;
    }, function () {
      if (M.box) { M.box.classList.remove('loading'); }
      M.error = 'Could not load this part of the map.';
      return node;
    });
  }
  function resolveKid(parent, ref) {
    var xs = parent.x || [];
    if (xs.indexOf(ref) >= 0) { return ref; }
    for (var i = 0; i < xs.length; i++) { if (!xs[i].y && xs[i].n === ref.n) { return xs[i]; } }
    return null;
  }
  function findKid(parent, name) {
    var xs = parent.x || [];
    for (var i = 0; i < xs.length; i++) { if (!xs[i].y && sameName(xs[i].n, name)) { return xs[i]; } }
    return null;
  }
  function drillChain(chain) {
    var seq = Promise.resolve(), stop = false, pushed = 0;
    chain.forEach(function (ref) {
      seq = seq.then(function () {
        if (stop) { return; }
        var parent = current();
        return ensureLoaded(parent).then(function () {
          var real = resolveKid(parent, ref);
          if (!real || !drillable(real)) { stop = true; return; }
          return ensureLoaded(real).then(function (n) {
            if (n.x && n.x.length) { M.stack.push(n); pushed++; } else { stop = true; }
          });
        });
      });
    });
    return seq.then(function () {
      if (pushed) { M.target = null; M.remain = []; renderMapAll(); syncHash(); }
      return pushed;
    });
  }
  function drillToPath(target) {
    var rootPath = M.meta.rootPath || '';
    var tkey = keyOf(target), rkey = keyOf(rootPath);
    M.stack = [M.root];
    M.target = { path: target, key: tkey };
    M.remain = [];
    if (rkey && !inside(tkey, rkey)) { renderMapAll(); return Promise.resolve(); }
    var rest = String(target).slice(rootPath.replace(/[\\/]+$/, '').length).split(/[\\/]+/).filter(Boolean);
    var seq = Promise.resolve(), stop = false;
    rest.forEach(function (name, i) {
      seq = seq.then(function () {
        if (stop) { return; }
        var cur = current();
        return ensureLoaded(cur).then(function () {
          var kid = findKid(cur, name) || (name.indexOf('+') >= 0 ? findKid(cur, name.replace(/\+/g, ' ')) : null);
          if (!kid) { stop = true; M.remain = rest.slice(i); return; }
          if (kid.x && kid.x.length || kid.k) { M.stack.push(kid); } else { stop = true; M.remain = rest.slice(i); }
        });
      });
    });
    return seq.then(function () { return ensureLoaded(current()); }).then(function () { if (M.box) { renderMapAll(); } });
  }
  function up() {
    if (M.stack.length > 1) {
      M.stack.pop();
      M.target = null; M.remain = [];
      renderMapAll();
      syncHash();
    }
  }
  function syncHash() {
    var p = M.stack.length > 1 ? pathAt(M.stack.length - 1) : null;
    var h = mapHash(p);
    replaceHash(h);
    S.query = p ? { path: p } : {};
    S.routeKey = routeKeyOf({ section: 'map', query: S.query });
  }
  // Load the biggest top-level chunks in the background so the first map shows three levels.
  function prefetch() {
    if (M.prefetched || !M.root || M.stack.length !== 1) { return; }
    M.prefetched = true;
    var big = visibleKids(M.root).filter(function (c) { return c.pv && c.k && c.b >= 0.04 * M.root.b; }).slice(0, 3);
    if (!big.length) { return; }
    var seq = Promise.resolve();
    big.forEach(function (c) {
      seq = seq.then(function () {
        return new Promise(function (res) { setTimeout(res, 40); }).then(function () { return ensureLoaded(c); }).then(function () {
          if (M.box && S.section === 'map' && M.stack.length === 1) { renderMap(); renderLegend(); renderMapSide(); }
        });
      });
    });
  }

  // ---------------------------------------------------------------- map side column
  function renderMapSide() {
    var side = M.sideEl;
    if (!side) { return; }
    U.clear(side);
    var curInfo = M.chain[M.chain.length - 1];
    var node = curInfo.node, cls = curInfo.cls;
    var g = node === M.root ? 'other' : (cls.group || 'other');

    var here = el('section', { cls: 'sv-card svm-here sv-g-' + g });
    bvs(here, cls.item ? 'storageItem' : 'tile', cls.item ? cls.item.id : null, 'You are here: ' + pvPath(curInfo.path));
    here.appendChild(el('div', { cls: 'sv-kicker', text: 'You are here' }));
    here.appendChild(el('div', { cls: 'svm-here-head' }, [
      el('span', { cls: 'svm-here-ico' }, icon(node === M.root ? 'disk' : GROUPS[g].icon)),
      el('div', { cls: 'svm-here-name' }, [el('strong', { text: pvName(curInfo.path, displayName(node)) }), el('span', { cls: 'svm-here-path', text: pvPath(curInfo.path) })])
    ]));
    here.appendChild(el('div', { cls: 'svm-here-stats' }, [
      ring(node.b / S.model.used, pctDisk(node.b), 'sv-ring-acc small'),
      el('div', null, [el('div', { cls: 'sv-big', text: B(node.b) }), el('div', { cls: 'sv-muted', text: 'of the used disk space' + (node.t ? ' · changed ' + plainAge(node.t) : '') })])
    ]));
    here.appendChild(el('p', { cls: 'svm-here-text', text: shortText(pvName(curInfo.path, explainFolder(node, curInfo.path, cls)), 200) }));
    here.appendChild(button(['What is this folder?', icon('chevron')], function () { openFolderPanel(curInfo); }, 'small'));
    side.appendChild(here);

    // biggest inside
    var kids = visibleKids(node);
    var max = kids.length ? kids[0].b : 0;
    var list = el('section', { cls: 'sv-card svm-kids' });
    list.appendChild(el('h3', { cls: 'sv-h3', text: 'Biggest inside' }));
    var ul = el('ul', { cls: 'svm-kid-list', attrs: { role: 'list' } });
    kids.slice(0, 12).forEach(function (k) {
      var path = k.y ? curInfo.path : joinPath(curInfo.path, k.n, M.meta.sep || '\\');
      var kcls = classify(k, path, curInfo.ctx, curInfo.path);
      var info = { node: k, path: path, cls: kcls, chain: [k], parentNode: node, depth: 1 };
      var can = drillable(k);
      var kName = pvName(path, displayName(k));
      var row = button([
        swatch(colourClass(k, kcls)),
        el('span', { cls: 'svm-kid-name', text: kName }),
        el('span', { cls: 'svm-kid-size', text: B(k.b) }),
        sizeBar(k.b, max, colourClass(k, kcls))
      ], function () { if (can) { drillChain([k]); } else { openFolderPanel(info); } }, 'svm-kid', { title: can ? 'Open ' + kName : 'About ' + kName });
      bvs(row, kcls.item ? 'storageItem' : 'tile', kcls.item ? kcls.item.id : null, kName + ' (' + B(k.b) + ')');
      var infoBtn = button(icon('info'), function () { openFolderPanel(info); }, 'ghost small icon-only svm-kid-info', { 'aria-label': 'What is ' + U.safeText(kName) + '?' });
      ul.appendChild(el('li', null, [row, infoBtn]));
    });
    if (!kids.length) { ul.appendChild(el('li', { cls: 'sv-muted', text: 'Nothing big enough to list.' })); }
    list.appendChild(ul);
    if (kids.length > 12) { list.appendChild(el('p', { cls: 'sv-muted small', text: '… and ' + (kids.length - 12) + ' smaller items' })); }
    side.appendChild(list);

    // clean-up items inside this folder
    var fk = node === M.root ? '' : keyOf(curInfo.path);
    var items = S.model.all.filter(function (it) { return inside(it.__key, fk); })
      .sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0); });
    if (items.length) {
      var card = el('section', { cls: 'sv-card svm-items' });
      card.appendChild(el('h3', { cls: 'sv-h3' }, ['Clean-up items here ', el('span', { cls: 'sv-badge soft', text: String(items.length) })]));
      var ul2 = el('ul', { cls: 'svm-item-list', attrs: { role: 'list' } });
      items.slice(0, 6).forEach(function (it) {
        var si = safetyInfo(it.safety);
        var b = button([swatch('sv-s-' + (SAFETY_INFO[it.safety] ? it.safety : 'none'), si.icon), el('span', { cls: 'svm-kid-name', text: pvName(it.path, it.label) }), el('span', { cls: 'svm-kid-size', text: B(it.bytes) })],
          function () { openItemPanel(it); }, 'svm-item', { title: si.label + ' · ' + pvPath(it.path) });
        bvs(b, 'storageItem', it.id, pvName(it.path, it.label));
        ul2.appendChild(el('li', null, b));
      });
      card.appendChild(ul2);
      var junkInside = S.model.junk.filter(function (it) { return inside(keyOf(it.path), fk); }).length;
      if (items.length > 6 && junkInside && fk) {
        card.appendChild(link(['See all ' + junkInside + ' in Junk & caches', icon('chevron')], '#/storage/junk?path=' + encodeURIComponent(curInfo.path), 'sv-link small'));
      } else if (items.length > 6) {
        card.appendChild(el('p', { cls: 'sv-muted small', text: '… and ' + (items.length - 6) + ' more in the lists on the left' }));
      }
      side.appendChild(card);
    }
  }

  // ================================================================== PANELS
  function openPanel(spec) {
    var a = app();
    if (!a || typeof a.openPanel !== 'function') { return; }
    var render = spec.render;
    // The shell calls render again when it re-renders the panel (for example after its own basket
    // button is used), so de-duplicate after every render.
    spec.render = function (body) {
      render(body);
      setTimeout(function () { dedupePanel(body); }, 0);
      setTimeout(function () { dedupePanel(body); }, 120);
    };
    a.openPanel(spec);
  }
  // The shell may add its own "Ask INFOSEC" / "Add to basket" buttons to every panel (ui-contract).
  // Hide ours when it does, so each button appears exactly once.
  function dedupePanel(body) {
    if (!body || !body.isConnected) { return; }
    var drawer = body.closest('[role="dialog"], [role="complementary"], aside, .drawer, .side-panel') || (body.parentElement && body.parentElement.parentElement) || body.parentElement;
    if (!drawer || drawer === body) { return; }
    var hasAsk = false, hasBasket = false;
    Array.prototype.forEach.call(drawer.querySelectorAll('button, a'), function (b) {
      if (body.contains(b)) { return; }
      var t = (b.textContent || '').toLowerCase();
      if (t.indexOf('infosec') >= 0) { hasAsk = true; }
      if (t.indexOf('basket') >= 0) { hasBasket = true; }
    });
    Array.prototype.forEach.call(body.querySelectorAll('.sv-own-infosec'), function (n) { n.hidden = hasAsk; });
    Array.prototype.forEach.call(body.querySelectorAll('.sv-own-basket'), function (n) { n.hidden = hasBasket; });
  }
  // What the shell receives as `item`: blocked items get method "none" so no shell basket button appears.
  function panelItem(subject) {
    if (subject && subject.id && basketBlockReason(subject)) { return Object.assign({}, subject, { method: 'none', basketBlocked: basketBlockReason(subject) }); }
    return subject;
  }
  function askInfosec(subject, isFolder) {
    var a = app();
    var prefill = 'What is "' + U.safeText(subject.label) + '" (' + U.safeText(subject.path) + ', ' + B(subject.bytes) + ')? Is it safe to clean, and how?';
    var context = {
      kind: 'storageItem', id: subject.id || null, label: subject.label, path: subject.path, bytes: subject.bytes,
      category: subject.category || null, safety: subject.safety || null, purpose: subject.purpose || null, how: subject.how || null,
      folder: !!isFolder
    };
    if (a && typeof a.openInfosec === 'function') { a.openInfosec({ prefill: prefill, context: context }); }
    else { nav('#/infosec'); }
  }
  function copyPath(path, status) {
    U.copyText(String(path || '')).then(function (ok) {
      status.textContent = ok ? 'Path copied.' : 'Copy is not available here: select the path above and press Ctrl+C.';
    });
  }
  function panelHero(ic, kicker, title, path, cls) {
    return el('div', { cls: 'sv-p-hero ' + (cls || '') }, [
      el('span', { cls: 'sv-p-ico' }, icon(ic)),
      el('div', { cls: 'sv-p-hero-text' }, [
        el('div', { cls: 'sv-kicker', text: kicker }),
        el('div', { cls: 'sv-p-title', text: pvName(path, title) }),
        el('div', { cls: 'sv-p-path', text: pvPath(path) })
      ])
    ]);
  }
  function fact(label, value, sub, visual) {
    return el('div', { cls: 'sv-p-fact' }, [visual || null, el('div', null, [
      el('div', { cls: 'sv-p-fact-label', text: label }),
      el('div', { cls: 'sv-p-fact-value', text: value }),
      sub ? el('div', { cls: 'sv-p-fact-sub', text: sub }) : null
    ])]);
  }
  function safetyBlock(s) {
    var info = safetyInfo(s);
    return el('div', { cls: 'sv-p-safety sv-s-' + (SAFETY_INFO[s] ? s : 'none') }, [
      el('span', { cls: 'sv-p-safety-ico' }, icon(info.icon)),
      el('div', null, [el('div', { cls: 'sv-p-safety-label', text: info.label }), el('div', { cls: 'sv-p-safety-plain', text: info.plain })])
    ]);
  }
  function panelActions(subject, opts) {
    opts = opts || {};
    var row = el('div', { cls: 'sv-p-actions' });
    if (opts.drill) { row.appendChild(button([icon('grid'), 'Show the biggest items inside'], function () { closePanel(); opts.drill(); }, 'primary')); }
    if (opts.mapPath) {
      var mp = link([icon('pin'), 'Show in map'], mapHash(opts.mapPath), 'sv-btn');
      mp.addEventListener('click', function () { closePanel(); });
      row.appendChild(mp);
    }
    var notes = [];
    if (subject.id && basket()) {
      var reason = basketBlockReason(subject);
      if (!reason) {
        var bt = basketToggle(subject, false);
        bt.classList.add('sv-own-basket');
        row.appendChild(bt);
      } else {
        notes.push(el('p', { cls: 'sv-p-note' }, [icon('lock'), el('span', { text: 'Not for the basket: ' + reason })]));
      }
    }
    var ask = button([icon('shield'), opts.folder ? 'Ask INFOSEC about this folder' : 'Ask INFOSEC about this'], function () { askInfosec(subject, opts.folder); }, 'infosec sv-own-infosec');
    row.appendChild(ask);
    var status = el('span', { cls: 'sv-p-status', attrs: { 'aria-live': 'polite' } });
    if (subject.path) { row.appendChild(button([icon('copy'), 'Copy path'], function () { copyPath(subject.path, status); }, 'ghost')); }
    var wrap = el('div', { cls: 'sv-p-actions-wrap' }, [row, status]);
    notes.forEach(function (n) { wrap.appendChild(n); });
    return wrap;
  }

  function openItemPanel(it) {
    if (!it) { return; }
    openPanel({
      title: it.label || it.path, subtitle: catLabel(it.category) + ' · ' + B(it.bytes),
      kind: 'storageItem', id: it.id, item: panelItem(it),
      render: function (body) { renderItemPanel(body, it); }
    });
  }

  function renderItemPanel(body, it) {
    var g = groupOfItem(it);
    var wrap = el('div', { cls: 'sv-panel sv-g-' + g });
    bvs(wrap, 'storageItem', it.id, it.label);
    wrap.appendChild(panelHero(itemIcon(it), catLabel(it.category), it.label, it.path));
    if (atRisk(it)) { wrap.appendChild(riskBox(it)); }

    var facts = el('div', { cls: 'sv-p-facts' });
    facts.appendChild(fact('Size', B(it.bytes), pctDisk(it.bytes) + ' of the used disk space', ring(it.bytes / S.model.used, pctDisk(it.bytes), 'sv-ring-acc small')));
    if (isDupGroup(it)) { facts.appendChild(fact('Extra space', B(wasted(it)), 'used by the extra copies')); }
    if (it.newest) { facts.appendChild(fact('Last changed', plainAge(it.newest), U.fmtDate(it.newest) + (it.oldest ? ' · oldest file ' + U.fmtDate(it.oldest) : ''))); }
    if (it.files && it.kind !== 'file') { facts.appendChild(fact('Files', U.fmtNum(it.files), it.kind === 'dir' ? 'inside this folder' : '')); }
    if (it.owner && it.owner !== 'unknown') { facts.appendChild(fact('Belongs to', it.owner === 'you' ? 'You' : it.owner, '')); }
    wrap.appendChild(facts);

    wrap.appendChild(safetyBlock(it.safety));

    wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'What is it?' }));
    if (it.purpose) { wrap.appendChild(el('p', { cls: 'sv-p-text', text: pvName(it.path, it.purpose) })); }
    var ci = catInfo(it.category);
    if (ci.plain && ci.plain !== it.purpose) { wrap.appendChild(el('p', { cls: 'sv-p-muted' }, [catChip(it.category), ' ', ci.plain])); }

    if (it.how) {
      wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'How to clean it' }));
      wrap.appendChild(el('div', { cls: 'sv-p-how' }, [icon(it.safety === 'use_tool' ? 'wrench' : 'info'), el('p', { text: it.how })]));
      wrap.appendChild(el('p', { cls: 'sv-p-muted', text: it.reversible === false ? 'Cannot be undone once removed.' : it.method === 'holding' ? 'Goes to a holding folder first, so it can be put back.' : it.method === 'recycle' ? 'Goes to the Recycle Bin, so it can be put back.' : '' }));
    }

    var flags = (it.flags || []).filter(function (f) { return FLAG_TEXT[f] && f !== 'work_at_risk'; });
    if (flags.length) {
      var ul = el('ul', { cls: 'sv-p-flags' });
      flags.forEach(function (f) { ul.appendChild(el('li', null, [icon('info'), FLAG_TEXT[f]])); });
      wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Good to know' }));
      wrap.appendChild(ul);
    }
    if (it.x && it.x.junkItemId && app() && typeof app().itemById === 'function') {
      var twin = app().itemById(it.x.junkItemId);
      if (twin && twin !== it) {
        wrap.appendChild(el('p', { cls: 'sv-p-muted' }, ['Also listed in Junk & caches as ', button(twin.label, function () { openItemPanel(twin); }, 'linkish'), '.']));
      }
    }

    if (isDupGroup(it)) {
      wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'The copies' }));
      wrap.appendChild(copiesGrid(it, true));
      wrap.appendChild(el('p', { cls: 'sv-p-note' }, [icon('info'), el('span', { text: 'We never choose for you. Keep the copy that is in the right place, then remove the others yourself in File Explorer.' })]));
    }
    if (it.group && !isDupGroup(it)) {
      var sibs = S.model.projects.filter(function (p) { return p.group === it.group && p !== it; });
      if (sibs.length) {
        wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Other copies of this project' }));
        var sl = el('ul', { cls: 'svm-item-list', attrs: { role: 'list' } });
        sibs.slice(0, 12).forEach(function (p) {
          var b = button([swatch(atRisk(p) ? 'sv-s-review' : 'sv-s-safe', atRisk(p) ? 'warning' : 'check'), el('span', { cls: 'svm-kid-name', text: pvName(p.path, p.label) }), el('span', { cls: 'svm-kid-size', text: B(p.bytes) })],
            function () { openItemPanel(p); }, 'svm-item', { title: pvPath(p.path) });
          bvs(b, 'storageItem', p.id, pvName(p.path, p.label));
          sl.appendChild(el('li', null, b));
        });
        wrap.appendChild(sl);
      }
    }
    wrap.appendChild(panelActions(it, { mapPath: isDupGroup(it) ? null : it.path }));
    body.appendChild(wrap);
  }

  function riskBox(it) {
    var g = gitRisk(it) || {};
    var bits = [];
    if (g.uncommitted) { bits.push(U.fmtNum(g.uncommitted) + ' change' + (g.uncommitted === 1 ? '' : 's') + ' not committed'); }
    if (g.unpushed) { bits.push(U.fmtNum(g.unpushed) + ' commit' + (g.unpushed === 1 ? '' : 's') + ' not pushed'); }
    if (g.stashes) { bits.push(g.stashes + ' stash' + (g.stashes === 1 ? '' : 'es')); }
    return el('div', { cls: 'sv-risk', attrs: { role: 'note' } }, [
      icon('warning'),
      el('div', null, [
        el('strong', { text: 'Don\'t delete before committing' }),
        el('div', null, ['This copy has work that exists only here' + (bits.length ? ': ' + bits.join(', ') : '') + '. Save it with a ', term('commit', 'commit'), ' (and push), then scan again.'])
      ])
    ]);
  }

  function openFolderPanel(info) {
    var node = info.node, cls = info.cls;
    var it = cls.item;
    var subject = it || {
      label: displayName(node), path: info.path, bytes: node.b, category: cls.cat || null, safety: cls.safety || null,
      purpose: explainFolder(node, info.path, cls), kind: 'dir'
    };
    openPanel({
      title: displayName(node), subtitle: info.path, kind: 'storageItem', id: it ? it.id : undefined, item: panelItem(subject),
      render: function (body) { renderFolderPanel(body, info, subject); }
    });
  }

  function renderFolderPanel(body, info, subject) {
    var node = info.node, cls = info.cls;
    var g = node === M.root ? 'other' : (cls.group || 'other');
    var wrap = el('div', { cls: 'sv-panel sv-g-' + g });
    bvs(wrap, cls.item ? 'storageItem' : 'tile', cls.item ? cls.item.id : null, displayName(node) + ' ' + info.path);
    wrap.appendChild(panelHero(node === M.root ? 'disk' : GROUPS[g].icon, GROUPS[g].label + (cls.cat ? ' · ' + catLabel(cls.cat) : ''), displayName(node), info.path));

    wrap.appendChild(el('h3', { cls: 'sv-p-h', text: node.y ? 'What is this?' : 'What is this folder?' }));
    wrap.appendChild(el('p', { cls: 'sv-p-text', text: pvName(info.path, explainFolder(node, info.path, cls)) }));
    if (!cls.item && node !== M.root) { wrap.appendChild(el('p', { cls: 'sv-p-muted' }, [swatch('sv-g-' + g, GROUPS[g].icon), ' ', GROUPS[g].label + ': ' + GROUPS[g].plain])); }

    var facts = el('div', { cls: 'sv-p-facts' });
    facts.appendChild(fact('Size', B(node.b), pctDisk(node.b) + ' of the used disk space', ring(node.b / S.model.used, pctDisk(node.b), 'sv-ring-acc small')));
    if (info.parentNode && info.parentNode.b) { facts.appendChild(fact('Share of ' + displayName(info.parentNode), U.pct(node.b, info.parentNode.b), '')); }
    if (node.f !== undefined) { facts.appendChild(fact('Files', U.fmtNum(node.f), node.d ? 'in ' + U.fmtNum(node.d) + ' folders' : '')); }
    if (node.t) { facts.appendChild(fact('Last changed', plainAge(node.t), U.fmtDate(node.t) + (node.a >= 0 && node.a <= 3 ? ' · most of it ' + AGE_SHORT[node.a] + ' old' : ''))); }
    if (node.k3 && node.b && node.k3[1]) { facts.appendChild(fact('Untouched 2+ years', B(node.k3[1]), U.pct(node.k3[1], node.b) + ' of this folder')); }
    if (node.cl) { facts.appendChild(fact('Online only', B(node.cl), 'cloud files that use no space here')); }
    wrap.appendChild(facts);

    if (cls.safety || cls.item) { wrap.appendChild(safetyBlock(cls.safety)); }
    var how = cls.item ? cls.item.how : (cls.files && cls.files.item ? cls.files.item.how : genericHow(cls));
    wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'How to clean it' }));
    wrap.appendChild(el('div', { cls: 'sv-p-how' }, [icon(cls.safety === 'use_tool' ? 'wrench' : cls.safety === 'do_not_touch' ? 'lock' : 'info'), el('p', { text: how })]));

    if (node.fl) {
      var ul = el('ul', { cls: 'sv-p-flags' });
      String(node.fl).split(',').forEach(function (f) { f = f.trim(); if (NODE_FLAG_TEXT[f]) { ul.appendChild(el('li', null, [icon('info'), NODE_FLAG_TEXT[f]])); } });
      if (ul.firstChild) { wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Good to know' })); wrap.appendChild(ul); }
    }

    // clean-up items inside
    var fk = node === M.root ? '' : node.y === 'f' ? null : keyOf(info.path);
    var items = node.y === 'f' ? ((cls.files && cls.files.items) || []).slice() :
      S.model.all.filter(function (it) { return inside(it.__key, fk) && it !== cls.item; });
    items.sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0); });
    if (items.length) {
      wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Clean-up items inside (' + items.length + ')' }));
      var il = el('ul', { cls: 'svm-item-list', attrs: { role: 'list' } });
      items.slice(0, 8).forEach(function (it) {
        var si = safetyInfo(it.safety);
        var b = button([swatch('sv-s-' + (SAFETY_INFO[it.safety] ? it.safety : 'none'), si.icon), el('span', { cls: 'svm-kid-name', text: pvName(it.path, it.label) }), el('span', { cls: 'svm-kid-size', text: B(it.bytes) })],
          function () { openItemPanel(it); }, 'svm-item', { title: si.label + ' · ' + pvPath(it.path) });
        bvs(b, 'storageItem', it.id, pvName(it.path, it.label));
        il.appendChild(el('li', null, b));
      });
      wrap.appendChild(il);
    }

    // biggest inside
    var kids = visibleKids(node);
    if (kids.length) {
      wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Biggest inside' }));
      var max = kids[0].b;
      var kl = el('ul', { cls: 'sv-p-kids', attrs: { role: 'list' } });
      kids.slice(0, 5).forEach(function (k) {
        kl.appendChild(el('li', null, [el('span', { cls: 'svm-kid-name', text: k.y ? displayName(k) : pvName(joinPath(info.path, k.n, M.meta.sep || '\\'), displayName(k)) }), el('span', { cls: 'svm-kid-size', text: B(k.b) }), sizeBar(k.b, max)]));
      });
      wrap.appendChild(kl);
    }

    var canDrill = !info.isCurrent && (drillable(node) || (info.chain && info.chain.slice(0, -1).some(drillable)));
    var drillFn = canDrill ? function () {
      if (info.chain && info.chain.length) { drillChain(info.chain); }
      else if (M.stack.indexOf(node) >= 0) { M.stack.length = M.stack.indexOf(node) + 1; renderMapAll(); syncHash(); }
    } : null;
    wrap.appendChild(panelActions(subject, { drill: drillFn, folder: !node.y }));
    body.appendChild(wrap);
  }

  function openHelpPanel() {
    openPanel({
      title: 'How to read the Storage pages', subtitle: 'Colours, labels and words', kind: 'custom',
      render: function (body) {
        var wrap = el('div', { cls: 'sv-panel' });
        wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'What it is (map colours)' }));
        var gl = el('ul', { cls: 'sv-help-list' });
        GROUP_ORDER.forEach(function (g) { gl.appendChild(el('li', null, [swatch('sv-g-' + g, GROUPS[g].icon), el('div', null, [el('strong', { text: GROUPS[g].label }), el('div', { cls: 'sv-muted', text: GROUPS[g].plain })])])); });
        wrap.appendChild(gl);
        wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Safe to clean?' }));
        var sl = el('ul', { cls: 'sv-help-list' });
        SAFETY_ORDER.forEach(function (s) { sl.appendChild(el('li', null, [swatch('sv-s-' + s, SAFETY_INFO[s].icon), el('div', null, [el('strong', { text: SAFETY_INFO[s].label }), el('div', { cls: 'sv-muted', text: SAFETY_INFO[s].plain })])])); });
        wrap.appendChild(sl);
        wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'How old' }));
        var al = el('ul', { cls: 'sv-help-list' });
        [0, 1, 2, 3].forEach(function (a) { al.appendChild(el('li', null, [swatch('sv-a-' + a, 'clock'), el('div', null, [el('strong', { text: AGE_LABELS[a] })])])); });
        wrap.appendChild(al);
        wrap.appendChild(el('h3', { cls: 'sv-p-h', text: 'Words' }));
        var dl = el('dl', { cls: 'sv-help-dl' });
        Object.keys(GLOSSARY).forEach(function (k) {
          dl.appendChild(el('dt', { text: GLOSSARY[k][0].replace(/^./, function (c) { return c.toUpperCase(); }) }));
          dl.appendChild(el('dd', { text: GLOSSARY[k][1] }));
        });
        wrap.appendChild(dl);
        body.appendChild(wrap);
      }
    });
  }

  // ================================================================== LIST SECTIONS
  var INTRO = {
    junk: function () {
      return ['Temporary files and ', term('caches', 'cache'), ' that apps can make again, plus old ', term('installers', 'installer'),
        ' and project ', term('dependencies', 'deps'), '. Removing them frees space now; caches slowly come back. The biggest groups are first.'];
    },
    big: function () {
      return ['The largest single files on the disk. Big does not mean useless: check what each one is before you decide. ',
        term('Virtual disks', 'vdisk'), ' must be shrunk from their own app.'];
    },
    old: function () {
      return ['Folders and big files nobody has changed for 2 years or more. Old does not mean unused: photos and archives are old on purpose. ',
        'Copy them to an external drive or cloud before removing them here.'];
    },
    duplicates: function () {
      return ['The same file, byte for byte, stored more than once (a ', term('duplicate', 'duplicate'), '). The copies are shown side by side. ',
        el('strong', { text: 'We never choose which copy to delete' }), ': you keep the one in the right place.'];
    },
    projects: function () {
      return ['Copies of the same programming project. Some hold work that exists only in that copy (not ', term('committed', 'commit'),
        ' or not pushed). ', el('strong', { text: 'Don\'t delete those before committing.' })];
    },
    system: function () {
      return ['Windows needs these to start and run. They are listed so you know what the big ones are. ',
        el('strong', { text: 'Never delete them by hand' }), '; some can be made smaller with Windows\' own settings (see each item).'];
    }
  };

  function listItems(id) {
    var m = S.model;
    return id === 'junk' ? m.junk : id === 'big' ? m.big : id === 'old' ? m.old : id === 'system' ? m.system : [];
  }
  function newListState(id) {
    var q = S.query || {};
    return {
      section: id, q: (q.q || '').toLowerCase(), safety: q.safety || null, group: q.group || null, cat: q.cat || null,
      pathKey: q.path ? keyOf(q.path) : null, path: q.path || null, sort: 'size', shown: PAGE, open: {}, riskOnly: false
    };
  }
  function statLine(id) {
    var m = S.model, st = m.stats[id];
    if (id === 'junk') {
      var easy = sumDedup(m.junk.filter(function (it) { return it.safety === 'safe' || it.safety === 'safe_after_check'; }));
      return st.count + ' items · ' + B(easy) + ' safe or safe after a check';
    }
    if (id === 'big') { return st.count + ' files'; }
    if (id === 'old') { return m.oldFolders.length + ' folders · ' + m.oldExtra.length + ' files'; }
    if (id === 'duplicates') { return st.count + ' groups of identical files · extra copies use ' + B(st.bytes); }
    if (id === 'projects') { return st.count + ' copies at risk · ' + st.total + ' project copies in total'; }
    if (id === 'system') { return st.count + ' items Windows needs'; }
    return '';
  }
  function listHero(id) {
    var sec = SECTION_BY_ID[id], st = S.model.stats[id];
    var bytes = id === 'projects' ? sumBytes(S.model.projects) : st.bytes;
    return el('header', { cls: 'sv-hero sv-acc-' + id }, [
      el('span', { cls: 'sv-hero-ico' }, icon(sec.icon)),
      el('div', { cls: 'sv-hero-text' }, [el('h2', { cls: 'sv-h2', text: sec.label }), el('p', { cls: 'sv-hero-intro' }, INTRO[id]())]),
      el('div', { cls: 'sv-hero-stats' }, [
        ring(bytes / S.model.used, pctDisk(bytes), 'sv-ring-acc'),
        el('div', null, [el('div', { cls: 'sv-big', text: B(bytes) }), el('div', { cls: 'sv-muted', text: statLine(id) })])
      ])
    ]);
  }

  function renderListSection(host, id) {
    if (!S.list || S.list.section !== id) { S.list = newListState(id); }
    host.appendChild(listHero(id));
    if (id === 'system') { host.appendChild(systemExtras()); }
    if (id === 'duplicates') { renderDuplicates(host); return; }
    if (id === 'projects') { renderProjects(host); return; }
    var items = listItems(id);
    host.appendChild(listToolbar(id, items));
    S.listBody = el('div', { cls: 'sv-list', attrs: { 'aria-live': 'polite' } });
    host.appendChild(S.listBody);
    renderListBody(id);
  }

  function matches(it, L) {
    if (L.safety && it.safety !== L.safety) { return false; }
    if (L.group && groupOfItem(it) !== L.group) { return false; }
    if (L.cat && it.category !== L.cat) { return false; }
    if (L.pathKey && !inside(keyOf(it.path), L.pathKey)) { return false; }
    if (L.q) {
      var hay = ((it.label || '') + ' ' + (it.path || '') + ' ' + (it.purpose || '') + ' ' + catLabel(it.category) + ' ' + (it.owner || '')).toLowerCase();
      if (hay.indexOf(L.q) < 0) { return false; }
    }
    return true;
  }
  function sorter(key) {
    if (key === 'age') {
      return function (a, b) {
        var da = U.toDate(a.newest), db = U.toDate(b.newest);
        return (da ? da.getTime() : Infinity) - (db ? db.getTime() : Infinity);
      };
    }
    if (key === 'name') { return function (a, b) { return String(a.label || '').localeCompare(String(b.label || ''), 'en', { sensitivity: 'base', numeric: true }); }; }
    return function (a, b) { return (b.bytes || 0) - (a.bytes || 0); };
  }

  function listToolbar(id, items) {
    var L = S.list;
    var bar = el('div', { cls: 'sv-toolbar' });
    var row1 = el('div', { cls: 'sv-toolbar-row' });
    var search = el('input', { cls: 'sv-search', attrs: { type: 'search', placeholder: 'Search by name, folder or what it is', 'aria-label': 'Search ' + SECTION_BY_ID[id].label } });
    search.value = L.q;
    search.addEventListener('input', U.debounce(function () { L.q = search.value.trim().toLowerCase(); L.shown = PAGE; renderListBody(id); }, 160));
    row1.appendChild(el('label', { cls: 'sv-search-wrap' }, [icon('search'), search]));
    var sort = el('select', { cls: 'sv-select', attrs: { 'aria-label': 'Sort the list' } });
    [['size', 'Biggest first'], ['age', 'Oldest first'], ['name', 'Name A-Z']].forEach(function (o) {
      var op = el('option', { text: o[1], attrs: { value: o[0] } });
      if (L.sort === o[0]) { op.selected = true; }
      sort.appendChild(op);
    });
    sort.addEventListener('change', function () { L.sort = sort.value; L.shown = PAGE; renderListBody(id); });
    row1.appendChild(el('label', { cls: 'sv-sort' }, [el('span', { cls: 'sv-muted', text: 'Sort' }), sort]));
    bar.appendChild(row1);

    // safety chips
    var counts = {};
    items.forEach(function (it) { counts[it.safety] = (counts[it.safety] || 0) + 1; });
    var present = SAFETY_ORDER.filter(function (s) { return counts[s]; });
    if (present.length > 1) {
      var chips = el('div', { cls: 'sv-chips', attrs: { role: 'group', 'aria-label': 'Show by clean-up safety' } });
      var all = button(['All ', el('span', { cls: 'sv-chip-n', text: String(items.length) })], function () { L.safety = null; L.shown = PAGE; syncChips(); renderListBody(id); }, 'sv-chip', { 'aria-pressed': String(!L.safety), 'data-val': '' });
      chips.appendChild(all);
      present.forEach(function (s) {
        var info = SAFETY_INFO[s];
        chips.appendChild(button([swatch('sv-s-' + s, info.icon), info.short + ' ', el('span', { cls: 'sv-chip-n', text: String(counts[s]) })], function () {
          L.safety = L.safety === s ? null : s; L.shown = PAGE; syncChips(); renderListBody(id);
        }, 'sv-chip', { 'aria-pressed': String(L.safety === s), 'data-val': s, 'data-sv-tip': info.plain, 'data-sv-term': info.label }));
      });
      var syncChips = function () {
        Array.prototype.forEach.call(chips.querySelectorAll('[data-val]'), function (c) { c.setAttribute('aria-pressed', String((L.safety || '') === c.getAttribute('data-val'))); });
      };
      bar.appendChild(el('div', { cls: 'sv-toolbar-row' }, [el('span', { cls: 'sv-muted sv-chips-label', text: 'Safe to clean?' }), chips]));
    }
    // colour-group chips (what kind of file)
    if (id === 'big' || id === 'old') {
      var gcounts = {};
      items.forEach(function (it) { var g = groupOfItem(it); gcounts[g] = (gcounts[g] || 0) + 1; });
      var gpresent = GROUP_ORDER.filter(function (g) { return gcounts[g]; });
      if (gpresent.length > 1) {
        var gchips = el('div', { cls: 'sv-chips', attrs: { role: 'group', 'aria-label': 'Show by kind' } });
        var gsync = function () {
          Array.prototype.forEach.call(gchips.querySelectorAll('[data-val]'), function (c) { c.setAttribute('aria-pressed', String((L.group || '') === c.getAttribute('data-val'))); });
        };
        gchips.appendChild(button('All kinds', function () { L.group = null; L.shown = PAGE; gsync(); renderListBody(id); }, 'sv-chip', { 'aria-pressed': String(!L.group), 'data-val': '' }));
        gpresent.forEach(function (g) {
          gchips.appendChild(button([swatch('sv-g-' + g, GROUPS[g].icon), GROUPS[g].label + ' ', el('span', { cls: 'sv-chip-n', text: String(gcounts[g]) })], function () {
            L.group = L.group === g ? null : g; L.shown = PAGE; gsync(); renderListBody(id);
          }, 'sv-chip', { 'aria-pressed': String(L.group === g), 'data-val': g, 'data-sv-tip': GROUPS[g].plain, 'data-sv-term': GROUPS[g].label }));
        });
        bar.appendChild(el('div', { cls: 'sv-toolbar-row' }, [el('span', { cls: 'sv-muted sv-chips-label', text: 'What kind?' }), gchips]));
      }
    }
    // filters that came from a link (category or folder)
    var pills = [];
    if (L.cat) { pills.push(['Showing only: ' + catLabel(L.cat), function () { L.cat = null; }]); }
    if (L.path) { pills.push(['Inside: ' + L.path, function () { L.path = null; L.pathKey = null; }]); }
    if (pills.length) {
      var pr = el('div', { cls: 'sv-toolbar-row sv-pills' });
      pills.forEach(function (p) {
        pr.appendChild(button([el('span', { text: p[0] }), icon('close')], function () {
          p[1]();
          replaceHash('#/storage/' + id);
          S.routeKey = routeKeyOf({ section: id, query: {} });
          S.query = {};
          renderSection();
        }, 'sv-pill', { 'aria-label': 'Remove filter: ' + U.safeText(p[0]) }));
      });
      bar.appendChild(pr);
    }
    return bar;
  }

  function renderListBody(id) {
    var body = S.listBody, L = S.list;
    if (!body) { return; }
    U.clear(body);
    var items = listItems(id).filter(function (it) { return matches(it, L); }).sort(sorter(L.sort));
    if (!items.length) {
      body.appendChild(el('div', { cls: 'sv-card sv-empty' }, [icon('search'), el('p', { text: 'Nothing matches. Try another search or filter.' })]));
      return;
    }
    var max = items.reduce(function (mx, it) { return Math.max(mx, it.bytes || 0); }, 0);
    if (id === 'junk' && !L.q && L.sort === 'size') { renderJunkGroups(body, items, max); return; }
    if (id === 'old' && !L.q && L.sort === 'size') {
      var folders = items.filter(function (it) { return it.__oldKind === 'folder'; });
      var files = items.filter(function (it) { return it.__oldKind !== 'folder'; });
      if (folders.length) { body.appendChild(subHead('folder', 'Old folders', folders.length + ' folders where most data has not changed in 2+ years')); folders.forEach(function (it) { body.appendChild(itemRow(it, { max: max })); }); }
      if (files.length) { body.appendChild(subHead('bigfile', 'Old big files', files.length + ' files not changed in 2+ years')); appendPaged(body, files, max, id); }
      return;
    }
    appendPaged(body, items, max, id);
  }
  function subHead(ic, title, sub) {
    return el('div', { cls: 'sv-subhead' }, [icon(ic), el('h3', { cls: 'sv-h3', text: title }), el('span', { cls: 'sv-muted', text: sub })]);
  }
  function appendPaged(body, items, max, id) {
    var L = S.list;
    var holder = el('div', { cls: 'sv-rows' });
    items.slice(0, L.shown).forEach(function (it) { holder.appendChild(itemRow(it, { max: max })); });
    body.appendChild(holder);
    if (items.length > L.shown) {
      body.appendChild(button(['Show ' + Math.min(PAGE, items.length - L.shown) + ' more (' + (items.length - L.shown) + ' left)'], function () { L.shown += PAGE; renderListBody(id); }, 'sv-more'));
    }
  }

  function renderJunkGroups(body, items, max) {
    var L = S.list;
    var by = {}, order = [];
    items.forEach(function (it) {
      if (!by[it.category]) { by[it.category] = []; order.push(it.category); }
      by[it.category].push(it);
    });
    var groups = order.map(function (c) { return { cat: c, items: by[c], bytes: sumDedup(by[c]) }; }).sort(function (a, b) { return b.bytes - a.bytes; });
    var total = groups.reduce(function (s, g) { return s + g.bytes; }, 0);
    groups.forEach(function (gr) {
      var info = catInfo(gr.cat);
      var open = !!L.open[gr.cat] || L.cat === gr.cat || groups.length === 1;
      var sec = el('section', { cls: 'sv-group sv-g-' + info.group, attrs: { 'data-bvs-section': 'storage-junk-' + gr.cat } });
      bvs(sec, 'section', null, info.label + ': ' + gr.items.length + ' items, ' + B(gr.bytes));
      var safeties = [];
      gr.items.forEach(function (it) { if (safeties.indexOf(it.safety) < 0) { safeties.push(it.safety); } });
      sec.appendChild(el('header', { cls: 'sv-group-head' }, [
        el('span', { cls: 'sv-group-ico' }, icon(CAT_ICON[gr.cat] || GROUPS[info.group].icon)),
        el('div', { cls: 'sv-group-text' }, [
          el('h3', { cls: 'sv-h3', text: info.label }),
          info.plain ? el('p', { cls: 'sv-muted', text: info.plain }) : null,
          el('div', { cls: 'sv-group-badges' }, safeties.map(function (s) { return safetyBadge(s); }))
        ]),
        el('div', { cls: 'sv-group-stats' }, [
          el('div', { cls: 'sv-big', text: B(gr.bytes) }),
          el('div', { cls: 'sv-muted', text: gr.items.length + ' item' + (gr.items.length === 1 ? '' : 's') + ' · ' + U.pct(gr.bytes, total) + ' of junk' }),
          sizeBar(gr.bytes, groups[0].bytes, 'sv-g-' + info.group)
        ])
      ]));
      var rows = el('div', { cls: 'sv-rows' });
      (open ? gr.items : gr.items.slice(0, 3)).forEach(function (it) { rows.appendChild(itemRow(it, { max: max, inGroup: true })); });
      sec.appendChild(rows);
      if (!open && gr.items.length > 3) {
        sec.appendChild(button(['Show all ' + gr.items.length, icon('chevron')], function () { L.open[gr.cat] = true; renderListBody('junk'); }, 'sv-more ghost'));
      }
      body.appendChild(sec);
    });
  }

  function basketBlockReason(it) {
    var b = basket();
    if (!b) { return 'The basket is not available on this page.'; }
    if (it.safety === 'do_not_touch') { return 'Windows needs this, so it can never go in the basket.'; }
    if (it.safety === 'use_tool') { return 'Clean this with the app\'s own tool (see "How to clean it"). It cannot go in the basket.'; }
    if (it.method === 'none') { return 'There is no safe way to remove this by hand.'; }
    if (isDupGroup(it)) { return 'You choose which copy to keep. Open the copies and remove the extra one yourself.'; }
    if (atRisk(it)) { return 'This copy has work that is not saved to git yet. Commit (and push) it first, then scan again.'; }
    if (!(typeof b.canAdd === 'function' ? b.canAdd(it) : true)) { return 'This item cannot go in the basket.'; }
    return null;
  }
  function syncBasketBtn(btn, on) {
    btn.setAttribute('aria-pressed', String(on));
    btn.classList.toggle('on', on);
    var label = btn.getAttribute('data-sv-label') || 'this item';
    btn.setAttribute('aria-label', on ? 'In the basket: ' + label + '. Click to take it out.' : 'Add ' + label + ' to the basket');
    btn.title = on ? 'In the basket (click to take it out)' : 'Add to the clean-up basket';
    var t = btn.querySelector('.sv-bk-text');
    if (t) { t.textContent = on ? 'In basket' : 'Add to basket'; }
  }
  function syncAllBasket() {
    var b = basket();
    if (!b) { return; }
    Array.prototype.forEach.call(document.querySelectorAll('[data-sv-basket-id]'), function (btn) {
      syncBasketBtn(btn, b.has(btn.getAttribute('data-sv-basket-id')));
    });
  }
  function basketToggle(it, compact) {
    var reason = basketBlockReason(it);
    if (reason) {
      return el('span', { cls: 'sv-bk locked', attrs: { tabindex: '0', 'data-sv-tip': reason, 'data-sv-term': 'Not for the basket', 'aria-label': 'Not for the basket: ' + reason } }, [icon('lock')]);
    }
    var b = basket();
    var btn = el('button', {
      cls: 'sv-bk' + (compact ? '' : ' wide'),
      attrs: { type: 'button', 'data-sv-basket-id': it.id, 'data-sv-label': U.safeText(it.label || it.id) }
    }, [icon('plus', 'off'), icon('check', 'on'), compact ? null : el('span', { cls: 'sv-bk-text' })]);
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      b.toggle(it);
      syncAllBasket();
    });
    syncBasketBtn(btn, b.has(it.id));
    return btn;
  }

  function itemRow(it, opts) {
    opts = opts || {};
    var g = groupOfItem(it);
    var row = el('div', { cls: 'sv-row sv-g-' + g + (atRisk(it) ? ' risk' : '') });
    bvs(row, 'storageItem', it.id, pvName(it.path, it.label) + ' (' + B(it.bytes) + ')');
    row.appendChild(el('div', { cls: 'sv-row-bk' }, basketToggle(it, true)));
    row.appendChild(el('span', { cls: 'sv-row-ico', attrs: { 'aria-hidden': 'true' } }, icon(itemIcon(it))));
    var title = button(pvName(it.path, it.label), function () { openItemPanel(it); }, 'sv-row-title', { title: 'Details: ' + U.safeText(pvName(it.path, it.label)) });
    var top = el('div', { cls: 'sv-row-top' }, [title]);
    if (!opts.inGroup) { top.appendChild(catChip(it.category)); }
    var main = el('div', { cls: 'sv-row-main' }, [top, el('div', { cls: 'sv-row-path', text: pvPath(it.path), title: pvPath(it.path) })]);
    if (it.purpose) { main.appendChild(el('div', { cls: 'sv-row-purpose', text: pvName(it.path, it.purpose) })); }
    if (opts.extra) { main.appendChild(opts.extra(it)); }
    row.appendChild(main);
    row.appendChild(el('div', { cls: 'sv-row-size' }, [
      el('strong', { text: B(it.bytes) }), sizeBar(it.bytes || 0, opts.max || it.bytes || 1, 'sv-g-' + g), el('span', { cls: 'sv-muted small', text: pctDisk(it.bytes) + ' of disk' })
    ]));
    row.appendChild(el('div', { cls: 'sv-row-meta' }, [ageChip(it.newest), safetyBadge(it.safety)]));
    var acts = el('div', { cls: 'sv-row-acts' });
    if (it.path && !isDupGroup(it)) { acts.appendChild(link([icon('pin'), el('span', { text: 'Show in map' })], mapHash(it.path), 'sv-link small', { title: 'Show where it is on the map' })); }
    acts.appendChild(button([el('span', { text: 'Details' }), icon('chevron')], function () { openItemPanel(it); }, 'ghost small'));
    row.appendChild(acts);
    row.addEventListener('click', function (ev) {
      if (ev.target.closest('button, a, input, label, select, [data-sv-tip]')) { return; }
      openItemPanel(it);
    });
    return row;
  }

  // ---------------------------------------------------------------- duplicates
  function renderDuplicates(host) {
    var L = S.list, m = S.model;
    var bar = el('div', { cls: 'sv-toolbar' });
    var search = el('input', { cls: 'sv-search', attrs: { type: 'search', placeholder: 'Search by file name or folder', 'aria-label': 'Search duplicates' } });
    search.value = L.q;
    bar.appendChild(el('div', { cls: 'sv-toolbar-row' }, [el('label', { cls: 'sv-search-wrap' }, [icon('search'), search])]));
    host.appendChild(bar);
    var body = el('div', { cls: 'sv-dups', attrs: { 'aria-live': 'polite' } });
    host.appendChild(body);
    function draw() {
      U.clear(body);
      var list = m.dups.filter(function (it) {
        if (!L.q) { return true; }
        var hay = (it.label + ' ' + it.path + ' ' + ((it.x && it.x.copies) || []).map(function (c) { return c.path; }).join(' ')).toLowerCase();
        return hay.indexOf(L.q) >= 0;
      }).sort(function (a, b) { return wasted(b) - wasted(a); });
      if (!list.length) { body.appendChild(el('div', { cls: 'sv-card sv-empty' }, [icon('copy'), el('p', { text: m.dups.length ? 'Nothing matches.' : 'No duplicate files were found.' })])); return; }
      var maxW = wasted(list[0]) || 1;
      list.slice(0, L.shown).forEach(function (it) { body.appendChild(dupCard(it, maxW)); });
      if (list.length > L.shown) {
        body.appendChild(button('Show ' + Math.min(PAGE, list.length - L.shown) + ' more (' + (list.length - L.shown) + ' left)', function () { L.shown += PAGE; draw(); }, 'sv-more'));
      }
    }
    search.addEventListener('input', U.debounce(function () { L.q = search.value.trim().toLowerCase(); L.shown = PAGE; draw(); }, 160));
    draw();
  }
  function copiesGrid(it, compact) {
    var copies = (it.x && it.x.copies) || [];
    var grid = el('div', { cls: 'sv-copies' + (compact ? ' compact' : '') });
    copies.forEach(function (c, i) {
      var folderPath = String(c.path || '').replace(/[\\/][^\\/]*$/, '');
      var status = el('span', { cls: 'sv-p-status', attrs: { 'aria-live': 'polite' } });
      var box = el('div', { cls: 'sv-copy' }, [
        el('div', { cls: 'sv-copy-n', text: 'Copy ' + (i + 1) }),
        el('div', { cls: 'sv-copy-folder' }, [icon('folder'), el('strong', { text: pvName(folderPath, c.folder || folderPath.split(/[\\/]/).pop() || folderPath) })]),
        el('div', { cls: 'sv-copy-path', text: pvPath(c.path) }),
        el('div', { cls: 'sv-muted small', text: (c.bytes ? B(c.bytes) + ' · ' : '') + (c.modifiedUtc ? 'changed ' + plainAge(c.modifiedUtc) + ' (' + U.fmtDate(c.modifiedUtc) + ')' : '') }),
        el('div', { cls: 'sv-copy-acts' }, [
          link([icon('pin'), 'Show in map'], mapHash(c.path), 'sv-link small'),
          button([icon('copy'), 'Copy path'], function () { copyPath(c.path, status); }, 'ghost small')
        ]),
        status
      ]);
      bvs(box, 'file', it.id + '#' + (i + 1), 'Copy ' + (i + 1) + ': ' + pvPath(c.path));
      grid.appendChild(box);
    });
    return grid;
  }
  function dupCard(it, maxW) {
    var copies = (it.x && it.x.copies) || [];
    var card = el('article', { cls: 'sv-card sv-dup sv-acc-duplicates' });
    bvs(card, 'storageItem', it.id, pvName(it.path, it.label) + ': ' + copies.length + ' copies');
    var w = wasted(it);
    card.appendChild(el('header', { cls: 'sv-dup-head' }, [
      el('span', { cls: 'sv-dup-ico' }, icon('copy')),
      el('div', { cls: 'sv-dup-title' }, [
        button(pvName(it.path, it.label), function () { openItemPanel(it); }, 'sv-row-title'),
        el('div', { cls: 'sv-muted', text: copies.length + ' identical copies · ' + B((it.x && it.x.sizeEach) || 0) + ' each' + ((it.flags || []).indexOf('cross_folder') >= 0 ? ' · in different folders' : '') })
      ]),
      el('div', { cls: 'sv-dup-waste' }, [el('strong', { text: B(w) }), el('span', { cls: 'sv-muted small', text: 'extra space' }), sizeBar(w, maxW, 'sv-acc-duplicates')])
    ]));
    card.appendChild(copiesGrid(it, false));
    card.appendChild(el('p', { cls: 'sv-dup-note' }, [icon('info'), 'Identical content. You decide which copy to keep; remove the others yourself in File Explorer.']));
    return card;
  }

  // ---------------------------------------------------------------- projects at risk
  function gitLine(it) {
    var g = gitRisk(it);
    if (atRisk(it)) {
      var bits = [];
      if (g && g.uncommitted) { bits.push(U.fmtNum(g.uncommitted) + ' unsaved change' + (g.uncommitted === 1 ? '' : 's')); }
      if (g && g.unpushed) { bits.push(U.fmtNum(g.unpushed) + ' commit' + (g.unpushed === 1 ? '' : 's') + ' not pushed'); }
      if (g && g.stashes) { bits.push(g.stashes + ' stash' + (g.stashes === 1 ? '' : 'es')); }
      return el('div', { cls: 'sv-git risk' }, [icon('warning'), el('span', { text: (bits.join(' · ') || 'Work exists only here') + ' — don\'t delete before committing' })]);
    }
    if ((it.flags || []).indexOf('not_a_git_repo') >= 0) { return el('div', { cls: 'sv-git unknown' }, [icon('eye'), el('span', { text: 'Not a git project: compare the copies by hand' })]); }
    if (g) { return el('div', { cls: 'sv-git ok' }, [icon('check'), el('span', { text: 'All work is saved in git' })]); }
    return el('span');
  }
  function renderProjects(host) {
    var L = S.list, m = S.model;
    var bar = el('div', { cls: 'sv-toolbar' });
    var chips = el('div', { cls: 'sv-chips', attrs: { role: 'group', 'aria-label': 'Which copies' } });
    var risky = m.projects.filter(atRisk).length;
    var bAll = button(['All copies ', el('span', { cls: 'sv-chip-n', text: String(m.projects.length) })], function () { L.riskOnly = false; sync(); draw(); }, 'sv-chip', { 'aria-pressed': String(!L.riskOnly) });
    var bRisk = button([swatch('sv-s-review', 'warning'), 'Only with unsaved work ', el('span', { cls: 'sv-chip-n', text: String(risky) })], function () { L.riskOnly = true; sync(); draw(); }, 'sv-chip', { 'aria-pressed': String(L.riskOnly) });
    function sync() { bAll.setAttribute('aria-pressed', String(!L.riskOnly)); bRisk.setAttribute('aria-pressed', String(L.riskOnly)); }
    chips.appendChild(bAll);
    chips.appendChild(bRisk);
    bar.appendChild(el('div', { cls: 'sv-toolbar-row' }, [el('span', { cls: 'sv-muted sv-chips-label', text: 'Show' }), chips]));
    host.appendChild(bar);
    var body = el('div', { cls: 'sv-projects', attrs: { 'aria-live': 'polite' } });
    host.appendChild(body);
    function draw() {
      U.clear(body);
      var by = {}, order = [];
      m.projects.forEach(function (it) {
        var k = it.group || it.label;
        if (!by[k]) { by[k] = []; order.push(k); }
        by[k].push(it);
      });
      var groups = order.map(function (k) {
        var items = by[k].slice().sort(function (a, b) { return (atRisk(b) ? 1 : 0) - (atRisk(a) ? 1 : 0) || (b.bytes || 0) - (a.bytes || 0); });
        return { key: k, items: items, risk: items.filter(atRisk).length, bytes: sumBytes(items) };
      }).filter(function (g) { return !L.riskOnly || g.risk; })
        .sort(function (a, b) { return (b.risk ? 1 : 0) - (a.risk ? 1 : 0) || b.bytes - a.bytes; });
      if (!groups.length) { body.appendChild(el('div', { cls: 'sv-card sv-empty' }, [icon('check'), el('p', { text: 'No project copies with unsaved work.' })])); return; }
      var max = m.projects.reduce(function (mx, it) { return Math.max(mx, it.bytes || 0); }, 0);
      groups.forEach(function (g) {
        var first = g.items[0], x = first.x || {};
        var card = el('article', { cls: 'sv-card sv-proj' + (g.risk ? ' risk' : '') });
        bvs(card, 'section', null, 'Project ' + (x.packageName || first.label) + ': ' + g.items.length + ' copies');
        card.appendChild(el('header', { cls: 'sv-proj-head' }, [
          el('span', { cls: 'sv-proj-ico' }, icon('branch')),
          el('div', { cls: 'sv-proj-title' }, [
            el('h3', { cls: 'sv-h3', text: x.packageName || first.label }),
            el('div', { cls: 'sv-muted small', text: (x.remote ? x.remote + ' · ' : '') + g.items.length + ' copies · ' + B(g.bytes) + ' in total' })
          ]),
          g.risk ? el('span', { cls: 'sv-badge warn' }, [icon('warning'), g.risk + ' with unsaved work']) : el('span', { cls: 'sv-badge ok' }, [icon('check'), 'No unsaved work'])
        ]));
        if (g.risk) {
          card.appendChild(el('div', { cls: 'sv-risk slim' }, [icon('warning'), el('div', null, [el('strong', { text: 'Don\'t delete before committing. ' }),
            'The copies marked in orange hold work that exists nowhere else. Save it with a ', term('commit', 'commit'), ' and push before removing any copy.'])]));
        }
        var rows = el('div', { cls: 'sv-rows' });
        g.items.forEach(function (it) { rows.appendChild(itemRow(it, { max: max, inGroup: true, extra: gitLine })); });
        card.appendChild(rows);
        body.appendChild(card);
      });
    }
    draw();
  }

  // ---------------------------------------------------------------- system extras
  function systemExtras() {
    var sum = S.model.sum || {};
    var wrap = el('div', { cls: 'sv-sys-extras' });
    var un = sum.unaccounted;
    if (un && un.bytes) {
      var c = el('div', { cls: 'sv-card sv-sys-card' }, [
        el('span', { cls: 'sv-sys-ico' }, icon('lock')),
        el('div', null, [
          el('div', { cls: 'sv-big', text: B(un.bytes) }),
          el('div', null, [term('Unaccounted space', 'unaccounted'), ': ' + (un.note || 'space the scan could not look into.')])
        ])
      ]);
      bvs(c, 'tile', null, 'Unaccounted space ' + B(un.bytes));
      wrap.appendChild(c);
    }
    var cl = sum.cloudOnly;
    if (cl && cl.bytes) {
      wrap.appendChild(el('div', { cls: 'sv-card sv-sys-card' }, [
        el('span', { cls: 'sv-sys-ico cloud' }, icon('download')),
        el('div', null, [el('div', { cls: 'sv-big', text: B(cl.bytes) }), el('div', { text: cl.note || 'Online-only files: they use no space on this PC.' })])
      ]));
    }
    return wrap;
  }

  // ================================================================== registration
  var VIEW = {
    title: 'Storage', group: 'main', icon: ICONS.grid, accent: '#6D5BD0',
    mount: mount, unmount: unmount,
    update: function (params) { applyRoute(readRoute(params)); }
  };
  function register(tries) {
    var a = app();
    if (a && typeof a.registerView === 'function') { a.registerView('storage', VIEW); return; }
    if (tries < 200) { setTimeout(function () { register(tries + 1); }, 50); }
  }
  register(0);

  // Small public helpers for the shell and other views (read-only navigation; nothing deletes).
  BVSUI.StorageView = {
    openItem: function (ref) {
      if (!S.model) { S.model = buildModel(); }
      var it = typeof ref === 'string' ? (S.model && S.model.all.concat(S.model.dups).filter(function (x) { return x.id === ref; })[0]) : ref;
      if (it) { openItemPanel(it); }
    },
    showInMap: function (path) { nav(mapHash(path)); },
    mapHash: mapHash
  };
})();
