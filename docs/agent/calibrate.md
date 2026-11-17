# Brief: record known-good items of this PC

**Goal.** Teach the scanner what is normal on *this* PC, so the next report is not cluttered with
things the user installed on purpose. The place for that is `src\config\local\expected.json`, the
machine profile. It is git-ignored and never leaves the PC.

**Why this needs care.** Every item in the profile takes a finding out of the verdict. An item
that is too broad, or that was never confirmed, can hide a real problem. So: one item, one
explicit confirmation from the user.

**When.** After the standard scan and report. Before verification (`verify.md`), because the
affected collectors must be re-run for the profile to take effect.

## Steps

1. **Create the profile if it does not exist.**

   ```powershell
   New-Item -ItemType Directory -Force src\config\local | Out-Null
   Copy-Item src\config\expected.example.json src\config\local\expected.json
   ```

   The template's `items` list is empty, so nothing changes yet. Its `examples` list shows one
   entry per category; the scanner ignores it.
2. **Collect candidates** from the report: findings whose `fp_notes` or evidence point to
   software or settings the user probably chose (a VPN, a container runtime, a developer tool's
   sandbox account, the antivirus product's own certificate, a known startup entry).
3. **Ask the user about each candidate, one at a time,** in plain words: what was found, where,
   and since when. For example: "A program called X starts with Windows from this folder. Did you
   install it?"
4. **Only on a clear yes, add one item** to `items`:
   - Copy the example of the matching `category` and adapt it.
   - Make `match` as narrow as possible: the exact name, path, ID or port. No wildcards over a
     whole folder tree, never the user profile or a drive root.
   - Write the `reason`, including that the user confirmed it and when.
   - Add `invalidIf` conditions that should cancel the match (unsigned binary, unexpected
     folder, listening on more than loopback).
   - If the user is not sure, either leave it out or set `"confirmWithUser": true`, which keeps
     the question in the report.
5. **Never add an item for:**
   - a finding of class `compromise`, or any critical finding;
   - something the user does not recognise;
   - "everything from vendor X" or "everything in folder Y".
6. **Re-run the modules whose findings you touched,** then rebuild the report:

   ```powershell
   pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 security -Only S01,S07
   pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 report
   ```

7. **Tell the user** which items you added. They can read and edit the file themselves.

Format and categories: `docs\schema.md`, "Machine profile".
