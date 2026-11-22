# Volume facts (authoritative figure set)

**What this describes.** These numbers measure my whole private workspace, of which this repository is a small published slice (six component folders). They are not counts of the code in this repository. For the tests that belong to this repository, run `./run_all_tests.sh` and see [VERIFICATION.md](VERIFICATION.md).

Measured 2026-11-21, 10:38 to 10:41 MST, on one Mac, with Python 3.13.17. Tag: [observed] (I ran it; the raw tool output is reproduced below).
This is the single set of volume numbers for everything I publish. It replaces the earlier figures (about 690,000 lines, 939,685 lines, 1,248 test files, 15,184 test definitions, 18,788 test functions, 1,469 test files and the "1.15 million lines" total). Those came from different tools and different scopes. See "Superseded numbers" below.
My workspace is live and changes every day (other sessions edit it while I measure), so every number here is dated and will already be slightly different tomorrow. Quote them as "about", with the date.

## The figure set (use these and only these)

Scope: repository code as authored (defined below), deduplicated, my private workspace (not published), Python 3.13.17, 2026-11-21.

| Fact | Value |
|---|---|
| Python files | 2,848 |
| Python lines (physical) | 929,441 (780,431 code, 115,627 blank, 33,383 comment) |
| Test files (`test_*.py`, `*_test.py`) | 1,259 |
| Test definitions, counted by AST | 14,930 (14,901 in `TestCase` classes, 29 at module level). A definition is not a pass. |
| Test cases collected by `unittest` discovery in `scripts/` | 15,665, with 5 modules that failed to import. Collection, not a pass count. |
| Other languages, same scope | shell 99 files / 7,939 lines; JavaScript 86 / 17,339; TypeScript 107 / 12,502; SQL 522 / 13,641; HTML 65 / 22,414; CSS 10 / 124; Go 15 / 1,258; Rust 1 / 444; C and C++ 7 / 1,106 |
| All languages above including Python | about 1,006,000 lines (929,441 Python plus 76,767 other), nine languages |

Rounded for prose: about 930,000 lines of Python in about 2,850 files, about 1,260 test files, about 14,900 test definitions (by AST), about 1.0 million lines across nine languages.

Not a figure I publish: the earlier "1.15 million lines in 16 languages" total. It came from a different tool and a wider scope that included my private runtime folder (`private/`, about 115,000 lines by that tool's own table) and Swift, C#, QML and other languages this tool does not count. I cannot reproduce it with this tool, so I dropped it. If I ever quote a total that includes `private/`, I will say so and give the tool and date next to it.

## How to read "test" numbers (one definition each)

- Test files: file names matching `test_*.py` or `*_test.py` in scope.
- Test definitions (AST): a `test_*` function or async function at module level, or directly inside a class whose base is named `...TestCase`. Found by parsing, not by grep. This is the number to quote as "test definitions". 14,930.
- Collected test cases: what `unittest` discovery reports for `scripts/` (15,665). It is larger than the AST count for `scripts/` because discovery also counts tests inherited from base classes and classes whose base is not literally named `...TestCase`. I did not break the difference down further.
- "Test functions" from a regex count (`def test_` anywhere, 18,788 in an earlier run) is retired. Do not quote it.
- None of these is a pass rate. I do not claim one for the workspace.

## Exact command and tool output

The tool is `volume_count.py`, a stdlib-only counter I wrote with AI agent help. It is not shipped in this repository: it contains my private workspace layout, so I removed it before release. A private copy is kept outside this repository, so you cannot re-run the measurement from here. The scope below is written out so it can be re-implemented. Treat these numbers as [observed] by me, not as independently reproducible by you.

Command (the workspace path is private and written here as a placeholder):

```
HOME=$(mktemp -d) PYTHONDONTWRITEBYTECODE=1 python3.13 -I -B volume_count.py --root <workspace> --collect
```

Self-test of the tool (13 tests on a synthetic tree): `python3.13 -I -B volume_count.py --selftest` ran 13 tests, OK [observed, 2026-11-21; also OK on Python 3.9.6].
The tool only reads the tree. The `--collect` step imports test modules, so it runs in a child process under macOS `sandbox-exec` with writes inside the workspace denied, network denied, a throwaway HOME and no bytecode writing; without a sandbox it refuses to run. The `SyntaxWarning` lines the child prints on stderr come from old test modules it imports, not from the counter.
Run time about 200 seconds (10:38:03 to 10:41:23 MST).

Raw output (only the root label is replaced by `<workspace>`):

```
VOLUME COUNT  root=<workspace>

SCOPE (repository code as authored)
  excluded directories:
    archive/       old copies and retired material, not current work
    data/          run output, logs, ledgers and downloaded libraries; data, not authored code
    private/       my private runtime state; not part of the repository
    system/        machine-generated system state
    .git/          version control internals
    .venv/         virtual environment (third-party code)
    venv/          virtual environment (third-party code)
    site-packages/ installed third-party packages
    dist-packages/ installed third-party packages
    node_modules/  installed third-party packages
    .stversions/   Syncthing automatic old-version store (copies of files that exist elsewhere)
    __pycache__/   byte-code caches
    vendor/        vendored copies of other people's code
    vendored/      vendored copies of other people's code
    third_party/   vendored copies of other people's code
  excluded file names:
    *sync-conflict*   Syncthing conflict copy (duplicate of a real file)
    *.bak*   hand-made backup (duplicate of a real file)
  then dedup by sha256 of content (identical files counted once)
  symlinks are never followed or counted

REPOSITORY CODE AS AUTHORED (scope above, deduped)
  python files            2848
  python lines            929441
    code                  780431
    blank                 115627
    comment               33383
  python test files       1259
  test defs (AST)         14930
    in TestCase classes   14901
    module-level          29
    in test-named files   14855
  ast-unparseable files   2
  tokenize-fallback files 1
  unreadable files        0
  c/c++                   7 files, 1106 lines
  css                     10 files, 124 lines
  go                      15 files, 1258 lines
  html                    65 files, 22414 lines
  javascript              86 files, 17339 lines
  rust                    1 files, 444 lines
  shell                   99 files, 7939 lines
  sql                     522 files, 13641 lines
  typescript              107 files, 12502 lines
  dedup: 2274 duplicate files dropped (1127 of them Python)

INCLUDING EVERYTHING (no exclusions, no dedup)
  python files            19707
  python lines            7505136
    code                  6112670
    blank                 1076007
    comment               316459
  python test files       6538
  test defs (AST)         83425
    in TestCase classes   52941
    module-level          30484
    in test-named files   82797
  ast-unparseable files   24
  tokenize-fallback files 13
  unreadable files        0
  c/c++                   2078 files, 1223532 lines
  css                     232 files, 45409 lines
  go                      15 files, 1258 lines
  html                    49978 files, 5072363 lines
  javascript              3207 files, 1733530 lines
  rust                    39 files, 15588 lines
  shell                   257 files, 16235 lines
  sql                     1610 files, 47506 lines
  typescript              454 files, 1579018 lines

ACTUAL COLLECTION (unittest discovery): ran under sandbox-exec; fake HOME; writes inside root denied; network denied
  scripts: {"collected": 15665, "import_failures": 5, "status": "ok"}
```

## Scope ("repository code as authored")

Counted: regular files under the workspace root, symlinks never followed. Skipped directories: `archive/` (old copies), `data/` (run output, logs, ledgers, downloaded libraries), `private/` (my runtime state), `system/` (generated state), `.git`, `.venv`, `venv`, `site-packages`, `dist-packages`, `node_modules` (third-party code), `.stversions` (Syncthing old versions), `__pycache__`, `vendor`, `vendored`, `third_party`. Skipped file names: `*sync-conflict*` and `*.bak*` (duplicates of real files). Then files with byte-identical content are counted once.
Line classes: blank, comment (a line holding only a `#` comment, found with `tokenize`), code (everything else, docstrings included).
The second block in the raw output ("including everything", no exclusions, no dedup) is an upper bound that contains downloaded libraries, backups, archives and run data. It is not authored work and I never quote it.

## Superseded numbers

Earlier drafts of these figures used different scopes (a narrower folder, or a wider walk that included run data and duplicates). They are retired. Only the figure set at the top of this file is current, and every number is dated.

## Limits

- The workspace is live and synced between machines; the numbers are for the moment of the run on 2026-11-21 and drift by about 1% in hours on the Python line count, and by far more on the "including everything" block.
- Lines are physical lines. They measure volume, not quality, correctness or how much a person typed. AI coding agents wrote most of the code under my direction and verification.
- `exports/` and `business/` may hold generated or exported material that is byte-different from other copies, so it is not removed by dedup.
- Counts of repositories, CHANGELOG lines and incident ledgers are not part of this tool's output; where they appear elsewhere they carry their own date and tag.
