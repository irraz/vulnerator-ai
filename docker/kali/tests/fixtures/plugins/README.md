# Plugin fixtures for `test_plugin_loader`

Example plugin tree that `test_plugin_loader.py` points at as `plugins_root`. Each
subdirectory exercises one loader path:

- `aaa_first` / `zzz_last`: valid plugins (check deterministic alphabetical order).
- `sibling_import`: `plugin.py` that does `import helper` (sibling) — demonstrates MEDIUM-3.
- `broken_import.src` → renamed in the test to a dir with a broken import (see note). Instead
  we use `broken_import` with a nonexistent `import` (phase 'import').
- `no_api`: without `PLUGIN_API` (phase 'api').
- `bad_api`: incompatible `PLUGIN_API` (phase 'api').
- `no_register`: without a callable `register` (phase 'register-missing').
- `raises_register`: `register` that registers a tool and then raises (phase 'register' + NIT-8).
- `example.disabled`: disabled dir (ignored).
- `not_a_plugin`: dir without `plugin.py` (skipped).

Invalid directory names (MEDIUM-4) CANNOT exist as a portable folder on all FS, so that case
is created on the fly inside the test with `tmp_path`.
