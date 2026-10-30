# Fixtures de plugins para `test_plugin_loader`

Árbol de plugins de ejemplo que `test_plugin_loader.py` apunta como `plugins_root`. Cada
subdirectorio ejercita un camino del cargador:

- `aaa_first` / `zzz_last`: plugins válidos (comprueban orden alfabético determinista).
- `sibling_import`: `plugin.py` que hace `import helper` (hermano) — demuestra MEDIUM-3.
- `broken_import.src` → se renombra en test a un dir con import roto (ver nota). En su
  lugar usamos `broken_import` con un `import` inexistente (fase 'import').
- `no_api`: sin `PLUGIN_API` (fase 'api').
- `bad_api`: `PLUGIN_API` incompatible (fase 'api').
- `no_register`: sin callable `register` (fase 'register-missing').
- `raises_register`: `register` que registra una tool y luego lanza (fase 'register' + NIT-8).
- `example.disabled`: dir deshabilitado (ignorado).
- `not_a_plugin`: dir sin `plugin.py` (omitido).

Los nombres inválidos de directorio (MEDIUM-4) NO pueden existir como carpeta portable en
todos los FS, así que ese caso se crea en caliente dentro del test con `tmp_path`.
