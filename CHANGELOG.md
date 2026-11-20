# История изменений

## 0.1.0 (2026-11-20)

### Добавлено
- паттерны ImHex `imhex/elf64.hexpat` и `imhex/pe.hexpat` (написаны вручную по спецификациям, в ImHex не запускались) (#7)
- `necropsy strings`: строки ASCII и UTF-16LE с классификацией (url, ip, email, path, registry, private-key, base64, api), фильтры `--min`, `--all`, `--class`, JSON (#5)
- разбор PE32/PE32+ в `inspect`: секции с энтропией, импорты, ASLR/DEP/CFG/подпись, предупреждения (#3)
- `necropsy inspect [--json] FILE`: разбор ELF32/64 little-endian: заголовок, сегменты, секции с энтропией, зависимости, символы, сводка защиты (PIE, NX, RELRO, canary, fortify, stripped, RWX) (#1)
