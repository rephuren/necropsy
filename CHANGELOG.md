# История изменений

## Не выпущено

### Добавлено
- разбор PE32/PE32+ в `inspect`: секции с энтропией, импорты, ASLR/DEP/CFG/подпись, предупреждения (#3)
- `necropsy inspect [--json] FILE`: разбор ELF32/64 little-endian: заголовок, сегменты, секции с энтропией, зависимости, символы, сводка защиты (PIE, NX, RELRO, canary, fortify, stripped, RWX) (#1)
