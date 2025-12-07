#!/bin/bash
# Создаем полный дамп проекта с комментариями и структурой
OUTPUT_FILE="project_full_dump.txt"

echo "# ПОЛНЫЙ ДАМП ПРОЕКТА CRYPTOCORE" > $OUTPUT_FILE
echo "# Дата создания: $(date)" >> $OUTPUT_FILE
echo "==============================================\n" >> $OUTPUT_FILE

# 1. Сначала выводим структуру проекта
echo "## СТРУКТУРА ПРОЕКТА" >> $OUTPUT_FILE
echo '```' >> $OUTPUT_FILE
tree -I "*.bin|*.png|*.dec|*.enc" --dirsfirst >> $OUTPUT_FILE 2>/dev/null || find . -type f -name "*.c" -o -name "*.h" -o -name "*.sh" -o -name "Makefile" -o -name "*.md" | sort >> $OUTPUT_FILE
echo '```' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# 2. Файл README.md
echo "## README.md" >> $OUTPUT_FILE
echo '```markdown' >> $OUTPUT_FILE
[ -f README.md ] && cat README.md >> $OUTPUT_FILE || echo "README.md не найден" >> $OUTPUT_FILE
echo '```' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# 3. Makefile
echo "## MAKEFILE" >> $OUTPUT_FILE
echo '```makefile' >> $OUTPUT_FILE
[ -f Makefile ] && cat Makefile >> $OUTPUT_FILE || echo "Makefile не найден" >> $OUTPUT_FILE
echo '```' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# 4. Основные исходные файлы (.c, .h)
echo "## ИСХОДНЫЙ КОД (C/C++)" >> $OUTPUT_FILE

# Ищем все исходные файлы
find src include -name "*.c" -o -name "*.h" 2>/dev/null | sort | while read file; do
    echo "### Файл: $file" >> $OUTPUT_FILE
    echo '```c' >> $OUTPUT_FILE
    cat "$file" >> $OUTPUT_FILE
    echo '```' >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
done

# 5. Тестовые файлы
echo "## ТЕСТЫ" >> $OUTPUT_FILE

# Тестовые .c файлы
find tests -name "*.c" 2>/dev/null | sort | while read file; do
    echo "### Тестовый файл: $file" >> $OUTPUT_FILE
    echo '```c' >> $OUTPUT_FILE
    cat "$file" >> $OUTPUT_FILE
    echo '```' >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
done

# Скрипты тестов
find tests -name "*.sh" 2>/dev/null | sort | while read file; do
    echo "### Скрипт тестирования: $file" >> $OUTPUT_FILE
    echo '```bash' >> $OUTPUT_FILE
    cat "$file" >> $OUTPUT_FILE
    echo '```' >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
done

# 6. Основные скрипты в корне
[ -f run_tests.sh ] && {
    echo "## СКРИПТЫ В КОРНЕ" >> $OUTPUT_FILE
    echo "### run_tests.sh" >> $OUTPUT_FILE
    echo '```bash' >> $OUTPUT_FILE
    cat run_tests.sh >> $OUTPUT_FILE
    echo '```' >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
}

echo "# КОНЕЦ ДАМПА ПРОЕКТА" >> $OUTPUT_FILE

echo "Дамп создан: $OUTPUT_FILE"