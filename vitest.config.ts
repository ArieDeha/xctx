import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['test/nodejs/**/*.spec.ts'],
        exclude: [
            'node_modules/**',
            'vendor/**',
            'dist/**',
            'coverage/**',
            'example/**',
            'src/Xctx/**',
            '**/*.php',
            '**/*.go',
            '**/*.md'
        ],
        coverage: {
            provider: 'v8',                    // <-- was 'c8'
            reportsDirectory: 'coverage-node',
            reporter: ['text', 'lcov', 'html'],
            include: ['src/nodejs/**/*.ts'],
            exclude: ['src/Xctx/**', 'dist/**', 'test/**', 'example/**'],
            thresholds: { lines: 90, functions: 90, branches: 85, statements: 90 },
        },
    },
});
