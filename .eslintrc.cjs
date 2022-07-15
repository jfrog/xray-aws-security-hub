module.exports = {
    extends: [
        'eslint:recommended',
        'plugin:node/recommended',
        'airbnb-base',
    ],
    env: {
        node: true,
        mocha: true,
        es6: true
    },
    parser: '@babel/eslint-parser',
    parserOptions: {
        requireConfigFile: false,
        sourceType: "module",
        allowImportExportEverywhere: false,
        ecmaFeatures: {
            globalReturn: false,
        },
    },
    rules: {
        'import/extensions': 'off',
        'import/no-dynamic-require': 'off',
        'import/no-extraneous-dependencies': 'off', // so we can import stuff from src/node_modules
        'import/prefer-default-export': 'off',
        'global-require': 'off',
        'max-classes-per-file': 'off',
        'max-len': 'off', // allow code to have an unlimited length
        'newline-per-chained-call': 'off', // method chaining for the win!
        'no-plusplus': 'off',
        'no-return-await': 'off', // While technically redundant, 'return await' helps to indicate the presence of an async function, and can be necessary to catch errors in the right place.
        'no-underscore-dangle': 'off', // some people like to denote a private variable using _ as the start of the name
        'no-unused-expressions': 'off', // helpful in chai testing
        'no-unused-vars': ['error', { varsIgnorePattern: '^_', argsIgnorePattern: '^_' }],
        'no-use-before-define': ['error', { functions: false, classes: true, variables: true }], // https://eslint.org/docs/rules/no-use-before-define
        'node/no-unpublished-require': ['error', { allowModules: ['chai', 'chai-as-promised', 'proxyquire', 'sinon'] }],
        'node/no-unsupported-features/es-syntax': 'off',
        'prefer-destructuring': ['error', { object: true, array: false }],
        'yoda': 'off', // support yoda conditionals like 1 === variable leading to less chances of introducing bugs with something like if (variable = 1)...
    },
};
