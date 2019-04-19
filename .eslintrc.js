module.exports = {
  env: {
    commonjs: true,
    es6: true,
    node: true,
  },
  extends: 'airbnb-base',
  globals: {
    Atomics: 'readonly',
    SharedArrayBuffer: 'readonly',
  },
  parserOptions: {
    ecmaVersion: 2018,
  },
  rules: {
    camelcase: 0,
    eqeqeq: 0,
    'no-plusplus': 0,
    'no-restricted-globals': 0,
    'no-underscore-dangle': 0,
    'prefer-destructuring': 0,
    'no-bitwise': 0,
    'no-param-reassign': 0,
    'no-continue': 0,
    'no-cond-assign': 0,
    'no-fallthrough': 0
  },
};
