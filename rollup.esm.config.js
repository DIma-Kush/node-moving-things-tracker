import babel from '@rollup/plugin-babel';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import sizes from 'rollup-plugin-sizes';

export default [
  {
    input: 'src/tracker',
    output: {
      file: 'bundle.esm.js',
      format: 'esm',
    },
    plugins: [
      resolve({ browser: true, preferBuiltins: false }),
      commonjs({ transformMixedEsModules: true }),
      babel({ babelHelpers: 'bundled' }),
      sizes(),
    ],
  },
];
