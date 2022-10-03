import resolve from '@rollup/plugin-node-resolve';
import { babel } from '@rollup/plugin-babel';
import sizes from 'rollup-plugin-sizes';
import commonjs from '@rollup/plugin-commonjs';

const config = {
  input: 'src/tracker',
  output: {
    file: 'bundle.cjs.js',
    format: 'cjs',
  },
  plugins: [
    resolve({ browser: true, preferBuiltins: false }),
    commonjs({ transformMixedEsModules: true }),
    babel({ babelHelpers: 'bundled' }),
    sizes(),
  ],
};

export default config;
