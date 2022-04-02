import resolve from "@rollup/plugin-node-resolve";
import { babel } from "@rollup/plugin-babel";
import sizes from "rollup-plugin-sizes";
import commonjs from '@rollup/plugin-commonjs';

const config = {
    input: 'tracker.js',
    output: {
        file: 'bundle.js',
        format: 'esm'
    },
    plugins: [
        resolve({ browser: true, preferBuiltins: false }),
        commonjs({ transformMixedEsModules: true }),
        babel({ babelHelpers: 'bundled' }),
        sizes()
    ]
};

export default config;