#!/usr/bin/env node
/** Build the packaged viewer JavaScript bundle. */
import { build } from "esbuild";
import { packagedBundlePath, viewerBundleOptions } from "./esbuild-options.mjs";

await build(viewerBundleOptions(packagedBundlePath));
