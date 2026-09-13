#!/usr/bin/env node
import { main } from "./cli.js";

main().then(code => process.exit(code)).catch(e => {
  process.stderr.write("fatal: " + (e as Error).message + "\n");
  process.exit(2);
});
