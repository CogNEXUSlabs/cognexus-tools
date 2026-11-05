import { copyFileSync } from "node:fs";

copyFileSync("src/taxonomy.json", "dist/taxonomy.json");
