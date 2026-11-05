import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    typecheck: {
      enabled: true,
      include: ["src/gate.hook.test-d.ts"],
      tsconfig: "./tsconfig.typecheck.json",
    },
  },
});
