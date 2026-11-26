import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => ({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: { TEST_MIGRATIONS: await readD1Migrations("./migrations"), PROVER_TOKEN: "test-prover-token-0001", MOCK_GPUS: "0" },
      },
    }),
  ],
  test: { setupFiles: ["./test/setup.ts"] },
}));
