import { pathToFileURL } from 'node:url';
import { ConfigError, parseConfig, validateRuntimeArguments } from './config.js';
import { createAzureStorage } from './azure-storage.js';
import { createTelemetryServer } from './server.js';

export async function main(): Promise<void> {
  let receiver: ReturnType<typeof createTelemetryServer> | undefined;
  try {
    validateRuntimeArguments(process.execArgv);
    const config = parseConfig(process.env);
    const storage = await createAzureStorage(config.azure);
    receiver = createTelemetryServer({ storage, limits: config.limits, enabled: config.enabled });
    receiver.server.on('error', () => {
      process.stderr.write('SERVICE_LISTENER_FAILED\n');
      receiver?.stop();
      process.exitCode = 1;
    });
    receiver.server.listen(config.port, config.host);
    const stop = () => {
      receiver?.stop();
      // Bound shutdown even if an underlying SDK request ignores abort.
      setTimeout(() => process.exit(0), 10000).unref();
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  } catch (error) {
    receiver?.stop();
    process.stderr.write(`${error instanceof ConfigError ? error.code : 'SERVICE_START_FAILED'}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
