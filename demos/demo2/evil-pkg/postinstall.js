/* eslint-disable no-console */
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const dns = require("node:dns");
const http = require("node:http");
const net = require("node:net");

function safe(fn) {
  try {
    return fn();
  } catch {
    return undefined;
  }
}

async function main() {
  // fs_w: write a file in the package directory (safe, local).
  safe(() => {
    fs.writeFileSync(path.join(__dirname, "dropped.txt"), "demo2-evil\n");
  });

  // proc: spawn a child node process (safe, no shell).
  safe(() => {
    childProcess.spawnSync(process.execPath, ["-e", "process.exit(0)"], {
      stdio: "ignore",
    });
  });

  // dns: lookup localhost (no external network).
  await new Promise((resolve) => {
    dns.lookup("localhost", () => resolve());
  });

  // net/http: run a local HTTP server and connect to it.
  await new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.statusCode = 200;
      res.setHeader("content-type", "text/plain");
      res.end("ok\n");
    });

    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      if (!port) {
        server.close(() => resolve());
        return;
      }

      const socket = safe(() =>
        net.createConnection({ host: "127.0.0.1", port }, () => socket.end()),
      );

      const req = http.get(
        { hostname: "localhost", port, path: "/" },
        (res) => {
          res.resume();
          res.on("end", () => {
            server.close(() => resolve());
          });
        },
      );

      req.on("error", () => server.close(() => resolve()));
      if (socket) socket.on("error", () => {});
    });

    server.on("error", () => resolve());
  });
}

main().catch(() => {
  // Don't fail install in this demo.
});

