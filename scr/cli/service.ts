import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readCredentials, readDeployment } from "./deployment.js";

export function serviceUnit(node: string, entry: string, config: string) {
  const quote = (value: string, command = false) => {
    if (/[\r\n\0]/.test(value)) throw Error("Invalid service path");
    const escaped = value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("%", "%%");
    return `"${command ? escaped.replaceAll("$", () => "$$") : escaped}"`;
  };
  return `[Unit]\nDescription=EdgeAegis native SecLang firewall\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory=${quote(dirname(config))}\nExecStart=${quote(node, true)} ${quote(entry, true)} serve ${quote(config, true)}\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=default.target\n`;
}

/** Production SSH lifecycle. No daemon is started during package installation. */
export async function service(command: string, path: string, system = false) {
  if (process.platform !== "linux")
    throw Error(
      "Background services require Linux systemd; use start local for foreground development",
    );
  if (!["install", "start", "stop", "status"].includes(command))
    throw Error("Select service install, start, stop or status");
  const file = resolve(path),
    hash = createHash("sha256").update(file).digest("hex").slice(0, 12);
  const name = `edgeaegis-${hash}.service`;
  const args = system ? [] : ["--user"];
  if (command === "install") {
    const { config } = await readDeployment(file);
    await readCredentials(config.secretFile);
    const directory = system ? "/etc/systemd/system" : join(homedir(), ".config/systemd/user");
    await mkdir(directory, { recursive: true });
    const unit = serviceUnit(
      process.execPath,
      fileURLToPath(new URL("./main.js", import.meta.url)),
      file,
    );
    await writeFile(
      join(directory, name),
      system ? unit.replace("WantedBy=default.target", "WantedBy=multi-user.target") : unit,
      { mode: 0o600 },
    );
    execFileSync("systemctl", [...args, "daemon-reload"], { stdio: "inherit", windowsHide: true });
    execFileSync("systemctl", [...args, "enable", "--now", name], {
      stdio: "inherit",
      windowsHide: true,
    });
    console.log(
      `Background service ${name}; logs: journalctl ${system ? "" : "--user "}-u ${name}`,
    );
  } else
    execFileSync("systemctl", [...args, command, "--no-pager", name], {
      stdio: "inherit",
      windowsHide: true,
    });
}
