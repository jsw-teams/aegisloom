import { spawn } from "node:child_process";
export const distro = process.env.RECORDING_VM || "CodexRecordingVM";
export const wsl = process.env.WSL_EXE || "C:\\Windows\\System32\\wsl.exe";
export const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
export function launch(args, { inputOpen = false } = {}) {
  const child = spawn(wsl, ["-d", distro, "--exec", "bash", "-s"], {
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const command =
    "exec env -u WAYLAND_DISPLAY -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR DISPLAY=:99 LANG=C.UTF-8 " +
    args.map(quote).join(" ") +
    "\n";
  if (inputOpen) child.stdin.write(command);
  else child.stdin.end(command);
  return child;
}
export function guest(args, { timeout = 30000 } = {}) {
  return new Promise((done, reject) => {
    const child = launch(["timeout", `${String(timeout / 1000)}s`, ...args]);
    let output = "";
    child.stdout.on("data", (part) => (output += part));
    child.stderr.on("data", (part) => (output += part));
    child.once("error", reject);
    child.once("exit", (code) =>
      code === 0 ? done(output.trim()) : reject(new Error(`${args[0]} exited ${code}: ${output}`)),
    );
  });
}
export const shell = (code, options) => guest(["bash", "-lc", code], options);
export function mount(path) {
  return path
    .replaceAll("\\", "/")
    .replace(/^([A-Za-z]):/, (_, drive) => `/mnt/${drive.toLowerCase()}`);
}
