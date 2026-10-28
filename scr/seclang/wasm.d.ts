declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}
declare module "*.yml" {
  const text: string;
  export default text;
}
