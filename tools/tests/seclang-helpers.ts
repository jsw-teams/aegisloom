import { type CompileSecLangOptions, compileSecLang as compile } from "../../scr/seclang/index.js";
import { loadSecLangBackends } from "../../scr/seclang/node.js";

const backends = await loadSecLangBackends();
export const compileSecLang = (source: string, options: CompileSecLangOptions = {}) =>
  compile(source, { ...backends, ...options });
export {
  createInjectionDetectors,
  createPCRE2Backend,
  executeSecLang,
  PCRE2Error,
  splitActions,
} from "../../scr/seclang/index.js";
