import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { parsers } from "prettier/plugins/markdown";

// Only repository citations use the GitHub token. The separate Markdown link checker
// requests ordinary reader-facing links without credentials.
const repo = "promptfoo/modelaudit";
const baseUrl = "https://github.com/" + repo + "/";
const manifest = ".release-please-manifest.json";
const previous = JSON.parse(execFileSync("git", ["show", "HEAD:" + manifest]));
const next = JSON.parse(readFileSync(manifest));
const comparisons = new Set();
for (const [path, prefix] of [
  [".", "v"],
  ["packages/modelaudit-picklescan", "modelaudit-picklescan-v"],
]) {
  if (previous[path] !== next[path]) {
    comparisons.add(prefix + previous[path] + "..." + prefix + next[path]);
  }
}

const checked = new Set();
function visit(node) {
  if (node.url?.startsWith(baseUrl) && !checked.has(node.url)) {
    checked.add(node.url);
    const path = new URL(node.url).pathname;
    if (!path.startsWith("/" + repo + "/"))
      throw new Error("Invalid release citation: " + node.url);
    const parts = path.slice(("/" + repo + "/").length).split("/");
    const kind = parts.shift();
    const target = parts.join("/");
    if (["issues", "pull", "commit", "compare"].includes(kind)) {
      if (kind === "compare") {
        // Only the generated comparison has an unpublished tag. Check other ranges normally.
        if (!comparisons.has(target)) {
          if (!/^.+\.\.\..+$/.test(target))
            throw new Error("Invalid comparison: " + node.url);
          execFileSync("gh", [
            "api",
            "--silent",
            "repos/" + repo + "/compare/" + encodeURIComponent(target),
          ]);
        }
      } else if (kind === "commit") {
        if (!/^[0-9a-f]{7,40}$/.test(target))
          throw new Error("Invalid commit: " + node.url);
        execFileSync("git", ["merge-base", "--is-ancestor", target, "HEAD"]);
      } else {
        if (!/^[1-9][0-9]*$/.test(target))
          throw new Error("Invalid issue or pull request: " + node.url);
        const resource = kind === "pull" ? "pulls" : "issues";
        execFileSync("gh", [
          "api",
          "--silent",
          "repos/" + repo + "/" + resource + "/" + target,
        ]);
      }
    }
  }
  for (const child of node.children ?? []) visit(child);
}

visit(await parsers.markdown.parse(readFileSync(process.argv[2], "utf8"), {}));
