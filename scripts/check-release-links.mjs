import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { parsers } from "prettier/plugins/markdown";

// Read actual Markdown links, including reference definitions, without treating code examples as citations.
const commitUrl =
  /^https:\/\/github\.com\/promptfoo\/modelaudit\/commit\/([a-f0-9]{7,40})(\/?(?:[?#].*)?)$/;
const commits = new Set();
const permalinks = new Map();
function collect(node) {
  const match = node.url?.match(commitUrl);
  if (match) {
    const [, commit, suffix] = match;
    commits.add(commit);
    if (commit.length === 40 && !suffix) permalinks.set(commit, node.url);
  }
  for (const child of node.children ?? []) collect(child);
}

collect(
  await parsers.markdown.parse(readFileSync(process.argv[2], "utf8"), {}),
);
for (const commit of commits) {
  // The read-only metadata job checks out the protected commit used to assemble this release.
  execFileSync("git", ["merge-base", "--is-ancestor", commit, "HEAD"]);
}

// Avoid checking verified permalinks a second time over HTTP.
const configPath = process.argv[3];
if (configPath) {
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  for (const [commit, url] of permalinks) {
    // merge-base also accepts annotated tag objects.
    const type = execFileSync("git", ["cat-file", "-t", commit], {
      encoding: "utf8",
    });
    if (type.trim() === "commit") {
      config.ignorePatterns.push({
        pattern: "^" + url.replaceAll(".", "\\.") + "$",
      });
    }
  }
  writeFileSync(configPath, JSON.stringify(config));
}
