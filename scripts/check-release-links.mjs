import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { parsers } from "prettier/plugins/markdown";

// Read actual Markdown links, including reference definitions, without treating code examples as citations.
const commitUrl =
  /^https:\/\/github\.com\/promptfoo\/modelaudit\/commit\/([a-f0-9]{7,40})\/?(?:[?#].*)?$/;
const commits = new Set();
function collect(node) {
  const match = node.url?.match(commitUrl);
  if (match) commits.add(match[1]);
  for (const child of node.children ?? []) collect(child);
}

collect(
  await parsers.markdown.parse(readFileSync(process.argv[2], "utf8"), {}),
);
for (const commit of commits) {
  // The read-only metadata job checks out the protected commit used to assemble this release.
  execFileSync("git", ["merge-base", "--is-ancestor", commit, "HEAD"]);
}
