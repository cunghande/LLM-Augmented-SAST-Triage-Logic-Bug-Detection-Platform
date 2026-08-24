import fs from "node:fs/promises";
import JSZip from "jszip";

const [mode, archivePath, entryName] = process.argv.slice(2);
if (!mode || !archivePath) process.exit(2);

const zip = await JSZip.loadAsync(await fs.readFile(archivePath));
if (mode === "-Z1") {
  process.stdout.write(`${Object.keys(zip.files).join("\n")}\n`);
} else if (mode === "-p" && entryName) {
  const entry = zip.file(entryName);
  if (!entry) process.exit(11);
  process.stdout.write(await entry.async("nodebuffer"));
} else {
  process.exit(2);
}
