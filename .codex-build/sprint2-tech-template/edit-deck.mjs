import fs from "node:fs/promises";
import { FileBlob, PresentationFile } from "@oai/artifact-tool";

const STARTER = "D:\\Code\\AI security\\.codex-build\\sprint2-tech-template\\template-starter.pptx";
const FINAL = "D:\\Code\\AI security\\LLM-Augmented-SAST-Sprint2-Tech-Deck.pptx";
const QA_DIR = "D:\\Code\\AI security\\.codex-build\\sprint2-tech-template\\final-qa";
const FONT = "Times New Roman";

const p = await PresentationFile.importPptx(await FileBlob.load(STARTER));

const LOCATORS = {
  "sh/4nex4nu5": [0, "shape", "TextBox 3"],
  "sh/uhcfydc3": [0, "shape", "TextBox 1"],
  "sh/filw7it8": [0, "shape", "TextBox 2"],
  "sh/orapsrm9": [0, "shape", "Page Number 1"],
  "sh/r2lknytk": [1, "shape", "Title 1"],
  "sh/61cjudsz": [1, "shape", "Content Placeholder 2"],
  "sh/4za1s3ut": [1, "shape", "Page Number 10"],
  "sh/xoj65sjy": [2, "shape", "Title 1"],
  "sh/wnapwnid": [2, "shape", "Content Placeholder 2"],
  "sh/nyhozi1g": [2, "shape", "TextBox 3"],
  "sh/mx87qdkb": [2, "shape", "TextBox 4"],
  "sh/90z618jm": [2, "shape", "Page Number 16"],
  "sh/gvmx0v6p": [3, "shape", "Title 1"],
  "sh/hgve907u": [3, "shape", "Content Placeholder 2"],
  "sh/6pkvulo7": [3, "shape", "Page Number 12"],
  "sh/9wjexsjm": [4, "shape", "Title 1"],
  "sh/8vadoni1": [4, "shape", "Content Placeholder 2"],
  "sh/yp8vid0z": [4, "shape", "Page Number 13"],
  "sh/ypsfq54n": [5, "shape", "Title 1"],
  "sh/jq1wzq58": [5, "shape", "Content Placeholder 2"],
  "sh/8vuxwfmp": [5, "shape", "Page Number 14"],
  "sh/etkfit0z": [6, "shape", "Title 1"],
  "sh/futgby1k": [6, "shape", "Content Placeholder 2"],
  "sh/ozmxo3ih": [6, "shape", "Page Number 18"],
  "sh/4zuto7a5": [7, "shape", "Title 1"],
  "sh/503ahcbq": [7, "shape", "Content Placeholder 2"],
  "sh/r25cj2tw": [7, "shape", "Page Number 15"],
  "sh/qdgvu1gj": [8, "shape", "Title 1"],
  "sh/rypwn6x4": [8, "shape", "Content Placeholder 2"],
  "sh/03id0byl": [8, "shape", "Page Number 19"],
  "sh/5s32d4z6": [9, "shape", "Title 1"],
  "sh/4ru1kzil": [9, "shape", "Content Placeholder 2"],
  "sh/vm107ah4": [9, "shape", "TextBox 3"],
  "sh/ulsjep0j": [9, "shape", "TextBox 4"],
  "sh/hoji9kza": [9, "shape", "Page Number 16"],
  "sh/8fadgnq9": [10, "shape", "Title 1"],
  "sh/tgjepsru": [10, "shape", "Content Placeholder 2"],
  "tb/tgnq1gbe": [10, "table", "Table 3"],
  "sh/zahwjy9s": [10, "shape", "Page Number 17"],
  "sh/m1kvyl03": [11, "shape", "Title 1"],
  "sh/72tcrqho": [11, "shape", "Content Placeholder 2"],
  "tb/jqx4zi5k": [11, "table", "Table 3"],
  "sh/lgbup0zi": [11, "shape", "Page Number 17"],
  "sh/d8j6l8na": [12, "shape", "Title 1"],
  "sh/c7apcn6p": [12, "shape", "Content Placeholder 2"],
  "sh/za1oni50": [12, "shape", "Page Number 19"],
};

function element(id) {
  const locator = LOCATORS[id];
  if (!locator) throw new Error(`Missing locator for ${id}`);
  const [slideIndex, kind, name] = locator;
  const slide = p.slides.getItem(slideIndex);
  const collection = kind === "table" ? slide.tables.items : slide.shapes.items;
  const found = collection.find((item) => item.name === name);
  if (!found) throw new Error(`Cannot find ${kind} '${name}' on slide ${slideIndex + 1}`);
  return found;
}

function replace(id, oldText, newText) {
  const shape = element(id);
  shape.text.replace(oldText, newText);
}

function setText(id, text, fontSize = 27, options = {}) {
  const shape = element(id);
  shape.text = text;
  shape.text.style = {
    typeface: FONT,
    fontSize,
    color: options.color ?? "#000000",
    bold: options.bold ?? false,
    alignment: options.alignment ?? "left",
    verticalAlignment: options.verticalAlignment ?? "top",
    autoFit: "shrinkText",
    wrap: "square",
  };
}

function setRich(id, paragraphs, fontSize = 27) {
  const shape = element(id);
  shape.text = paragraphs.map((item) => ({
    ...(item.bullet ? { bulletCharacter: item.bullet, marginLeft: 28, indent: -16 } : {}),
    runs: [{
      run: item.text,
      textStyle: {
        typeface: FONT,
        fontSize: `${item.size ?? fontSize}px`,
        bold: item.bold ?? false,
        italic: item.italic ?? false,
        color: item.color ?? "#000000",
      },
    }],
  }));
  shape.text.style = {
    typeface: FONT,
    fontSize,
    color: "#000000",
    verticalAlignment: "top",
    autoFit: "shrinkText",
    wrap: "square",
  };
}

function setNotes(slideIndex, talkTrack, sources) {
  const slide = p.slides.getItem(slideIndex);
  slide.speakerNotes.textFrame.setText(`${talkTrack}\n\n[Sources]\n${sources.map((s) => `- ${s}`).join("\n")}`);
  slide.speakerNotes.setVisible(true);
}

function setTable(id, values) {
  const table = element(id);
  values.forEach((row, r) => row.forEach((value, c) => {
    table.cells.set(r, c, value);
    const cell = table.getCell(r, c);
    cell.text.style = {
      typeface: FONT,
      fontSize: r === 0 ? 22 : 21,
      bold: r === 0,
      color: r === 0 ? "#FFFFFF" : "#000000",
      verticalAlignment: "middle",
    };
  }));
}

// Slide 1 — Opening
replace("sh/4nex4nu5", "LLM-Augmented SAST Triage", "LLM-Augmented SAST Triage");
replace("sh/filw7it8", "SEMINAR", "SPRINT 2 TECHNICAL DECK");
replace("sh/uhcfydc3", "Presenter: DoVanCung", "Presenter: DoVanCung");
replace("sh/orapsrm9", "1", "1");
setNotes(0, "Sprint 2 đưa hệ thống từ triage theo finding sang evidence-driven triage có dataflow cross-file, logic detector, policy và risk scoring deterministic.", ["README.md", "docs/sprint-2-status.md"]);

// Slide 2 — Pipeline
replace("sh/r2lknytk", "XÂY DỰNG BÀI TOÁN", "KIẾN TRÚC HỆ THỐNG");
setText("sh/61cjudsz", "Pipeline triage duy nhất", 37, { bold: true });
replace("sh/4za1s3ut", "10", "2");
setNotes(1, "Hai chế độ CLI và mọi loại finding dùng chung một pipeline. Module 2 và Joern bổ sung evidence trước provider; không tạo pipeline cạnh tranh.", ["README.md", "docs/architecture.md"]);

// Slide 3 — Contracts
replace("sh/xoj65sjy", "XÂY DỰNG BÀI TOÁN", "PIPELINE CONTRACTS");
setText("sh/wnapwnid", "Scanner, domain model và Safe Context", 37, { bold: true });
setRich("sh/nyhozi1g", [
  { text: "1. Scanner → NormalizedFinding", bold: true, size: 34 },
  { text: "Semgrep: SAST finding", bullet: "•" },
  { text: "Gitleaks: secret được redact sớm", bullet: "•" },
  { text: "Artifact–repository binding phải VERIFIED", bullet: "•" },
  { text: "Finding lỗi vẫn được giữ lại", bullet: "•" },
], 27);
setRich("sh/mx87qdkb", [
  { text: "2. Safe Context → TriageInput", bold: true, size: 34 },
  { text: "Resolve path và kiểm tra containment", bullet: "•" },
  { text: "Chọn AST scope hoặc line window", bullet: "•" },
  { text: "Redact credential và cắt theo budget", bullet: "•" },
  { text: "Provider không nhận raw source", bullet: "•" },
], 27);
replace("sh/90z618jm", "16", "3");
setNotes(2, "Domain boundary giữ raw source và raw secret khỏi public model. Provider chỉ nhận TriageInput đã sanitize.", ["docs/domain-models.md", "docs/security-policy.md"]);

// Slide 4 — Safe Context
replace("sh/gvmx0v6p", "XÂY DỰNG BÀI TOÁN", "SAFE CONTEXT & DATA BOUNDARY");
setRich("sh/hgve907u", [
  { text: "SafeContextService — ranh giới duy nhất", bold: true, size: 35 },
  { text: "Raw source chỉ tồn tại trong local scope" },
  { text: "Gitleaks secret được redact tại parser và context" },
  { text: "Chặn traversal, absolute path và symlink escape" },
  { text: "Source được đóng gói như untrusted data" },
  { text: "Reporter leak-check trước khi ghi file" },
], 31);
replace("sh/6pkvulo7", "12", "4");
setNotes(3, "Sanitize cho Semgrep không phải no-op. Gitleaks được redact hai lớp vì source file vẫn có thể chứa secret thật.", ["docs/security-policy.md", "docs/threat-model.md"]);

// Slide 5 — Joern
replace("sh/9wjexsjm", "XÂY DỰNG BÀI TOÁN", "JOERN CPG & CROSS-FILE EVIDENCE");
setRich("sh/8vadoni1", [
  { text: "Joern 4.0.600 — dataflow backend", bold: true, size: 33 },
  { text: "CPG cho toàn repository", bullet: "•" },
  { text: "Argument → Parameter", bullet: "•" },
  { text: "Caller → Callee", bullet: "•" },
  { text: "Return → Assignment", bullet: "•" },
  { text: "Tìm guard / sanitizer ở file khác", bullet: "•" },
  { text: "FunctionSummary không chứa source", bullet: "•" },
], 27);
replace("sh/yp8vid0z", "13", "5");
setNotes(4, "Joern là backend duy nhất cho source–sink, dataflow và call graph. FunctionSummary chỉ giữ identifier, path tương đối, line và flow/control facts.", ["docs/joern-analysis.md", "README.md"]);

// Slide 6 — Evidence Card
replace("sh/ypsfq54n", "XÂY DỰNG BÀI TOÁN", "EVIDENCE CARD & BOUNDED AGENT");
setRich("sh/jq1wzq58", [
  { text: "Evidence Card v3", bold: true, size: 34 },
  { text: "Source / sink symbol và line", bullet: "•" },
  { text: "Function-scoped sanitized code", bullet: "•" },
  { text: "Trace step: kind, file, symbol, line", bullet: "•" },
  { text: "Counter-evidence: authz / sanitizer", bullet: "•" },
  { text: "Retrieval-resolution cho fact trực tiếp", bullet: "•" },
  { text: "Bounded Agent", bold: true, size: 32 },
  { text: "Tối đa 5 tool call cho mỗi finding", bullet: "•" },
  { text: "Dừng khi đủ evidence hoặc không tiến triển", bullet: "•" },
], 27);
replace("sh/8vuxwfmp", "14", "6");
setNotes(5, "Evidence Card là contract an toàn giữa analysis layer và provider. Agent chỉ truy vấn facts bounded, không thực thi source hoặc output của LLM.", ["docs/sprint-2-status.md", "docs/architecture.md"]);

// Slide 7 — Logic detector
replace("sh/etkfit0z", "HƯỚNG PHÁT TRIỂN", "LOGIC DETECTOR — SPRINT 2");
setRich("sh/futgby1k", [
  { text: "Chỉ phát ra hai lớp đã chốt", bold: true, size: 34 },
  { text: "missing_authz_idor", bold: true, bullet: "•" },
  { text: "owner / user / tenant / ACL guard", bullet: "▪" },
  { text: "exact-object authorization counter-evidence", bullet: "▪" },
  { text: "business_rule_bypass", bold: true, bullet: "•" },
  { text: "client-controlled price / total", bullet: "▪" },
  { text: "quantity thiếu bound", bullet: "▪" },
  { text: "pagination hoặc collection thiếu cap", bullet: "▪" },
  { text: "Bounded candidate engine — không phải formal proof", italic: true },
], 27);
replace("sh/ozmxo3ih", "18", "7");
setNotes(6, "Detector Sprint 2 giới hạn còn hai lớp. Counter-evidence được kiểm tra trước khi phát candidate IDOR.", ["docs/sprint-2-scope.md", "docs/sprint-2-status.md"]);

// Slide 8 — LLM + Policy
replace("sh/4zuto7a5", "XÂY DỰNG BÀI TOÁN", "LLM TRIAGE & CONSERVATIVE POLICY");
setRich("sh/503ahcbq", [
  { text: "Provider chỉ nhận TriageInput đã sanitize", bold: true, size: 32 },
  { text: "Schema triage-decision-v1", bold: true },
  { text: "LIKELY_TP", bullet: "•" },
  { text: "LIKELY_FP", bullet: "•" },
  { text: "NEEDS_REVIEW", bullet: "•" },
  { text: "Output luôn được validate", bullet: "•" },
  { text: "Policy mới quyết định system action", bullet: "•" },
  { text: "Thiếu evidence → MANUAL_REVIEW", bullet: "•" },
  { text: "Provider lỗi → TRIAGE_ERROR", bullet: "•" },
], 26);
replace("sh/r25cj2tw", "15", "8");
setNotes(7, "LLM đưa ra model verdict; PolicyEngine mới tạo system action. Policy không tự động chấp nhận FP khi structured evidence chưa đủ.", ["README.md", "docs/current-project-plan.md"]);

// Slide 9 — Risk scoring
replace("sh/qdgvu1gj", "HƯỚNG PHÁT TRIỂN", "DETERMINISTIC RISK SCORING");
setRich("sh/rypwn6x4", [
  { text: "deterministic-risk-v1", bold: true, size: 35 },
  { text: "Severity", bullet: "•" },
  { text: "Reachability", bullet: "•" },
  { text: "Exposure", bullet: "•" },
  { text: "Data sensitivity", bullet: "•" },
  { text: "Exploitability", bullet: "•" },
  { text: "Áp dụng cho mọi finding", bold: true },
  { text: "Score + level + 5 thành phần", bullet: "•" },
  { text: "Remediation và validation checklist", bullet: "•" },
  { text: "Không sử dụng LLM verdict", bullet: "•" },
], 28);
replace("sh/03id0byl", "19", "9");
setNotes(8, "Risk scoring là deterministic và độc lập với verdict của model. Nó hỗ trợ ưu tiên, không thay thế policy action.", ["docs/sprint-2-status.md", "docs/current-project-plan.md"]);

// Slide 10 — Reporting
replace("sh/5s32d4z6", "XÂY DỰNG BÀI TOÁN", "REPORTING & AUDIT");
setText("sh/4ru1kzil", "Ba báo cáo và run metadata", 37, { bold: true });
setRich("sh/vm107ah4", [
  { text: "1. Reviewer output", bold: true, size: 34 },
  { text: "report.md", bullet: "•" },
  { text: "report.html", bullet: "•" },
  { text: "Evidence path từng bước", bullet: "•" },
  { text: "Risk, remediation, checklist", bullet: "•" },
  { text: "Lý do MANUAL_REVIEW", bullet: "•" },
], 27);
setRich("sh/ulsjep0j", [
  { text: "2. Machine & audit output", bold: true, size: 34 },
  { text: "report.json", bullet: "•" },
  { text: "run-metadata.json", bullet: "•" },
  { text: "Scanner / model / config binding", bullet: "•" },
  { text: "Safe processing error", bullet: "•" },
  { text: "Không raw prompt, response, traceback", bullet: "•" },
], 27);
replace("sh/hoji9kza", "16", "10");
setNotes(9, "Mọi finding đều xuất hiện trong report. Reporter áp dụng leak check và không ghi raw prompt, raw response, traceback hay absolute repository path.", ["README.md", "docs/security-policy.md"]);

// Slide 11 — Verification table
replace("sh/8fadgnq9", "XÂY DỰNG BÀI TOÁN", "VERIFICATION STATUS");
setText("sh/tgjepsru", "Code, Docker và real-provider", 37, { bold: true });
setTable("tb/tgnq1gbe", [
  ["Layer", "Result", "Status"],
  ["Test suite", "459 passed / 2 skipped", "PASS"],
  ["Docker + Joern", "66 / 66 repositories", "PASS"],
  ["DVGA real Qwen", "30 / 30 findings", "PASS"],
]);
replace("sh/zahwjy9s", "17", "11");
setNotes(10, "Kết quả kiểm chứng bao phủ unit/integration test, Docker smoke, Joern trên 66 repository và một demo end-to-end dùng Qwen thật.", ["docs/sprint-2-status.md"]);

// Slide 12 — Focused benchmark
replace("sh/m1kvyl03", "XÂY DỰNG BÀI TOÁN", "FOCUSED DETECTOR BENCHMARK");
setText("sh/72tcrqho", "96 mapped locations — development-fit", 37, { bold: true });
setTable("tb/jqx4zi5k", [
  ["Scope", "TP / TN", "Precision / Recall"],
  ["Total", "65 / 31", "1.000 / 1.000"],
  ["IDOR", "30 / 31", "1.000 / 1.000"],
  ["Business rule", "35 / 0", "1.000 / 1.000"],
]);
replace("sh/lgbup0zi", "17", "12");
setNotes(11, "Đây là deterministic detector benchmark trên các location đã map. Dataset đã được dùng trong tuning và business-rule chưa có negative case được review, nên không phải held-out claim.", ["docs/sprint-2-status.md"]);

// Slide 13 — Limits / next gates
replace("sh/d8j6l8na", "HƯỚNG PHÁT TRIỂN", "TECHNICAL LIMITS & NEXT GATES");
setRich("sh/c7apcn6p", [
  { text: "Giới hạn hiện tại", bold: true, size: 34 },
  { text: "Python-focused; Evidence Engine hiểu Python", bullet: "•" },
  { text: "Sequential processing; không auto-suppress", bullet: "•" },
  { text: "Logic detector bounded; không formal proof", bullet: "•" },
  { text: "Focused benchmark đã được dùng trong tuning", bullet: "•" },
  { text: "1.050 candidate chưa adjudicate", bullet: "•" },
  { text: "Stage gate tiếp theo", bold: true, size: 32 },
  { text: "Freeze held-out dataset mới", bullet: "•" },
  { text: "Hai reviewer và adjudicator", bullet: "•" },
  { text: "Đo coverage, failure rate và calibration", bullet: "•" },
  { text: "AppSec / service-owner review", bullet: "•" },
], 25);
replace("sh/za1oni50", "19", "13");
setNotes(12, "Bước tiếp theo là external acceptance: held-out mới, adjudication độc lập, real-provider evaluation và review trên service thật.", ["docs/sprint-2-status.md", "docs/current-project-plan.md"]);

await fs.mkdir(QA_DIR, { recursive: true });
for (const [index, slide] of p.slides.items.entries()) {
  const stem = `slide-${String(index + 1).padStart(2, "0")}`;
  const png = await p.export({ slide, format: "png", scale: 1 });
  await fs.writeFile(`${QA_DIR}\\${stem}.png`, new Uint8Array(await png.arrayBuffer()));
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(`${QA_DIR}\\${stem}.layout.json`, await layout.text());
}
const montage = await p.export({ format: "webp", montage: true, scale: 1 });
await fs.writeFile(`${QA_DIR}\\montage.webp`, new Uint8Array(await montage.arrayBuffer()));
const inspect = await p.inspect({ kind: "slide,textbox,shape,image,table,notes,layout", maxChars: 30000 });
await fs.writeFile(`${QA_DIR}\\final-inspect.ndjson`, inspect.ndjson);

const exported = await PresentationFile.exportPptx(p);
await exported.save(FINAL);
console.log(`Created ${FINAL}`);
