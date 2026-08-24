import fs from "node:fs/promises";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const OUT = "D:\\Code\\AI security\\LLM-Augmented-SAST-Tech-Deck.pptx";
const RENDER_DIR = "D:\\Code\\AI security\\.codex-build\\tech-deck-13\\renders";

const W = 1280;
const H = 720;
const FONT = "Times New Roman";
const C = {
  ink: "#172033",
  navy: "#183B63",
  blue: "#2F6FA3",
  muted: "#5F6B7A",
  light: "#E7ECF2",
  pale: "#F5F7FA",
  green: "#2D7A5E",
  amber: "#A56616",
  red: "#9F3A38",
  white: "#FFFFFF",
};

const pres = Presentation.create({ slideSize: { width: W, height: H } });

async function writeBlob(path, blob) {
  await fs.writeFile(path, new Uint8Array(await blob.arrayBuffer()));
}

function addText(slide, text, x, y, w, h, size = 24, options = {}) {
  const shape = slide.shapes.add({
    geometry: "textbox",
    name: options.name,
    position: { left: x, top: y, width: w, height: h },
    fill: options.fill ?? "none",
    line: options.line ?? { style: "solid", fill: "none", width: 0 },
    borderRadius: options.borderRadius,
  });
  shape.text = text;
  shape.text.style = {
    typeface: FONT,
    fontSize: size,
    bold: options.bold ?? false,
    italic: options.italic ?? false,
    color: options.color ?? C.ink,
    alignment: options.align ?? "left",
    verticalAlignment: options.valign ?? "middle",
  };
  return shape;
}

function addLine(slide, x, y, w, color = C.light, width = 2) {
  return slide.shapes.add({
    geometry: "rect",
    position: { left: x, top: y, width: w, height: width },
    fill: color,
    line: { style: "solid", fill: color, width: 0 },
  });
}

function addBox(slide, x, y, w, h, options = {}) {
  return slide.shapes.add({
    geometry: options.geometry ?? "roundRect",
    name: options.name,
    position: { left: x, top: y, width: w, height: h },
    fill: options.fill ?? C.pale,
    line: options.line ?? { style: "solid", fill: C.light, width: 1.5 },
    borderRadius: options.borderRadius ?? 10,
  });
}

function addBulletList(slide, items, x, y, w, rowH = 54, size = 24, color = C.ink) {
  items.forEach((item, i) => {
    addText(slide, "•", x, y + i * rowH, 26, rowH, size + 2, { bold: true, color: C.blue });
    addText(slide, item, x + 34, y + i * rowH, w - 34, rowH, size, { color });
  });
}

function addHeader(slide, number, title, subtitle = "") {
  addText(slide, String(number).padStart(2, "0"), 58, 38, 50, 38, 18, { bold: true, color: C.blue });
  addText(slide, title, 116, 32, 1080, 58, 39, { bold: true, color: C.ink, name: `slide-${number}-title` });
  addLine(slide, 58, 102, 1164, C.light, 2);
  if (subtitle) addText(slide, subtitle, 116, 106, 1040, 36, 18, { color: C.muted });
}

function addFooter(slide, number) {
  addText(slide, String(number).padStart(2, "0"), 1140, 676, 82, 24, 15, {
    color: C.muted,
    align: "right",
    name: `slide-${number}-page-number`,
  });
}

function finish(slide, number, notes, sources) {
  if (number > 1) addFooter(slide, number);
  slide.speakerNotes.textFrame.setText(`${notes}\n\n[Sources]\n${sources.map((s) => `- ${s}`).join("\n")}`);
  slide.speakerNotes.setVisible(true);
}

function baseSlide() {
  const slide = pres.slides.add();
  slide.background.fill = C.white;
  return slide;
}

// 1 — Title
{
  const s = baseSlide();
  addBox(s, 58, 108, 9, 430, { geometry: "rect", fill: C.navy, line: { style: "solid", fill: C.navy, width: 0 }, borderRadius: 0 });
  addText(s, "LLM-Augmented\nSAST Triage", 110, 152, 800, 180, 56, { bold: true, color: C.ink, name: "deck-title" });
  addText(s, "Evidence-driven security finding triage", 112, 350, 720, 48, 27, { color: C.blue });
  addText(s, "Semgrep  •  Gitleaks  •  Joern  •  Qwen3-14B", 112, 414, 720, 40, 22, { color: C.muted });
  addText(s, "TECH DECK  |  CẬP NHẬT 24.08.2026", 112, 548, 600, 30, 17, { bold: true, color: C.muted });
  addText(s, "01", 1140, 676, 82, 24, 15, { color: C.muted, align: "right", name: "slide-1-page-number" });
  finish(s, 1, "Dự án xây dựng một công cụ CLI giúp reviewer phân loại finding từ SAST và secret scanning. LLM chỉ đề xuất; quyết định cuối được kiểm soát bởi policy bảo thủ.", ["README.md", "docs/sprint-2-status.md"]);
}

// 2 — Problem
{
  const s = baseSlide();
  addHeader(s, 2, "Scanner tìm thấy lỗi — nhưng chưa đủ để quyết định");
  const items = [
    ["Nhiều cảnh báo", "Reviewer phải đọc và đối chiếu thủ công."],
    ["Thiếu context", "Flow liên file và business logic khó nhìn thấy."],
    ["Chi phí triage", "Finding quan trọng dễ bị chìm trong nhiễu."],
    ["Rủi ro LLM", "Có thể sai, bị prompt injection hoặc làm lộ dữ liệu."],
  ];
  items.forEach((item, i) => {
    const y = 156 + i * 118;
    addText(s, String(i + 1), 74, y, 54, 54, 28, { bold: true, color: C.white, align: "center", fill: C.navy, borderRadius: 27 });
    addText(s, item[0], 154, y - 2, 300, 42, 28, { bold: true, color: C.ink });
    addText(s, item[1], 465, y - 2, 700, 48, 23, { color: C.muted });
  });
  finish(s, 2, "Semgrep và Gitleaks phát hiện tốt các pattern, nhưng chưa đủ context để xác định lỗi thật. Đưa source trực tiếp cho LLM còn tạo thêm rủi ro bảo mật.", ["README.md", "docs/current-project-plan.md"]);
}

// 3 — Goal
{
  const s = baseSlide();
  addHeader(s, 3, "Mục tiêu: biến finding thành quyết định có evidence");
  addText(s, "Một pipeline duy nhất", 58, 154, 1164, 54, 31, { bold: true, color: C.navy, align: "center" });
  const steps = ["Chuẩn hóa", "Làm sạch", "Bổ sung evidence", "Triage", "Báo cáo"];
  steps.forEach((label, i) => {
    const x = 72 + i * 236;
    addText(s, String(i + 1), x + 72, 246, 58, 58, 28, { bold: true, color: C.white, align: "center", fill: i === 4 ? C.green : C.blue, borderRadius: 29 });
    addText(s, label, x, 326, 202, 58, 24, { bold: true, color: C.ink, align: "center" });
  });
  addText(s, "Không thay thế reviewer — ưu tiên finding và giữ toàn bộ dấu vết audit.", 142, 468, 996, 80, 27, { italic: true, color: C.muted, align: "center", fill: C.pale, borderRadius: 12 });
  finish(s, 3, "Mục tiêu không phải thay thế reviewer, mà là bổ sung evidence, chuẩn hóa quyết định và giúp ưu tiên finding quan trọng.", ["README.md", "docs/current-project-plan.md"]);
}

// 4 — Scope
{
  const s = baseSlide();
  addHeader(s, 4, "Sprint 2 tập trung vào logic bug có giá trị cao");
  addText(s, "TRONG PHẠM VI", 76, 158, 500, 34, 20, { bold: true, color: C.green });
  addBulletList(s, ["Repository Python", "Semgrep và Gitleaks", "IDOR / missing authorization", "Business-rule bypass"], 80, 210, 500, 64, 25);
  addLine(s, 638, 158, 0, C.light, 1);
  s.shapes.add({ geometry: "line", position: { left: 638, top: 160, width: 0, height: 410 }, fill: "none", line: { style: "solid", fill: C.light, width: 2 } });
  addText(s, "CHỦ ĐÍCH CHƯA LÀM", 700, 158, 480, 34, 20, { bold: true, color: C.red });
  addBulletList(s, ["Không auto-suppress finding", "Không tự động sửa code", "Không chứng minh khai thác", "Chưa claim chất lượng tổng quát"], 704, 210, 470, 64, 25);
  finish(s, 4, "Phạm vi hiện tại ưu tiên hai lớp logic bug: IDOR hoặc thiếu authorization, và business-rule bypass như giá, số lượng hoặc pagination không được kiểm soát.", ["docs/sprint-2-scope.md", "docs/current-project-plan.md"]);
}

// 5 — Architecture
{
  const s = baseSlide();
  addHeader(s, 5, "Một pipeline nối scanner, evidence, LLM và policy");
  const labels = ["Repository", "Semgrep\nGitleaks", "Normalize", "Safe Context", "Joern\nEvidence", "LLM + Policy", "Reports"];
  const xs = labels.map((_, i) => 48 + i * 176);
  for (let i = 0; i < labels.length - 1; i++) {
    s.shapes.add({
      geometry: "rightArrow",
      position: { left: xs[i] + 142, top: 315, width: 50, height: 34 },
      fill: C.light,
      line: { style: "solid", fill: C.light, width: 0 },
    });
  }
  labels.forEach((label, i) => {
    const fill = i === 0 ? C.pale : i === 6 ? "#EAF4EF" : C.white;
    const lineColor = i === 6 ? "#A9D2BE" : C.light;
    addText(s, label, xs[i], 268, 148, 128, i === 3 || i === 5 ? 20 : 22, {
      bold: true,
      color: i === 6 ? C.green : C.ink,
      align: "center",
      fill,
      line: { style: "solid", fill: lineColor, width: 2 },
      borderRadius: 12,
    });
  });
  addText(s, "Module 2 và Joern bổ sung evidence — không tạo pipeline cạnh tranh.", 148, 480, 984, 70, 25, { color: C.muted, align: "center" });
  finish(s, 5, "Toàn bộ finding đi qua một pipeline duy nhất. Module 2 và Joern chỉ bổ sung evidence trước khi finding đi qua cùng provider và policy.", ["README.md", "docs/architecture.md"]);
}

// 6 — Domain boundaries
{
  const s = baseSlide();
  addHeader(s, 6, "Sáu domain model giữ ranh giới dữ liệu rõ ràng");
  const models = ["Normalized\nFinding", "Sanitized\nContext", "Triage\nInput", "Triage\nDecision", "Policy\nDecision", "Triage\nResult"];
  models.forEach((label, i) => {
    const x = 64 + (i % 3) * 402;
    const y = 174 + Math.floor(i / 3) * 190;
    addText(s, String(i + 1), x, y, 46, 46, 22, { bold: true, color: C.white, align: "center", fill: C.navy, borderRadius: 23 });
    addText(s, label, x + 66, y - 8, 290, 74, 27, { bold: true, color: C.ink });
    addLine(s, x + 66, y + 74, 286, C.light, 1);
  });
  addText(s, "Raw source không nằm trong public model. Provider chỉ nhận TriageInput đã sanitize.", 140, 566, 1000, 62, 25, { bold: true, color: C.navy, align: "center", fill: C.pale, borderRadius: 10 });
  finish(s, 6, "Hệ thống tách rõ sáu domain model bất biến. Raw source không được nằm trong public model và provider chỉ nhận TriageInput đã làm sạch.", ["docs/domain-models.md", "docs/architecture.md"]);
}

// 7 — Evidence
{
  const s = baseSlide();
  addHeader(s, 7, "Evidence Engine trả lời: dữ liệu đi từ đâu đến đâu?");
  const rows = [
    ["SOURCE", "User input / request parameter", C.blue],
    ["GUARD", "Authorization, ownership, tenant, ACL", C.green],
    ["SINK", "File, command, query hoặc object access", C.red],
  ];
  rows.forEach((r, i) => {
    const y = 166 + i * 112;
    addText(s, r[0], 72, y, 160, 64, 22, { bold: true, color: C.white, align: "center", fill: r[2], borderRadius: 8 });
    addText(s, r[1], 262, y, 660, 64, 25, { color: C.ink });
  });
  addBox(s, 960, 166, 250, 288, { fill: C.pale, line: { style: "solid", fill: C.light, width: 1.5 } });
  addText(s, "Phân tích", 990, 194, 190, 34, 25, { bold: true, color: C.navy, align: "center" });
  addBulletList(s, ["Python AST", "Symbol index", "Same-file", "Cross-file", "Joern CPG"], 988, 244, 190, 42, 20);
  addText(s, "Counter-evidence giúp tránh gắn nhãn IDOR khi đã có guard phù hợp.", 150, 514, 980, 72, 25, { color: C.muted, align: "center", italic: true });
  finish(s, 7, "Evidence Engine kết hợp AST và Joern CPG để xác định source, guard và sink. Counter-evidence giúp tránh gắn nhãn IDOR khi đã có kiểm tra phù hợp.", ["README.md", "docs/joern-analysis.md", "docs/sprint-2-status.md"]);
}

// 8 — Logic bugs
{
  const s = baseSlide();
  addHeader(s, 8, "Detector ưu tiên bốn pattern business logic");
  const patterns = [
    ["01", "IDOR", "Truy cập tài liệu khác chủ sở hữu"],
    ["02", "Giá trị tiền", "Price hoặc total do client kiểm soát"],
    ["03", "Số lượng", "Quantity không có bound hợp lệ"],
    ["04", "Tài nguyên", "Pagination hoặc collection thiếu giới hạn"],
  ];
  patterns.forEach((p, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = 74 + col * 590;
    const y = 164 + row * 198;
    addText(s, p[0], x, y, 76, 64, 25, { bold: true, color: C.blue, align: "center" });
    addText(s, p[1], x + 94, y - 2, 430, 42, 28, { bold: true, color: C.ink });
    addText(s, p[2], x + 94, y + 48, 430, 64, 22, { color: C.muted });
    addLine(s, x + 94, y + 130, 430, C.light, 1);
  });
  addText(s, "Candidate engine có giới hạn — remediation vẫn cần developer review.", 158, 570, 964, 48, 23, { italic: true, color: C.muted, align: "center" });
  finish(s, 8, "Detector hiện là bounded candidate engine, tập trung vào một số pattern giá trị cao. Nó tạo evidence và remediation nhưng không phải bằng chứng khai thác hoàn chỉnh.", ["docs/sprint-2-scope.md", "docs/current-project-plan.md"]);
}

// 9 — Security
{
  const s = baseSlide();
  addHeader(s, 9, "Security by design: dữ liệu nhạy cảm không vượt boundary");
  addText(s, "TRUST BOUNDARY", 74, 166, 252, 54, 21, { bold: true, color: C.white, align: "center", fill: C.navy, borderRadius: 8 });
  addText(s, "SafeContextService", 74, 240, 252, 104, 27, { bold: true, color: C.navy, align: "center", fill: C.pale, line: { style: "solid", fill: C.light, width: 2 }, borderRadius: 10 });
  addText(s, "Raw source chỉ tồn tại cục bộ", 74, 365, 252, 68, 20, { color: C.muted, align: "center" });
  addBulletList(s, ["Redact secret ngay tại parser", "Chặn traversal và symlink escape", "Coi source là untrusted data", "Validate mọi output của LLM", "Không lưu prompt, response, traceback"], 404, 164, 770, 76, 24);
  addText(s, "Defense in depth: parser → sanitizer → provider boundary → reporter leak check", 180, 566, 920, 58, 23, { bold: true, color: C.green, align: "center" });
  finish(s, 9, "Secret từ Gitleaks được redact sớm, context được sanitize lại và reporter kiểm tra rò rỉ thêm một lần trước khi ghi file.", ["docs/security-policy.md", "docs/threat-model.md"]);
}

// 10 — Policy
{
  const s = baseSlide();
  addHeader(s, 10, "LLM đề xuất; policy mới quyết định hành động");
  const bx = [82, 448, 814];
  const labels = [
    ["LLM VERDICT", "LIKELY_TP\nLIKELY_FP\nNEEDS_REVIEW"],
    ["POLICY ENGINE", "Evidence\nConfidence\nSafety conditions"],
    ["SYSTEM ACTION", "AUTO_ACCEPT\nMANUAL_REVIEW\nTRIAGE_ERROR"],
  ];
  for (let i = 0; i < 2; i++) {
    s.shapes.add({ geometry: "rightArrow", position: { left: bx[i] + 300, top: 290, width: 72, height: 40 }, fill: C.light, line: { style: "solid", fill: C.light, width: 0 } });
  }
  labels.forEach((p, i) => {
    addText(s, p[0], bx[i], 186, 300, 48, 20, { bold: true, color: i === 1 ? C.white : C.blue, align: "center", fill: i === 1 ? C.navy : C.pale, borderRadius: 8 });
    addText(s, p[1], bx[i], 246, 300, 176, 24, { bold: i === 1, color: C.ink, align: "center", fill: C.white, line: { style: "solid", fill: C.light, width: 1.5 }, borderRadius: 10 });
  });
  addText(s, "Risk score chạy song song và hoàn toàn deterministic — không dùng verdict của LLM.", 146, 490, 988, 76, 25, { color: C.muted, align: "center", fill: C.pale, borderRadius: 10 });
  finish(s, 10, "LLM trả về nhận định; policy mới quyết định hành động cuối. Risk score không phụ thuộc verdict của LLM.", ["README.md", "docs/current-project-plan.md", "docs/sprint-2-status.md"]);
}

// 11 — Outputs
{
  const s = baseSlide();
  addHeader(s, 11, "Mọi finding đều được giữ lại và có thể audit");
  const outputs = [
    ["JSON", "Dữ liệu đầy đủ\ncho xử lý tự động"],
    ["MARKDOWN", "Báo cáo chính\ncho reviewer"],
    ["HTML", "Báo cáo trực quan\nđộc lập"],
    ["METADATA", "Version, config,\ntiming và binding"],
  ];
  outputs.forEach((o, i) => {
    const x = 62 + i * 300;
    addText(s, o[0], x, 190, 254, 58, 22, { bold: true, color: C.white, align: "center", fill: i === 3 ? C.green : C.navy, borderRadius: 8 });
    addText(s, o[1], x, 264, 254, 142, 24, { color: C.ink, align: "center", fill: C.pale, borderRadius: 10 });
  });
  addText(s, "Context thiếu → MANUAL_REVIEW    |    Provider lỗi → TRIAGE_ERROR", 130, 500, 1020, 64, 26, { bold: true, color: C.navy, align: "center" });
  addText(s, "Không finding nào bị mất khỏi báo cáo.", 276, 572, 728, 42, 23, { italic: true, color: C.muted, align: "center" });
  finish(s, 11, "Mỗi finding đều xuất hiện trong báo cáo. Khi context hoặc provider gặp lỗi, finding được chuyển sang MANUAL_REVIEW hoặc TRIAGE_ERROR.", ["README.md", "docs/architecture.md", "docs/security-policy.md"]);
}

// 12 — Verification
{
  const s = baseSlide();
  addHeader(s, 12, "Pipeline đã được kiểm chứng từ unit test đến real LLM");
  const metrics = [
    ["459", "tests passed"],
    ["66/66", "repository với Docker + Joern"],
    ["30/30", "finding được Qwen triage"],
    ["28", "evidence card hoàn chỉnh"],
  ];
  metrics.forEach((m, i) => {
    const x = 70 + i * 296;
    addText(s, m[0], x, 180, 254, 104, 49, { bold: true, color: i === 3 ? C.green : C.navy, align: "center" });
    addText(s, m[1], x, 286, 254, 66, 21, { color: C.muted, align: "center" });
  });
  addLine(s, 72, 390, 1136, C.light, 2);
  addText(s, "DVGA end-to-end", 76, 430, 290, 44, 28, { bold: true, color: C.ink });
  addText(s, "Semgrep, Gitleaks, Module 2, Joern 4.0.600 và Qwen3-14B-AWQ đều hoàn tất; không có lỗi scanner, schema hoặc provider.", 382, 414, 810, 110, 23, { color: C.muted });
  addText(s, "Ruff: tất cả check đạt  •  Docker smoke: passed", 76, 570, 1116, 38, 21, { bold: true, color: C.green, align: "center" });
  finish(s, 12, "Hệ thống đã được kiểm chứng từ unit test đến Docker smoke và real-provider demo. Trên DVGA, toàn pipeline chạy hoàn chỉnh, không có lỗi schema hoặc provider.", ["docs/sprint-2-status.md"]);
}

// 13 — Benchmark
{
  const s = baseSlide();
  addHeader(s, 13, "Benchmark cho thấy tiềm năng — chưa phải claim tổng quát");
  addText(s, "96", 72, 166, 250, 110, 58, { bold: true, color: C.navy, align: "center" });
  addText(s, "location đã map", 72, 276, 250, 44, 22, { color: C.muted, align: "center" });
  addText(s, "65", 364, 166, 220, 110, 58, { bold: true, color: C.green, align: "center" });
  addText(s, "true positive", 364, 276, 220, 44, 22, { color: C.muted, align: "center" });
  addText(s, "31", 626, 166, 220, 110, 58, { bold: true, color: C.blue, align: "center" });
  addText(s, "true negative", 626, 276, 220, 44, 22, { color: C.muted, align: "center" });
  addText(s, "0", 888, 166, 300, 110, 58, { bold: true, color: C.red, align: "center" });
  addText(s, "FP / FN trong tập đã map", 888, 276, 300, 44, 22, { color: C.muted, align: "center" });
  addLine(s, 72, 366, 1136, C.light, 2);
  addText(s, "DEVELOPMENT-FIT", 78, 410, 280, 46, 21, { bold: true, color: C.white, align: "center", fill: C.amber, borderRadius: 8 });
  addText(s, "Dataset đã được dùng trong quá trình tuning; business-rule chưa có negative case được review đầy đủ.", 390, 398, 790, 82, 23, { color: C.ink });
  addText(s, "Bước kế tiếp: đóng băng held-out dataset và thực hiện adjudication độc lập.", 126, 540, 1028, 64, 26, { bold: true, color: C.navy, align: "center", fill: C.pale, borderRadius: 10 });
  finish(s, 13, "Focused benchmark đạt kết quả tuyệt đối trên 96 location đã map. Tuy nhiên đây là development-fit, chưa thể dùng để khẳng định chất lượng tổng quát.", ["docs/sprint-2-status.md"]);
}

await fs.mkdir(RENDER_DIR, { recursive: true });
for (const [i, slide] of pres.slides.items.entries()) {
  const stem = `slide-${String(i + 1).padStart(2, "0")}`;
  await writeBlob(`${RENDER_DIR}\\${stem}.png`, await pres.export({ slide, format: "png", scale: 1 }));
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(`${RENDER_DIR}\\${stem}.layout.json`, await layout.text());
}
await writeBlob(`${RENDER_DIR}\\montage.webp`, await pres.export({ format: "webp", montage: true, scale: 1 }));
const pptx = await PresentationFile.exportPptx(pres);
await pptx.save(OUT);
console.log(`Created ${OUT}`);
