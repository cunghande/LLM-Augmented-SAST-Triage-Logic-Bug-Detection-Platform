from pathlib import Path

import pymupdf


source = Path(__file__).parent / "render-word" / "SAST_Triage_Tech_Doc_Sprint_1_2.pdf"
output = source.parent / "pages"
output.mkdir(parents=True, exist_ok=True)
document = pymupdf.open(source)
matrix = pymupdf.Matrix(144 / 72, 144 / 72)
for index, page in enumerate(document, start=1):
    pixmap = page.get_pixmap(matrix=matrix, alpha=False)
    pixmap.save(output / f"page-{index}.png")
print(f"pages={document.page_count}")
