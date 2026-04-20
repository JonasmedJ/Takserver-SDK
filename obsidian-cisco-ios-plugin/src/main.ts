import { Plugin, MarkdownPostProcessorContext, editorLivePreviewField } from "obsidian";
import { ViewPlugin, DecorationSet, EditorView, ViewUpdate, Decoration } from "@codemirror/view";
import { RangeSetBuilder } from "@codemirror/state";
import { tokenizeCiscoLine } from "./ciscoHighlighter";

function renderCiscoBlock(
  source: string,
  el: HTMLElement,
  _ctx: MarkdownPostProcessorContext
): void {
  el.empty();
  const pre = el.createEl("pre", { cls: "cisco-ios-block" });
  const code = pre.createEl("code", { cls: "language-ios" });

  const lines = source.split("\n");
  lines.forEach((line, lineIndex) => {
    if (lineIndex > 0) code.createEl("br");
    const tokens = tokenizeCiscoLine(line);
    if (tokens.length === 0) {
      code.appendText(line);
      return;
    }
    let pos = 0;
    for (const token of tokens) {
      if (token.start > pos) {
        code.appendText(line.slice(pos, token.start));
      }
      const span = code.createEl("span", { cls: token.cssClass });
      span.appendText(line.slice(token.start, token.end));
      pos = token.end;
    }
    if (pos < line.length) {
      code.appendText(line.slice(pos));
    }
  });
}

const FENCE_OPEN_RE = /^```\s*(ios|cisco|cisco-ios)\s*$/i;
const FENCE_CLOSE_RE = /^```\s*$/;

class CiscoHighlighterPlugin {
  decorations: DecorationSet;

  constructor(view: EditorView) {
    this.decorations = this.buildDecorations(view);
  }

  update(update: ViewUpdate) {
    if (update.docChanged || update.viewportChanged) {
      this.decorations = this.buildDecorations(update.view);
    }
  }

  buildDecorations(view: EditorView): DecorationSet {
    // Only apply in Live Preview mode
    if (!view.state.field(editorLivePreviewField)) {
      return Decoration.none;
    }

    const builder = new RangeSetBuilder<Decoration>();
    const doc = view.state.doc;

    for (const { from, to } of view.visibleRanges) {
      // Look back up to 50 lines to catch a fence that opened above the viewport
      const startLine = Math.max(1, doc.lineAt(from).number - 50);
      const endLine = doc.lineAt(to).number;

      let inBlock = false;

      for (let i = startLine; i <= endLine; i++) {
        const line = doc.line(i);
        const text = line.text.trim();

        if (!inBlock) {
          if (FENCE_OPEN_RE.test(text)) {
            inBlock = true;
          }
          continue;
        }

        if (FENCE_CLOSE_RE.test(text)) {
          inBlock = false;
          continue;
        }

        // Only emit decorations for lines within the visible range
        if (line.from > to) break;
        if (line.to < from) continue;

        const tokens = tokenizeCiscoLine(line.text);
        for (const token of tokens) {
          if (token.start === token.end) continue;
          builder.add(
            line.from + token.start,
            line.from + token.end,
            Decoration.mark({ class: token.cssClass })
          );
        }
      }
    }

    return builder.finish();
  }
}

const ciscoViewPlugin = ViewPlugin.fromClass(CiscoHighlighterPlugin, {
  decorations: (v) => v.decorations,
});

export default class CiscoIosPlugin extends Plugin {
  async onload() {
    this.registerMarkdownCodeBlockProcessor("ios", renderCiscoBlock);
    this.registerMarkdownCodeBlockProcessor("cisco", renderCiscoBlock);
    this.registerMarkdownCodeBlockProcessor("cisco-ios", renderCiscoBlock);
    this.registerEditorExtension(ciscoViewPlugin);
  }
}
