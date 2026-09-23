# Audit UI sources

`../src/audit_ui.html` is generated. It is one self-contained file because
`audit.rs` embeds it with `include_str!` and serves it from a single route —
edit these sources and rebuild, never the generated file.

```bash
node tools/premptictl/ui/build.js
```

| File | What |
| --- | --- |
| `shell.html` | the document: head, chrome, trail, detail slot, and the four inline slots the build fills |
| `tokens.css` | design tokens, compiled from the design system's `tokens.json` |
| `page.css` | the page shell: sticky chrome, the two-column split, the empty state |
| `app.js` | page logic only: poll `api/records`, verify the chain, filter, mount components |
| `design-system/bundle.js`·`bundle.css` | the component library, copied verbatim from the design system |

`design-system/` is a copy, not a fork. The upstream is the Kebnetrails design
system artifact — tokens, component guidelines and live previews live there,
and it is where `bundle.js` is edited. To pick up a change, copy the two files
back down and rebuild; do not patch them here.

## Previewing without a server

```bash
node tools/premptictl/ui/build.js --preview   # writes preview.html with a stubbed API
node tools/premptictl/ui/serve.js             # http://127.0.0.1:8731/preview.html
```

`demo.js` holds the stub records — one per verdict, including a denied command
and an LLM error — so the highlighting, the lanes and the detail panel can be
checked without a live audit log. Neither file ships in the binary.

## The build's two guards

It refuses to write if a source that gets inlined into a `<script>` contains a
closing script tag or a comment opener (either would end the element early),
and if any slot was left unfilled.
