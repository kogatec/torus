// Renders frames.json (from prepare.py) to PNG frames with AppKit (Menlo + system font fallback).
//   osascript -l JavaScript render.js <frames.json> <outdir>
ObjC.import('AppKit');
ObjC.import('Foundation');
function run(argv) {
  const [jsonPath, outDir] = argv;
  const text = $.NSString.stringWithContentsOfFileEncodingError(jsonPath, $.NSUTF8StringEncoding, null).js;
  const data = JSON.parse(text);
  const W = 1920, H = 1080, PADX = 56, PADY = 70, SIZE = 21, LH = 30;
  const hex = (h) => $.NSColor.colorWithSRGBRedGreenBlueAlpha(parseInt(h.slice(0, 2), 16) / 255, parseInt(h.slice(2, 4), 16) / 255, parseInt(h.slice(4, 6), 16) / 255, 1);
  const palette = { fg: 'cdd6f4', red: 'f38ba8', green: 'a6e3a1', yellow: 'f9e2af', magenta: 'cba6f7', cyan: '89dceb', gray: '7f849c', dim: '6c7086' };
  const colors = {}; for (const k in palette) colors[k] = hex(palette[k]);
  const fonts = { false: $.NSFont.fontWithNameSize('Menlo', SIZE), true: $.NSFont.fontWithNameSize('Menlo-Bold', SIZE) };
  const bg = hex('1e1e2e');
  const attrCache = {};
  const attrsFor = (color, bold) => {
    const key = color + bold;
    if (!attrCache[key]) {
      const a = $.NSMutableDictionary.alloc.init;
      a.setObjectForKey(fonts[bold], $.NSFontAttributeName);
      a.setObjectForKey(colors[color] || colors.fg, $.NSForegroundColorAttributeName);
      attrCache[key] = a;
    }
    return attrCache[key];
  };
  data.frames.forEach((f, idx) => {
    const rep = $.NSBitmapImageRep.alloc.initWithBitmapDataPlanesPixelsWidePixelsHighBitsPerSampleSamplesPerPixelHasAlphaIsPlanarColorSpaceNameBytesPerRowBitsPerPixel(null, W, H, 8, 4, true, false, $.NSDeviceRGBColorSpace, 0, 0);
    const ctx = $.NSGraphicsContext.graphicsContextWithBitmapImageRep(rep);
    $.NSGraphicsContext.saveGraphicsState;
    $.NSGraphicsContext.setCurrentContext(ctx);
    bg.setFill;
    $.NSRectFill($.NSMakeRect(0, 0, W, H));
    const lines = data.segments[f.seg].slice(0, f.n);
    lines.forEach((runs, row) => {
      let x = PADX;
      const y = H - PADY - (row + 1) * LH;
      runs.forEach(([t, color, bold]) => {
        const s = $.NSString.alloc.initWithUTF8String(t);
        const a = attrsFor(color, bold);
        s.drawAtPointWithAttributes($.NSMakePoint(x, y), a);
        x += s.sizeWithAttributes(a).width;
      });
    });
    $.NSGraphicsContext.restoreGraphicsState;
    const png = rep.representationUsingTypeProperties($.NSBitmapImageFileTypePNG, $({}));
    png.writeToFileAtomically(outDir + '/f' + String(idx).padStart(4, '0') + '.png', true);
  });
  return data.frames.length + ' frames';
}
