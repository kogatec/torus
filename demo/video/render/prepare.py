"""Turns a captured demo run (ANSI) into frames.json for render.js: segments (intro, scenes, summary), styled
runs per line, and a timeline where each segment lasts at least as long as its narration."""
import json, re, sys
cap, minp, out = sys.argv[1], sys.argv[2], sys.argv[3]
MIN = json.load(open(minp))['min']
raw = open(cap, encoding='utf-8').read().replace('\r', '').split('\n')
strip = lambda s: re.sub(r'\x1b\[[0-9;]*m', '', s)
while raw and strip(raw[-1]).strip() == '': raw.pop()

COLORS = {'31': 'red', '32': 'green', '33': 'yellow', '35': 'magenta', '36': 'cyan', '90': 'gray'}
def runs(line):
    out, color, bold, dim, pos = [], None, False, False, 0
    for m in re.finditer(r'\x1b\[([0-9;]*)m', line):
        if m.start() > pos: out.append([line[pos:m.start()], color or ('dim' if dim else 'fg'), bold])
        for code in (m.group(1) or '0').split(';'):
            if code in ('0', ''): color, bold, dim = None, False, False
            elif code == '1': bold = True
            elif code == '2': dim = True
            elif code in COLORS: color = COLORS[code]
        pos = m.end()
    if pos < len(line): out.append([line[pos:], color or ('dim' if dim else 'fg'), bold])
    return [r for r in out if r[0]]

segments = [[]]
for i, l in enumerate(raw):
    p = strip(l)
    if 'Setting up accounts' in p: continue
    if p.strip() == '' and i + 2 < len(raw) and re.fullmatch(r'━+', strip(raw[i+1]).strip() or 'x') and re.search(r'SCENE \d|SUMMARY', strip(raw[i+2])):
        segments.append([])
        continue  # the blank line before a banner is dropped: each segment starts on a clean screen
    segments[-1].append(l)

def delay(l):
    p = strip(l)
    if p.strip() == '': return 80
    if re.fullmatch(r'━+', p.strip()): return 60
    if re.search(r'SCENE \d|SUMMARY', p): return 120
    if 'BLOCKED' in p: return 1100
    if '⚡' in p: return 1300
    if re.match(r'^\s+#\d', p): return 140
    if re.match(r'^\s+→', p): return 450
    return 380

frames, starts, t = [], [], 0
for s, seg in enumerate(segments):
    starts.append(t); seg_t = 0
    for k, l in enumerate(seg):
        d = delay(l)
        frames.append({'seg': s, 'n': k + 1, 'ms': d}); seg_t += d
    hold = MIN[s] - seg_t if s < len(MIN) else 0
    if hold > 0: frames[-1]['ms'] += hold; seg_t += hold
    t += seg_t
json.dump({'segments': [[runs(l) for l in seg] for seg in segments], 'frames': frames, 'starts': starts, 'end': t}, open(out, 'w', encoding='utf-8'), ensure_ascii=False)
print('segments', len(segments), 'frames', len(frames), 'max lines', max(len(s) for s in segments), 'total s', t / 1000)
