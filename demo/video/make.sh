#!/usr/bin/env bash
# Builds the narrated demo video (macOS: needs `say`, `osascript`, ffmpeg).
#   1. one real run of the demo on a fresh local validator, captured with colors
#   2. narration audio per segment (intro, scenes 1-6, summary) with macOS text-to-speech
#   3. frames rendered from the captured output with AppKit; each segment stays on screen at least as
#      long as its narration (only the pacing changes; every line comes from the real run)
#   4. ffmpeg: frames + narration → torus-demo.mp4
set -euo pipefail
cd "$(dirname "$0")"
../run.sh --fast > capture.ansi 2>&1
python3 - <<'PY'
import json, subprocess
n = json.load(open('narration.json'))
durs = []
for i, t in enumerate(n['segments']):
    subprocess.run(['say', '-v', n['voice'], '-r', str(n['rate']), '-o', f'seg{i}.aiff', t.replace('Törus', 'Torus')], check=True)
    d = float(subprocess.run(['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', f'seg{i}.aiff'], capture_output=True, text=True).stdout)
    durs.append(int(d * 1000) + 900)
json.dump({'min': durs}, open('min.json', 'w'))
PY
python3 render/prepare.py capture.ansi min.json render/frames.json
rm -rf render/out && mkdir -p render/out
osascript -l JavaScript render/render.js "$PWD/render/frames.json" "$PWD/render/out"
python3 - <<'PY'
import json, subprocess
d = json.load(open('render/frames.json', encoding='utf-8'))
with open('render/list.txt', 'w') as f:
    for i, fr in enumerate(d['frames']):
        f.write(f"file 'out/f{i:04d}.png'\nduration {fr['ms'] / 1000:.3f}\n")
    f.write(f"file 'out/f{len(d['frames']) - 1:04d}.png'\n")
inputs, filt = [], []
for i, start in enumerate(d['starts']):
    inputs += ['-i', f'seg{i}.aiff']
    ms = start + 300
    filt.append(f'[{i + 1}:a]adelay={ms}|{ms},aformat=channel_layouts=stereo[a{i}]')
filt.append(''.join(f'[a{i}]' for i in range(len(d['starts']))) + f'amix=inputs={len(d["starts"])}:normalize=0,apad[aout]')
subprocess.run(['ffmpeg', '-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', 'render/list.txt'] + inputs + [
    '-filter_complex', ';'.join(filt), '-map', '0:v', '-map', '[aout]', '-vf', 'fps=30,format=yuv420p',
    '-c:v', 'libx264', '-preset', 'medium', '-crf', '20', '-c:a', 'aac', '-b:a', '160k',
    '-t', f"{d['end'] / 1000 + 1.0:.2f}", '-movflags', '+faststart', 'torus-demo.mp4'], check=True)
PY
echo "wrote demo/video/torus-demo.mp4"
