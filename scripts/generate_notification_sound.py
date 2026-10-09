"""Reproduce SevenMirror's original bright two-note notification cue.
No third-party samples or transcribed melody are used.
"""
from pathlib import Path
import array
import math
import wave

RATE = 48000
DURATION = .70
NOTES = [(392.0 * 2 ** (1 / 12), 0.0, .40, 1.0),
         (493.8833 * 2 ** (1 / 12), .23, .47, .85)]
HARMONICS = (1.0, .15, .035)
DECAY = 5.3
OUTPUT = Path(__file__).resolve().parents[1] / 'public/sounds/notification.wav'

values = []
for i in range(round(DURATION * RATE)):
    t = i / RATE
    value = 0.0
    for frequency, start, length, gain in NOTES:
        age = t - start
        if not 0 <= age < length:
            continue
        attack = min(1.0, age / .016)
        release = min(1.0, (length - age) / .090)
        envelope = math.sin(attack * math.pi / 2) ** 2 * release ** 2 * math.exp(-DECAY * age)
        tone = sum(weight * math.exp(-(partial - 1) * 5 * age) * math.sin(2 * math.pi * partial * frequency * age)
                   for partial, weight in enumerate(HARMONICS, 1))
        value += gain * envelope * tone
    values.append(value)
scale = .55 / max(abs(v) for v in values)
pcm = array.array('h', (round(v * scale * 32767) for v in values))
pcm[0] = pcm[-1] = 0
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with wave.open(str(OUTPUT), 'wb') as output:
    output.setnchannels(1)
    output.setsampwidth(2)
    output.setframerate(RATE)
    output.writeframes(pcm.tobytes())
