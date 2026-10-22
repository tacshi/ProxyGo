#!/usr/bin/env python3
"""Copies an Icon Composer document, recolored as a variant of
assets/icon/variants.json, in light and dark alike:

    recolor-icon.py assets/icon/AppIcon.icon out/AppIcon.icon neon
"""
import json
import os
import shutil
import sys

VARIANTS = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "icon", "variants.json")


def color(h):
    return "srgb:" + ",".join(f"{int(h[i:i + 2], 16) / 255:.5f}" for i in (1, 3, 5)) + ",1.00000"


def everywhere(value):
    return [{"value": value}, {"appearance": "dark", "value": value}]


def main():
    src, dst, name = sys.argv[1:]
    with open(VARIANTS) as f:
        variants = json.load(f)
    if name not in variants:
        sys.exit(f"recolor-icon.py: no variant {name} in variants.json")
    v = variants[name]
    shutil.copytree(src, dst)
    path = os.path.join(dst, "icon.json")
    with open(path) as f:
        icon = json.load(f)
    top, bottom = v["background"]
    icon["fill-specializations"] = everywhere({
        "linear-gradient": [color(top), color(bottom)],
        "orientation": {"start": {"x": 0.3, "y": 0}, "stop": {"x": 0.7, "y": 1}},
    })
    for group in icon["groups"]:
        for layer in group["layers"]:
            layer["fill-specializations"] = everywhere({"solid": color(v[layer["name"]])})
    with open(path, "w") as f:
        json.dump(icon, f, indent=2)


if __name__ == "__main__":
    main()
