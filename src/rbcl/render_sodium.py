"""
Dynamically render libsodium from .so/.pyd file during GH Actions build
"""
import platform
import pystache

# Determine OS type
pl = platform.system()
LIB_EXT = ".pyd" if pl == "Windows" else ".so"

data = {
    "SODIUM_HEX": open(f"src/rbcl/sodium.{LIB_EXT}", "rb").read().hex()  # pylint: disable=consider-using-with
}
template = open("src/rbcl/_sodium.tmpl", encoding='utf-8').read()  # pylint: disable=consider-using-with

with open("src/rbcl/_sodium.py", "w", encoding='utf-8') as sodium_out:
    sodium_out.write(pystache.render(template, data))
