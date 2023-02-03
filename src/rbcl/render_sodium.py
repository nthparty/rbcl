"""
Dynamically render libsodium from .so/.pyd file during GH Actions build
"""
import pystache

data = {
    "SODIUM_HEX": open("src/rbcl/sodium.so", "rb").read().hex()  # pylint: disable=consider-using-with
}
template = open("src/rbcl/_sodium.tmpl", encoding='utf-8').read()  # pylint: disable=consider-using-with

with open("src/rbcl/_sodium.py", "w", encoding='utf-8') as sodium_out:
    sodium_out.write(pystache.render(template, data))
