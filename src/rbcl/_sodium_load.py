# Make the new python file
f = open('_sodium.abi3.so', 'rb')
bs = f.read()
f.close()

f = open('sodium.py', 'wb')
f.write(b'bs = bytes.fromhex(\''+bs.hex().encode('ascii')+b'\')\n')

load_str = """
pl = platform.system()
lib_ext = '.dll' if pl == 'Windows' else '.so'
libpath = tempfile.NamedTemporaryFile(suffix=lib_ext).name

f = open(libpath, 'wb')
f.write(bs)

_sodium = importlib.util.module_from_spec(importlib.util.spec_from_file_location("_sodium", libpath))

# lib = _sodium

f.close()
""".encode()

f.write(load_str)
f.close()
