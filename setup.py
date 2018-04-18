import setuptools

try:
	import multiprocessing
except ImportError:
	pass

setuptools.setup(
	setup_requires=['pbr'],
	pbr=True)
