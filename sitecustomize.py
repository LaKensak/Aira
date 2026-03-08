import importlib, sys
sdist = importlib.import_module('setuptools._distutils')
sys.modules['distutils'] = sdist
sys.modules['distutils.sysconfig'] = sdist.sysconfig