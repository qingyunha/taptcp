from distutils.core import setup, Extension

module1 = Extension('tun',
                    sources = ['tunmodule.c'])

setup (name = 'tun',
       version = '1.0',
       description = 'This is a demo package',
       ext_modules = [module1])
