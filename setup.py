from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='pi_serial_server',
      version='1.0',
      description='A serial port server for Raspberry Pi',
      long_description=readme(),
      classifiers=[
        'Programming Language :: Python :: 2.7',
      ],
      keywords='serial port server raspberry pi',
      url='http://github.com/gbrucepayne/pi_serial_server',
      author='Geoff Bruce-Payne',
      author_email='gbrucepayne@hotmail.com',
      license='MIT',
      packages=['pi_serial_server'],
      install_requires=['pyserial>=3'],
      include_package_data=True,
      zip_safe=False)
