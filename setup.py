from setuptools import setup
setup(name='computer_sec_project1',
      version='1.0',
      description='A set of programs for Project 1',
      url='https://helixteamhub.cloud/msu/projects/computer_security_project_1/repositories/computer_security_project_1/tree/master',
      author='Brian HVB',
      author_email='brian@grimecho.com',
      license='MIT',
      packages=['computer_sec_project1'],
      install_requires=[
        'pycrypto'
      ],
      zip_safe=False)