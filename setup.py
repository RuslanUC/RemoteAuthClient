from setuptools import setup
from os.path import join, dirname

requirements = [
    "cryptography>=3.4.7",
    "websockets>=10.1",
    "aiohttp>=3.8.1"
]

setup(
    name='remoteauthclient',
    version='1.4.0b2',
    packages=["remoteauthclient"],
    long_description=open(join(dirname(__file__), 'README.md')).read(),
    long_description_content_type="text/markdown",
    description='Client for Discord authorization via qr code',
    url='https://github.com/RuslanUC/RemoteAuthClient',
    repository='https://github.com/RuslanUC/RemoteAuthClient',
    author='RuslanUC',
    install_requires=requirements,
    python_requires='>=3.7',
    license='MIT',
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
      ]
)
