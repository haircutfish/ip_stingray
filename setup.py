from setuptools import setup, find_packages

setup(
    name='ip_stingray',
    version='1.0.0',
    description='A python script for checking the reputation of an IP address\'s ASN.',
    author='HaircutFish aka Daniel Rearden',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'requests>=2.0.0',
        'colorama>=0.4.6',
    ],
    entry_points={
        'console_scripts': [
            'ip_stingray=ip_stingray.cli:main',
        ],
    },
    python_requires='>=3.6',
)
