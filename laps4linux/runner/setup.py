import setuptools

setuptools.setup(
    name="laps4linux",
    version="1.5.4",
    author="Zafer Balkan",
    description="laps4linux - auto-rotate the root password for AD bound (samba net, pbis, adcli) linux servers",
    packages=["runner", "shared"],
    package_dir={"": ".."},
    license="GPL-3.0",
    url="https://github.com/zbalkan/LAPS4LINUX",
    python_requires='>=3'
)
