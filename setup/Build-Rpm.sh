#!/bin/bash
# Exit when any command fails
set -e

# Ensure that the rpm build tools are installed
yum install -y rpmdevtools rpmlint
rpmdev-setuptree

# Get scriptpath
SCRIPT_RELATIVE_DIR=$(dirname "${BASH_SOURCE[0]}")
cd "${SCRIPT_RELATIVE_DIR}"
SCRIPT_DIR=$(eval "pwd")

# Get the version from the python script
VERSION=$(awk '/PRODUCT_VERSION\:\s+str\s+=\s+/ { print $4 }' "${SCRIPT_DIR}"/../laps-runner.py | tr -d \')
echo "Version: ${VERSION}"

# Generate and fill the source folders
mkdir -p laps4linux-"${VERSION}"/usr/sbin
mkdir -p laps4linux-"${VERSION}"/etc/cron.hourly
cp "${SCRIPT_DIR}"/../laps-runner.py laps4linux-"${VERSION}"/usr/sbin/laps-runner
chmod +x laps4linux-"${VERSION}"/usr/sbin/laps-runner
cp "${SCRIPT_DIR}"/../constants.py laps4linux-"${VERSION}"/usr/sbin/constants
chmod +x laps4linux-"${VERSION}"/usr/sbin/constants
cp "${SCRIPT_DIR}"/../helpers.py laps4linux-"${VERSION}"/usr/sbin/helpers
chmod +x laps4linux-"${VERSION}"/usr/sbin/helpers
cp "${SCRIPT_DIR}"/../configuration.py laps4linux-"${VERSION}"/usr/sbin/configuration
chmod +x laps4linux-"${VERSION}"/usr/sbin/configuration

# Test if we have our own laps-runner config
if [ -f "${SCRIPT_DIR}"/../laps-runner.json ]; then
    cp "${SCRIPT_DIR}"/../laps-runner.json laps4linux-"${VERSION}"/etc
else
    echo 'WARNING: You are using the provided json file, make sure this is intended'
    cp "${SCRIPT_DIR}"/../laps-runner.example.json laps4linux-"${VERSION}"/etc/laps-runner.json
fi
chown 600 "${SCRIPT_DIR}"/../laps-runner.json
echo '#!/bin/sh' >laps4linux-"${VERSION}"/etc/cron.hourly/laps-runner
echo '/usr/sbin/laps-runner --config /etc/laps-runner.json' >>laps4linux-"${VERSION}"/etc/cron.hourly/laps-runner
chmod +x laps4linux-"${VERSION}"/etc/cron.hourly/laps-runner
tar --create --file laps4linux-"${VERSION}".tar.gz laps4linux-"${VERSION}"
if [ ! -f laps4linux-"${VERSION}".tar.gz ]; then
    echo 'Tar file was not detected, exiting'
    exit 1
fi
# Remove out build directory, now that we have our tarball
rm -fr laps4linux-"${VERSION}"
mv laps4linux-"${VERSION}".tar.gz ~/rpmbuild/SOURCES/
cp rpmbuild/SPECS/* ~/rpmbuild/SPECS/
echo 'Building RPM package based on SPECS/laps4linux.spec'

rpmbuild -bb -D 'debug_package %{nil}' ~/rpmbuild/SPECS/laps4linux.spec
