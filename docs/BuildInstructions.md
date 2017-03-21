Requirements for building of cassiopeia
=================

Operation System Debian 9.0 (Stretch)

Install the following packages:

    apt-get install wget curl debhelper fakeroot build-essential libboost-test-dev libtool-bin libpqxx-dev libasan3

Clone the repository:

    git clone https://code.wpia.club/cassiopeia.git

Generate the changelog file for the Debian packages:
    
    cassiopeia/scripts/genchangelog.sh

Compile the source code and build the Debian packages:

    cd cassiopeia && dpkg-buildpackage -b -us -uc
