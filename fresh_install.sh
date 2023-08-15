# script to get dam integration up and 
# running on a fresh VM install. Note this assumes an ubuntu VM.

# install mininet and ryu packages and grab repo
echo "~~~~install faucet~~~~~"
echo "faucet_install"
function faucet_install(){
    sudo apt-get update 
    sudo apt install git
    sudo apt-get install python3-pip
    python3 -m pip install faucet
}

echo "~~~~ dotfiles install ~~~~~"
echo "dot_install"
#you can ignore this. For personal use
function dot_install(){
    git clone https://github.com/cravies/vimrc
    cp ./vimrc/basic.vim ~/.vimrc
    source ~/.bashrc
}

#installing zeek
echo "~~~~~~Install Zeek~~~~~~~"
echo "zeek_install"
function zeek_install(){
    #clean up from previous failed install
    rm -rf zeek
    git clone --recursive https://github.com/zeek/zeek
    cd zeek
    sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
    ./configure
    make
    sudo make install
    cd ..
    echo 'alias zeek="/usr/local/zeek/bin/zeek"' >> ~/.bashrc
    source ~/.bashrc
}

#install zeek broker framework
echo "~~~~~Install Zeek comms framework - Broker~~~~~"
echo "broker_install"
function broker_install(){
    #clean up from previous install
    rm -rf broker
    git clone --recursive https://github.com/zeek/broker
    cd broker
    ./configure
    make
    sudo make install
    cd ..
    #move broker installation to right place
    cp -r /usr/lib/python3/dist-packages/broker /home/$USERNAME/.local/lib/python3.8/site-packages/
}

echo "~~~~~Install 'Dam' and required dependencies~~~~~"
echo "dam_install"
function dam_install(){
    #install openvswitch
    sudo apt update
    sudo apt upgrade
    sudo apt install xterm
    sudo apt install openvswitch-switch
    #install docker
    sudo apt-get install docker.io
    #install dam
    git clone https://github.com/alshaboti/dam
    cd dam 
    #make sure I am in docker group otherwise ill get permission denied
    sudo usermod -aG docker $USERNAME
    newgrp docker
    source setup.sh
}

