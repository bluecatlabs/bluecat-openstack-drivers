# plugin.sh - DevStack plugin.sh dispatch script bluecat_openstack

function install_bluecat_openstack {
    cd $DIR_BLUECAT
    sudo python setup.py install
    # sudo pip install -r requirements.txt
}


function update_conf_option {
    local file=$1
    local section=$2
    local option=$3
    local value=$4
    local add_mode=$5

    old_val=$(iniget "$file" "$section" "$option")

    found=$(echo -n "$old_val" | sed -n -e "/$value/,/$value/p")
    if [ -z "$found" ]
    then
        if [ "$add_mode" -eq "1" ]
        then
            wc_cnt=`echo -n $old_val | wc -c`
            if [ $wc_cnt -gt 0 ]
            then
                value="${value},${old_val}"
            fi
        fi
        inicomment "$file" "$section" "$option"
        iniadd "$file" "$section" "$option" "$value"
    fi
}

function configure_bluecat_openstack {
    echo_summary "Configuring Neutron/Nova for Bluecat Openstack Driver"


    iniset $NEUTRON_CONF DEFAULT ipam_driver "networking_infoblox.ipam.driver.InfobloxPool"

    NOVA_CONF=/etc/nova/nova.conf
    update_conf_option $NOVA_CONF DEFAULT notification_driver messagingv2 0
    update_conf_option $NOVA_CONF DEFAULT notification_topics notifications 0
    update_conf_option $NOVA_CONF DEFAULT notify_on_state_change vm_state 0
    update_conf_option $NEUTRON_CONF DEFAULT notification_driver messagingv2 0
    update_conf_option $NEUTRON_CONF DEFAULT notification_topics notifications 0

}

DIR_BLUECAT=$DEST/bluecat_openstack

# check for service enabled
if is_service_enabled networking-infoblox; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services for Bluecat OpenStack"
        #install_package cowsay

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing BlueCat OpenStack Drivers"
        install_bluecat_openstack

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring Infoblox Networking"
        configure_bluecat_openstack

    fi

    if [[ "$1" == "unstack" ]]; then
        sudo pip uninstall -q -y bluecatopenstack
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        :
    fi
fi