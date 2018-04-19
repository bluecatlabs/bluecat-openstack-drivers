# Configure bluecatopenstack under Devstack

function install_bluecat_openstack {
    cd $DIR_BLUECAT
    sudo python setup.py install
    sudo pip install -r requirements.txt
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
    echo_summary "Configuring Neutron/Nova.conf for Bluecat Openstack Driver"

    iniset $NEUTRON_CONF DEFAULT ipam_driver "bluecatopenstack"

    # Set parameters in nova.conf
    NOVA_CONF=/etc/nova/nova.conf
    update_conf_option $NOVA_CONF DEFAULT notification_driver messagingv2 0
    update_conf_option $NOVA_CONF DEFAULT notification_topics notifications 0
    update_conf_option $NOVA_CONF DEFAULT notify_on_state_change vm_state 0
    update_conf_option $NOVA_CONF DEFAULT use_syslog True 0

    # Set parameters in Neutron.conf
    update_conf_option $NEUTRON_CONF DEFAULT notification_driver messagingv2 0
    update_conf_option $NEUTRON_CONF DEFAULT notification_topics notifications 0
    update_conf_option $NEUTRON_CONF DEFAULT notify_nova_on_port_status_changes true 0
    update_conf_option $NEUTRON_CONF DEFAULT notify_nova_on_port_data_changes true 0
    update_conf_option $NEUTRON_CONF DEFAULT control_exchange neutron 0

    # Set bluecat parameters in Neutron.conf

    iniset $NEUTRON_CONF bluecat bam_address $bam_address
    iniset $NEUTRON_CONF bluecat bam_api_user $bam_api_user
    iniset $NEUTRON_CONF bluecat bam_api_pass $bam_api_pass
    iniset $NEUTRON_CONF bluecat bam_config_name $bam_config_name
    iniset $NEUTRON_CONF bluecat bam_ipv4_public_block $bam_ipv4_public_block
    iniset $NEUTRON_CONF bluecat bam_ipv4_private_block $bam_ipv4_private_block
    iniset $NEUTRON_CONF bluecat bam_ipv4_private_network $bam_ipv4_private_network
    iniset $NEUTRON_CONF bluecat bam_ipv4_private_iprange_startip $bam_ipv4_private_iprange_startip
    iniset $NEUTRON_CONF bluecat bam_ipv4_private_iprange_endip $bam_ipv4_private_iprange_endip
    iniset $NEUTRON_CONF bluecat bam_ipv4_private_iprange_gw $bam_ipv4_private_iprange_gw
    iniset $NEUTRON_CONF bluecat bam_ipv6_public_block $bam_ipv6_public_block
    iniset $NEUTRON_CONF bluecat bam_ipv6_private_block $bam_ipv6_private_block
    iniset $NEUTRON_CONF bluecat bam_dns_zone $bam_dns_zone
    iniset $NEUTRON_CONF bluecat bam_updatemodify_networks $bam_updatemodify_networks
    iniset $NEUTRON_CONF bluecat bcn_neutron_transport_url $bcn_neutron_transport_url
    iniset $NEUTRON_CONF bluecat bcn_neutron_nameserver $bcn_neutron_nameserver
    iniset $NEUTRON_CONF bluecat bcn_neutron_logfile $bcn_neutron_logfile
    iniset $NEUTRON_CONF bluecat bcn_neutron_ttl $bcn_neutron_ttl
    iniset $NEUTRON_CONF bluecat bcn_neutron_domain_override $bcn_neutron_domain_override
    iniset $NEUTRON_CONF bluecat bcn_neutron_debuglevel $bcn_neutron_debuglevel
    iniset $NEUTRON_CONF bluecat bcn_neutron_replace $bcn_neutron_replace
    iniset $NOVA_CONF bluecat bcn_nova_TSIG $bcn_nova_TSIG

     # Set bluecat parameters in nova.conf
    iniset $NOVA_CONF bluecat bcn_nova_transport_url $bcn_nova_transport_url
    iniset $NOVA_CONF bluecat bcn_nova_nameserver $bcn_nova_nameserver
    iniset $NOVA_CONF bluecat bcn_nova_logfile $bcn_nova_logfile
    iniset $NOVA_CONF bluecat bcn_nova_ttl $bcn_nova_ttl
    iniset $NOVA_CONF bluecat bcn_nova_domain_override $bcn_nova_domain_override
    iniset $NOVA_CONF bluecat bcn_nova_debuglevel $bcn_nova_debuglevel
    iniset $NOVA_CONF bluecat bcn_nova_TSIG $bcn_nova_TSIG
}

DIR_BLUECAT=$DEST/bluecatopenstack

# check for service enabled
if is_service_enabled bluecatopenstack; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services for Bluecat OpenStack"
        #install_package cowsay

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "*** Installing BlueCat OpenStack Drivers"
        install_bluecat_openstack

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "*** Configuring BlueCat Openstack Drivers"
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
