Overview
============

This tool builds a replication topology as described in the configuration.  By default, it plans and applies changes related to the current host, but it can also be run centrally to plan and apply changes for the entire topology.

Requirements
============

The Python packages `python-ldap` and `python-enum34` are required.

Configuration
============

A configuration file is required.  By default the tool looks for a file named 'replform.rf' in the same directory as itself.  It is a JSON-formatted file which describes the desired replication topology.  Only 'suppliers' and 'consumers' are supported, not hubs.

At the top-level, 'suffix', 'repman', 'suppliers', and 'consumers' are all required.  For example:

    //comments aren't supported in JSON, but we'll use them here for examples

    {
      // 'suffix' is the same for every host in the cluster
      "suffix": "dc=bozemanpass,dc=local"

      // a list of suppliers
      "suppliers": [
        {
          // every supplier must have a unique replica id number
          "replicaid": 5,

          // the LDAP host
          "hostname": "test5.bozemanpass.local",

          // if this is 636, LDAPS is assumed, else LDAP
          "port": 389,

          // the DN and PW used to bind to the server
          "binddn": "cn=Directory Manager",
          "bindpw": "secret12",

          // the directory for the replication changelog
          // when creating the changelog, the parent directory
          // must exist, but the leaf directory must not
          "changelogdir": "/var/lib/dirsrv/slapd-bpi/changelogdb"

          // the replication manager entry
          "repman": {
            "dn": "cn=repman,cn=config",
            "pw": "secret12"
          }
        },
        {
          // what supplier to use if initializing over the wire
          "init_from": "test76.bozemanpass.local",

          "replicaid": 76,
          "hostname": "test5.bozemanpass.local",
          "port": 389,
          "binddn": "cn=Directory Manager",
          "bindpw": "secret12",
          "changelogdir": "/var/lib/dirsrv/slapd-bpi/changelogdb"
          "repman": {
            "dn": "cn=repman,cn=config",
            "pw": "secret12"
          }
        }
       ],

      // a list of consumers
      "consumers": [
        
        // consumers should not have changelog or replica_id information

        {
          "init_from": "test5.bozemanpass.local",
          "hostname": "test6.bozemanpass.local",
          "port": 389,
          "binddn": "cn=Directory Manager",
          "bindpw": "secret12",
          "repman": {
            "dn": "cn=repman,cn=config",
            "pw": "secret12"
          }
        },
        {
          "init_from": "test76.bozemanpass.local",
          "hostname": "test7.bozemanpass.local",
          "port": 389,
          "binddn": "cn=Directory Manager",
          "bindpw": "secret12",
          "repman": {
            "dn": "cn=repman,cn=config",
            "pw": "secret12"
          }
        }
       ]
    }


Usage
============
    usage: replform.py <plan | apply> [-h] [-f CFGFILE] [-v] [--initialize]
                                      [--remove-missing] [--only-for ONLYFOR] [-g]
    
    optional arguments:
      -h, --help            show this help message and exit
      -f CFGFILE, --config-file CFGFILE
                            Configuration file. (default: replform.rf)
      -v, --verbose         Verbose output (default: False)
      --initialize          Initialize replicas. (default: False)
      --remove-missing      Remove agreements to missing servers. (default: False)
      --only-for ONLYFOR    Examine the specified host. Default is the current host.
      -g, --global          Examine all servers. Default is the current host.

Examples
============

In the replform.py output below, '+' indicates a task or entry that will be added, '-' something that will be removed, and '!' a warning or important information.

To plan actions for the current server (the default target) run the 'plan' sub-command:

    $ replform.py plan

    PLAN: test76.bozemanpass.local
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : disable_schema_mod
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test5.bozemanpass.local:389 (ReplicaType.supplier)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)

To execute the changes, use the 'apply' sub-command:

    $ replform.py apply

    APPLY: test76.bozemanpass.local
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : disable_schema_mod
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test5.bozemanpass.local:389 (ReplicaType.supplier)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)


Running again will show no changes that need to be made:

    $ replform.py plan

    PLAN: test76.bozemanpass.local

NOTE: The tool does not store any state.  It inspects the servers over LDAP each time it is run.

This allows the tool to be run periodically with shared configuration, each server in the cluster handling its own tasks
to configure itself for replication.

It is also possible to plan actions for the entire cluster with the '--global' flag:

    $ replform.py plan --global

    PLAN: global
    !	test5.bozemanpass.local:389 (ReplicaType.supplier) : uninitialized -> test76.bozemanpass.local:389 (ReplicaType.supplier) 
    !	test5.bozemanpass.local:389 (ReplicaType.supplier) : uninitialized -> test6.bozemanpass.local:389 (ReplicaType.consumer) 
    !	test5.bozemanpass.local:389 (ReplicaType.supplier) : uninitialized -> test7.bozemanpass.local:389 (ReplicaType.consumer) 
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : disable_schema_mod
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test6.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test6.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test7.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test7.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test5.bozemanpass.local:389 (ReplicaType.supplier)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)

By default, replicas are not initialized online, since the administrator may wish to initialize using file-system initialization, etc.
To add a task for online initialization, user the '--initialize' flag:

    $ replform.py plan --global --initialize
    PLAN: global
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : disable_schema_mod
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test6.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test6.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test7.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test7.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test5.bozemanpass.local:389 (ReplicaType.supplier)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)

To execute the planned changes, use the 'apply' command:

    $ replform.py apply --global --initialize
    APPLY: global
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : disable_schema_mod
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_changelog
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    +	test6.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test6.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test7.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test7.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test5.bozemanpass.local:389 (ReplicaType.supplier)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)

Running 'plan' again should show no actions to be taken:

    $ replform.py plan --global --initialize
    PLAN: global


Adding the '--verbose' option will show each of the actions which were tested ('=' means that the current state already matches the desired state):

    $ replform.py plan --global --initialize --verbose
    PLAN: global
    =	test76.bozemanpass.local:389 (ReplicaType.supplier) : disable_schema_mod
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    =	test76.bozemanpass.local:389 (ReplicaType.supplier) : add_repman
    =	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_replica
    =	test6.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    =	test6.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    =	test7.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    =	test7.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test76.bozemanpass.local:389 (ReplicaType.supplier)
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    =	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test7.bozemanpass.local:389 (ReplicaType.consumer)
    =	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test5.bozemanpass.local:389 (ReplicaType.supplier)
    =	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test6.bozemanpass.local:389 (ReplicaType.consumer)
    =	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test7.bozemanpass.local:389 (ReplicaType.consumer)

Adding a new server (in this case, a consumer) to the cluster will result in new tasks to perform:

    $ replform.py plan --global --initialize
    PLAN: global
    +	test8.bozemanpass.local:389 (ReplicaType.consumer) : add_repman
    +	test8.bozemanpass.local:389 (ReplicaType.consumer) : create_replica
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test8.bozemanpass.local:389 (ReplicaType.consumer)
    +	test5.bozemanpass.local:389 (ReplicaType.supplier) : initialize_consumer -> test8.bozemanpass.local:389 (ReplicaType.consumer)
    +	test76.bozemanpass.local:389 (ReplicaType.supplier) : create_repl_agreement -> test8.bozemanpass.local:389 (ReplicaType.consumer)


To remove a consumer from the cluster (it is not possible to automate the removal of a supplier), use the '--remove-missing' option:

    $ replform.py plan --global --remove-missing
    PLAN: global
    -	test5.bozemanpass.local:389 (ReplicaType.supplier) : remove_repl_agreement -> test8.bozemanpass.local
    -	test76.bozemanpass.local:389 (ReplicaType.supplier) : remove_repl_agreement -> test8.bozemanpass.local

This makes no changes to the consumer server, it simply removes all the replication agreements from the suppliers.
