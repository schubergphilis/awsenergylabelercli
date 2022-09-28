=====
Usage
=====




.. code-block:: bash

    aws-energy-labeler --help
    usage: aws-energy-labeler [-h] [--log-config LOGGER_CONFIG]
                              [--log-level {debug,info,warning,error,critical}]
                              [--landing-zone-name LANDING_ZONE_NAME | --single-account-id SINGLE_ACCOUNT_ID]
                              [--region REGION]
                              [--frameworks [FRAMEWORKS [FRAMEWORKS ...]]]
                              [--allowed-account-ids [ALLOWED_ACCOUNT_IDS [ALLOWED_ACCOUNT_IDS ...]]]
                              [--denied-account-ids [DENIED_ACCOUNT_IDS [DENIED_ACCOUNT_IDS ...]]]
                              [--allowed-regions [ALLOWED_REGIONS [ALLOWED_REGIONS ...]]
                              | --denied-regions
                              [DENIED_REGIONS [DENIED_REGIONS ...]]]
                              [--export-path EXPORT_PATH]
                              [--export-metrics | --export-all] [--to-json]

    A cli to label accounts and landing zones with energy labels based on Security
    Hub finding.

    optional arguments:
      -h, --help            show this help message and exit
      --log-config LOGGER_CONFIG, -l LOGGER_CONFIG
                            The location of the logging config json file
      --log-level {debug,info,warning,error,critical}, -L {debug,info,warning,error,critical}
                            Provide the log level. Defaults to info.
      --landing-zone-name LANDING_ZONE_NAME, -n LANDING_ZONE_NAME
                            The name of the Landing Zone to label. Mutually
                            exclusive with --single-account-id argument.
      --single-account-id SINGLE_ACCOUNT_ID, -s SINGLE_ACCOUNT_ID
                            Run the labeler on a single account. Mutually
                            exclusive with --landing-zone-name argument.
      --region REGION, -r REGION
                            The home AWS region, default is None
      --frameworks [FRAMEWORKS [FRAMEWORKS ...]], -f [FRAMEWORKS [FRAMEWORKS ...]]
                            The list of applicable frameworks: ["aws-foundational-
                            security-best-practices", "cis", "pci-dss"],
                            default=["aws-foundational-security-best-practices"]
      --allowed-account-ids [ALLOWED_ACCOUNT_IDS [ALLOWED_ACCOUNT_IDS ...]], -a [ALLOWED_ACCOUNT_IDS [ALLOWED_ACCOUNT_IDS ...]]
                            A list of AWS Account IDs for which an energy label
                            will be produced. Mutually exclusive with --denied-
                            account-ids and --single-account-id arguments.
      --denied-account-ids [DENIED_ACCOUNT_IDS [DENIED_ACCOUNT_IDS ...]], -d [DENIED_ACCOUNT_IDS [DENIED_ACCOUNT_IDS ...]]
                            A list of AWS Account IDs that will be excluded from
                            producing the energy label. Mutually exclusive with
                            --allowed-account-ids and --single-account-id
                            arguments.
      --allowed-regions [ALLOWED_REGIONS [ALLOWED_REGIONS ...]], -ar [ALLOWED_REGIONS [ALLOWED_REGIONS ...]]
                            A list of AWS regions included in producing the energy
                            label.Mutually exclusive with --denied-regions
                            argument.
      --denied-regions [DENIED_REGIONS [DENIED_REGIONS ...]], -dr [DENIED_REGIONS [DENIED_REGIONS ...]]
                            A list of AWS regions excluded from producing the
                            energy label.Mutually exclusive with --allowed-regions
                            argument.
      --export-path EXPORT_PATH, -p EXPORT_PATH
                            Exports a snapshot of chosen data in JSON formatted
                            files to the specified directory or S3 location.
      --export-metrics, -em
                            Exports metrics/statistics without sensitive findings
                            data in JSON formatted files to the specified
                            directory or S3 location.
      --export-all, -ea     Exports metrics/statistics along with sensitive
                            findings data in JSON formatted files to the specified
                            directory or S3 location.
      --to-json, -j         Return the report in json format.
