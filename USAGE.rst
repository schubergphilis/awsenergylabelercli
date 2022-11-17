=====
Usage
=====




.. code-block:: bash

    aws-energy-labeler --help
    usage: aws-energy-labeler    [-h] [--log-config LOGGER_CONFIG]
                                 [--log-level {debug,info,warning,error,critical}]
                                 --region REGION
                                 [--organizations-zone-name ORGANIZATIONS_ZONE_NAME]
                                 [--audit-zone-name AUDIT_ZONE_NAME]
                                 [--single-account-id SINGLE_ACCOUNT_ID]
                                 [--frameworks FRAMEWORKS]
                                 [--allowed-account-ids ALLOWED_ACCOUNT_IDS]
                                 [--denied-account-ids DENIED_ACCOUNT_IDS]
                                 [--allowed-regions ALLOWED_REGIONS]
                                 [--denied-regions DENIED_REGIONS]
                                 [--export-path EXPORT_PATH]
                                 [--export-metrics-only] [--to-json]
                                 [--report-closed-findings-days REPORT_CLOSED_FINDINGS_DAYS]
                                 [--report-suppressed-findings]
                                 [--account-thresholds ACCOUNT_THRESHOLDS]
                                 [--zone-thresholds ZONE_THRESHOLDS]
                                 [--security-hub-query-filter SECURITY_HUB_QUERY_FILTER]
                                 [--validate-metadata-file VALIDATE_METADATA_FILE]
                                 [--version]

    A cli to label accounts and security zones with energy labels based on
    Security Hub findings.

    optional arguments:
      -h, --help            show this help message and exit
      --log-config LOGGER_CONFIG, -l LOGGER_CONFIG
                            The location of the logging config json file
      --log-level {debug,info,warning,error,critical}, -L {debug,info,warning,error,critical}
                            Provide the log level. Defaults to info.
      --region REGION, -r REGION
                            The home AWS region, default is looking into the
                            environment for either "AWS_LABELER_REGION" or
                            "AWS_DEFAULT_REGION" variables.
      --organizations-zone-name ORGANIZATIONS_ZONE_NAME, -o ORGANIZATIONS_ZONE_NAME
                            The name of the Organizations Zone to label. Implies
                            access to organizations api in aws.Mutually exclusive
                            with --single-account-id argument and --audit-zone-
                            name.
      --audit-zone-name AUDIT_ZONE_NAME, -z AUDIT_ZONE_NAME
                            The name of the Audit Zone to label. Does not need
                            access to organizations api in aws, retrieves accounts
                            from security hub, will not report on the audit
                            account itself.Mutually exclusive with --single-
                            account-id argument and --organizations-zone-name.
      --single-account-id SINGLE_ACCOUNT_ID, -s SINGLE_ACCOUNT_ID
                            Run the labeler on a single account. Mutually
                            exclusive with --organizations-zone-name and --audit-
                            zone-name argument.
      --frameworks FRAMEWORKS, -f FRAMEWORKS
                            The list of applicable frameworks: ["aws-foundational-
                            security-best-practices", "cis", "pci-dss"],
                            default=["aws-foundational-security-best-practices"].
                            Setting the flag with an empty string argument will
                            set no frameworks for filters.
      --allowed-account-ids ALLOWED_ACCOUNT_IDS, -a ALLOWED_ACCOUNT_IDS
                            A list of AWS Account IDs for which an energy label
                            will be produced. Mutually exclusive with --denied-
                            account-ids and --single-account-id arguments.
      --denied-account-ids DENIED_ACCOUNT_IDS, -d DENIED_ACCOUNT_IDS
                            A list of AWS Account IDs that will be excluded from
                            producing the energy label. Mutually exclusive with
                            --allowed-account-ids and --single-account-id
                            arguments.
      --allowed-regions ALLOWED_REGIONS, -ar ALLOWED_REGIONS
                            A list of AWS regions included in producing the energy
                            label.Mutually exclusive with --denied-regions
                            argument.
      --denied-regions DENIED_REGIONS, -dr DENIED_REGIONS
                            A list of AWS regions excluded from producing the
                            energy label.Mutually exclusive with --allowed-regions
                            argument.
      --export-path EXPORT_PATH, -p EXPORT_PATH
                            Exports a snapshot of chosen data in JSON formatted
                            files to the specified directory or S3 location.
      --export-metrics-only, -e
                            Exports metrics/statistics without sensitive findings
                            data if set, in JSON formatted files to the specified
                            directory or S3 location, default is export all data.
      --to-json, -j         Return the report in json format.
      --report-closed-findings-days REPORT_CLOSED_FINDINGS_DAYS, -rd REPORT_CLOSED_FINDINGS_DAYS
                            If set the report will contain info on the number of
                            findings that were closed during the provided days
                            count
      --report-suppressed-findings, -rs
                            If set the report will contain info on the number of
                            suppressed findings
      --account-thresholds ACCOUNT_THRESHOLDS, -at ACCOUNT_THRESHOLDS
                            If set the account thresholds will be used instead of
                            the default ones. Usage of this option will be
                            reported on the report output and the metadata file
                            upon export.
      --zone-thresholds ZONE_THRESHOLDS, -zt ZONE_THRESHOLDS
                            If set the zone thresholds will be used instead of the
                            default ones. Usage of this option will be reported on
                            the report output and the metadata file upon export.
      --security-hub-query-filter SECURITY_HUB_QUERY_FILTER, -sf SECURITY_HUB_QUERY_FILTER
                            If set, this filter will be used instead of the
                            default built in. Usage of this option will be
                            reported on the report output and the metadata file
                            upon export. Usage of the allowed ips and denied ips
                            options will still affect the filter as well as the
                            default set frameworks. If no framework filtering is
                            needed the built in default frameworks can be
                            overriden by calling the "-f" option with "" as an
                            argument.
      --validate-metadata-file VALIDATE_METADATA_FILE, -vm VALIDATE_METADATA_FILE
                            Validates a metadata file. If this argument is set any
                            other argument is effectively disregarded and only the
                            file provided is processed.
      --version, -v         Prints the version of the tool. If this argument is
                            set any other argument is effectively disregarded.
