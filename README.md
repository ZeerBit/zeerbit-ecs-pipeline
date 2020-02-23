# Elastic Common Schema (ECS) ingest pipeline for Zeek network traffic analyzer 
## Overview
ZeerBit-ECS-Pipeline is an Elasticsearch ingest pipeline for [Zeek](https://www.zeek.org/) network traffic analyzer. It maps original Zeek log data into [ECS](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html) format. The pipeline is designed for [Fluent Bit](https://fluentbit.io/) log processor with goals of achieving:

- high performance
- small footprint

## Zeek logs
The following [Zeek logs](https://docs.zeek.org/en/current/script-reference/log-files.html) are supported:

- [`Conn::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)
- [`DHCP::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info)
- [`DNS::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info)
- [`HTTP::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info)
- [`SSL:Info`](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info)

The pipeline maps original key/values from the Zeek logs into proper [ECS Fields](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html). If a key from any of the logs above doesn't have a corresponding ECS field, it is mapped as `zeek.<log_type>.<key>`. For example, `info_msg` from `HTTP::Info` is mapped as `zeek.http.info_msg`.
  
The pipeline supports both tabular, as well as JSON log formats. Parcers for the tabular format are provided for sets of fields that Zeek logs by default . If optional fields are enabled, or additional Zeek modules, like [`bro-community-id`](https://github.com/corelight/bro-community-id) or [`ja3`](https://github.com/salesforce/ja3), are installed, it is recommended to use JSON format as input. The pipeline is tested with JSON format produced by  [`json-streaming-logs`](https://github.com/corelight/json-streaming-logs) Zeek module. If enabling JSON logging is not an option, modification of `Regex` expressions in `bro_<log_type>_parser` configuration blocks in [`parsers.conf`](parsers.conf) shall be done to accomodate additonal fields.

## Installation
Prerequisites:

- Fluent Bit v1.2+
- Read access to Bro 2.6+ or Zeek 3.0+ logs

Create a user for running Fluent Bit. Depending on permissions of Zeek log directory, making `fluentbit` user a member of a group that has read access to Zeek log files might be nessesary with `-G <zeek_read_group>` parameter:

    useradd -r fluentbit -g fluentbit -s /usr/sbin/nologin    

Choose a folder for the pipeline code and clone the repository

    export FBIT_PATH=/usr/local/etc/fluent-bit
    cd $FBIT_PATH
    export FBIT_PIPELINE=zeek
    git clone https://github.com/ZeerBit/zeerbit-ecs-pipeline.git $FBIT_PIPELINE
    chgrp fluentbit $FBIT_PIPELINE
    chmod g+w $FBIT_PIPELINE

Edit startup script [`fluent-bit.start`](fluent-bit.start) to define Elasticsearch connection parameters, as well as location of the pipeline.

    export ES_HOST=
    export ES_PORT=
    export ES_USER=
    export ES_PASSWORD=
    
    export FBIT_PATH="/usr/local/etc/fluent-bit/zeek"

Edit input configuration in [`fluent-bit-input.conf`](fluent-bit-input.conf) to provide information about your Zeek deployment and update path to Zeek log file spool directory, if needed.

    @SET observer_hostname=localhost
    @SET observer_product=zeek
    @SET observer_version=3.0.1
    @SET labels_env=prod
    
    @SET zeeklogdir=/usr/local/zeek/spool/zeek

Start Fluent Bit pipeline

    sudo ./fluent-bit.start

## Copyright notice

COPYRIGHT 2019 - 2020 [Alex Bortok](https://github.com/bortok) and the [ZeerBit](https://github.com/zeerbit) contributors.

This code is provided under the TBD.
You can find the complete terms in LICENSE.txt