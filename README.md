# ECS pipeline for Zeek with Fluent Bit
## Overview
Elastic Common Schema (ECS) pipeline for Zeek/Bro network traffic analyzer with [Fluent Bit](https://fluentbit.io/).

## Zeek logs
The following [Zeek logs](https://docs.zeek.org/en/current/script-reference/log-files.html) are supported:

- [`Conn::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)
- [`DHCP::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info)
- [`DNS::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info)
- [`HTTP::Info`](https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info)
- [`SSL:Info`](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info)

The pipeline maps original key/values from the Zeek logs into proper [ECS keys](https://www.elastic.co/guide/en/ecs/current/index.html). If a key from any of the logs above doesn't have a corresponding key in ECS, it is mapped as `zeek.<log_type>.<key>`. For example, `tags` from `HTTP::Info` are mapped as `zeek.http.tags`.
  
The pipeline supports both tabular as well as JSON log formats. Parcers for the tabular format are provided for sets of fields that Zeek logs by default . If optional fields are enabled, or if additionall Zeek modules, like [`bro-community-id`](https://github.com/corelight/bro-community-id) or [`ja3`](https://github.com/salesforce/ja3), are installed, it is recommended to use JSON format as input. The pipeline is tested with JSON format produced by  [`json-streaming-logs`](https://github.com/corelight/json-streaming-logs) Zeek module. If enabling JSON logging is not an option, modification of the parcers in [`parsers.conf`](parsers.conf) shall be done to accomodate additonal fields.

## Installation
Prerequisites:

- Fluent Bit v1.2+
- Read-only access to Bro 2.6+ or Zeek 3.0+ logs

Create a user for running Fluent Bit

    TBD for username:group fluentbit:fluentbit

Choose a folder for the pipeline code and clone the repository

    export FBIT_PATH=/usr/local/etc/fluent-bit
    cd $FBIT_PATH
    export FBIT_PIPELINE=zeek
    git clone https://github.com/bortok/zeek-ecs-fluent-bit.git $FBIT_PIPELINE
    chgrp fluentbit $FBIT_PIPELINE
    chmod g+w $FBIT_PIPELINE

Edit startup script `fluent-bit.start` to define Elasticsearch connection parameters, as well as location of the pipeline.

    export ES_HOST=
    export ES_PORT=
    export ES_USER=
    export ES_PASSWORD=
    
    export FBIT_PATH="/usr/local/etc/fluent-bit/zeek"

Edit input configuration in `fluent-bit-input.conf` to provide information about your Zeek deployment and update paths to Zeek log files, if needed.

    @SET observer_hostname=localhost
    @SET observer_product=zeek
    @SET observer_version=3.0.1
    @SET labels_env=prod

Start Fluent Bit pipeline

    sudo ./fluent-bit.start

## Copyright notice

COPYRIGHT 2019 - 2020 [Alex Bortok](https://github.com/bortok)

This code is provided under the TBD.
You can find the complete terms in LICENSE.txt