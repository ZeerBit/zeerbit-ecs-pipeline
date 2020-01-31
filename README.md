# ECS pipeline for Zeek with Fluent Bit
## Overview
Elastic Common Schema (ECS) pipeline for Zeek/Bro network traffic analyzer with [Fluent Bit](https://fluentbit.io/).

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

# Copyright notice

COPYRIGHT 2019 - 2020 [Alex Bortok](https://github.com/bortok)

This code is provided under the TBD.
You can find the complete terms in LICENSE.txt