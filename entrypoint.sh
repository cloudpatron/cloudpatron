#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Require variables.
if [ -z "${CLOUDPATRON_HTTP_HOST-}" ] ; then
    echo "Environment variable CLOUDPATRON_HTTP_HOST required. Exiting."
    exit 1
fi

# Allow optional variables.
if [ -z "${CLOUDPATRON_BACKLINK-}" ] ; then
    export CLOUDPATRON_BACKLINK=""
fi

# cloudpatron service
if ! test -d /etc/sv/cloudpatron ; then
    mkdir /etc/sv/cloudpatron
    cat <<RUNIT >/etc/sv/cloudpatron/run
#!/bin/sh
exec /usr/bin/cloudpatron --http-host "${CLOUDPATRON_HTTP_HOST}" --backlink "${CLOUDPATRON_BACKLINK}"
RUNIT
    chmod +x /etc/sv/cloudpatron/run

    # cloudpatron service log
    mkdir /etc/sv/cloudpatron/log
    mkdir /etc/sv/cloudpatron/log/main
    cat <<RUNIT >/etc/sv/cloudpatron/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/sv/cloudpatron/log/run
    ln -s /etc/sv/cloudpatron /etc/service/cloudpatron
fi

exec $@
