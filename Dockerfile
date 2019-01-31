FROM phusion/baseimage:0.11
MAINTAINER github.com/cloudpatron/cloudpatron

COPY cloudpatron-linux-amd64 /usr/bin/cloudpatron
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENV DEBIAN_FRONTEND noninteractive

RUN chmod +x /usr/bin/cloudpatron /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]

CMD [ "/sbin/my_init" ]
