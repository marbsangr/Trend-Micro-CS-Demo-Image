FROM tomcat:8.5-alpine

LABEL maintainer="Niuren.Zhu <niuren.zhu@icloud.com>"

RUN set -x \

    && apk update \
    && apk add --no-cache unzip curl tzdata \
    && apk add --no-cache fontconfig ttf-dejavu \
    && rm -rf /var/cache/apk/*

RUN set -x \
    && mkdir -p ${CATALINA_HOME}/ibas \
    && mkdir -p ${CATALINA_HOME}/ibas/conf \
    && mkdir -p ${CATALINA_HOME}/ibas/data \
    && mkdir -p ${CATALINA_HOME}/ibas/logs \
    && mkdir -p ${CATALINA_HOME}/ibas_tools \
    && mkdir -p ${CATALINA_HOME}/ibas_lib \
    && rm -rf ${CATALINA_HOME}/webapps \
    && mkdir -p ${CATALINA_HOME}/webapps

RUN set -x \
    && curl -fsSL -o /tmp/btulz.transforms.tar http://maven.colorcoding.org/repository/maven-releases/org/colorcoding/tools/btulz.transforms/latest/btulz.transforms-latest.tar \
    && tar -xvf /tmp/btulz.transforms.tar -C ${CATALINA_HOME}/ibas_tools \
    && rm -f /tmp/btulz.transforms.tar \
    && curl -fsSL -o /tmp/btulz.scripts.tar http://maven.colorcoding.org/repository/maven-releases/org/colorcoding/tools/btulz.scripts/latest/btulz.scripts-latest.tar \
    && mkdir -p /tmp/btulz.scripts \
    && tar -xvf /tmp/btulz.scripts.tar -C /tmp/btulz.scripts \
    && rm -f /tmp/btulz.scripts.tar \
    && cp -f /tmp/btulz.scripts/ibas/deploy_apps.sh ${CATALINA_HOME}/deploy_apps.sh \
    && cp -f /tmp/btulz.scripts/ibas/initialize_apps.sh ${CATALINA_HOME}/initialize_apps.sh \
    && rm -rf /tmp/btulz.scripts

COPY conf/* ${CATALINA_HOME}/conf/
COPY ibas/ ${CATALINA_HOME}/ibas/

RUN chmod 775 ${CATALINA_HOME}/*.sh

VOLUME ${CATALINA_HOME}/ibas/
