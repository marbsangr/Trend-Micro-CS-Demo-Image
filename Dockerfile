FROM maven:3-jdk-8-alpine

MAINTAINER jrrdev

RUN mkdir -p /cve-2017-538/exploit && \
	mkdir -p /usr/src/cve-2017-538

ADD ./pom.xml /usr/src/cve-2017-538/pom.xml
ADD ./src /usr/src/cve-2017-538/src
ADD ./docker/entry-point.sh /cve-2017-538/entry-point.sh
ADD ./exploit/exploit.py /cve-2017-538/exploit/exploit.py

ADD ./key.pem /cve-2017-538/key/key.pem
ADD ./accesskey.csv /cve-2017-538/accesskey.csv

RUN chmod +x /cve-2017-538/entry-point.sh && \
	sync && \
	cd /usr/src/cve-2017-538 && \
	mvn package && \
	cp /usr/src/cve-2017-538/target/*.jar /cve-2017-538/cve-2017-538-example.jar && \
	rm -Rf /usr/src/cve-2017-538

WORKDIR /cve-2017-538

ENTRYPOINT ["./entry-point.sh"]

EXPOSE 8080

VOLUME ["/cve-2017-538/exploit/"]
