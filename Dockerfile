FROM tomcat:7
MAINTAINER piesecurity <admin@pie-secure.org>
RUN set -ex \
	&& rm -rf /usr/local/tomcat/webapps/* \
	&& chmod a+x /usr/local/tomcat/bin/*.sh
#ADD https://secure.eicar.org/eicar.com.txt /root/
COPY struts2-showcase-2.3.12.war /usr/local/tomcat/webapps/ROOT.war
COPY key.pem /usr/local/tomcat/webapps/key.pem
EXPOSE 8080
