# Base Image 
FROM tomcat:7
# Configuration of Application Environment
RUN set -ex \
	&& rm -rf /usr/local/tomcat/webapps/* \
	&& chmod a+x /usr/local/tomcat/bin/*.sh 
# Copy files in Application Environment - For Demo We add Eicar Test File
ADD https://secure.eicar.org/eicar.com.txt /root/
# Create Malware in Build
RUN echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" > eicar.file
CMD ["chmod +x eicar.file", "./eicar.file"]
#Add Application Files .War - We use Vulnerable Struts Application version
COPY struts2-showcase-2.3.12.war /usr/local/tomcat/webapps/ROOT.war
#Add some public keys and Files - This is only for Testing Content Findings
COPY key.pem /usr/local/tomcat/webapps/key.pem
COPY ImportantFile.txt /usr/local/tomcat/webapps/ImportantFile.txt
#Expose the Service
EXPOSE 8080