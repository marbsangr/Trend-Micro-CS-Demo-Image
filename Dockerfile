FROM node:8
ADD https://secure.eicar.org/eicar.com.txt ./
RUN apt-get install -y imagemagick
