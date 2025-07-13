# Base image
FROM debian:12-slim
# Image creator
MAINTAINER imocence
# Set environment variables (avoid interactive installation prompts)
#ENV DEBIAN_FRONTEND=noninteractive
# Specify the working directory
WORKDIR /www/server

ADD panel.tar.gz /www/server/
ADD panel.tar.gz /www/server/
COPY install_bt.sh /www/server/

RUN chmod +x /www/server/install_bt.sh && echo y |bash /www/server/install_bt.sh

VOLUME ["/www/server/"]

# Set the ferrous port
EXPOSE 20 21 22 80 443 888 3306 8888

# Start the nginx prevent container exit
CMD /etc/init.d/bt start && rm -rf /www/server/panel/data/bind.pl && tail -f /dev/null