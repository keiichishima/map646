FROM debian:jessie

RUN apt update && apt install -y make g++ libjsoncpp-dev
#RUN ln -s /usr/include/jsoncpp/json/ /usr/include/json
#RUN apt install -y libjson-c-dev

RUN apt-get install -y libjson0 libjson0-dev


RUN mkdir /map646
WORKDIR /map646

COPY / .
RUN make


FROM debian:jessie
LABEL maintainer="frank.villaro@infomaniak.com"
RUN apt-get update && apt-get install -y libjson0

WORKDIR /root/
COPY --from=0 /map646/map646 .
COPY entrypoint.sh .

ENTRYPOINT [ "./entrypoint.sh" ]
