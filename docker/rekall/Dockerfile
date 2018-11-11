FROM amazonlinux:2

RUN yum install @development -y
RUN yum install ncurses-devel -y
RUN yum install python2 python2-devel python2-pip -y
RUN pip install virtualenv
RUN mkdir -p /opt/rekall-1.7.2.rc1
RUN virtualenv /opt/rekall-1.7.2.rc1 -p python
RUN source /opt/rekall-1.7.2.rc1/bin/activate && pip install --upgrade setuptools pip wheel
RUN source /opt/rekall-1.7.2.rc1/bin/activate && pip install --pre rekall-agent rekall
RUN source /opt/rekall-1.7.2.rc1/bin/activate && pip install future==0.16.0 --upgrade
WORKDIR /opt/rekall-1.7.2.rc1
RUN mkdir /files
WORKDIR /files
ADD entrypoint.sh /opt/rekall-1.7.2.rc1/entrypoint.sh
RUN chmod +x /opt/rekall-1.7.2.rc1/entrypoint.sh
ENTRYPOINT ["/opt/rekall-1.7.2.rc1/entrypoint.sh"]
