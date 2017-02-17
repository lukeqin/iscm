# iscm
Server network and service management

该程序是为了让零linux能力的人也能配置服务器的网络和服务。
功能：
1、配置和查询服务器网络。
2、配置和查询服务（通过supervisor管理服务，可以是任何服务）。

该程序可以打包为rpm包，和它管理的服务（也打包为rpm）一起集成到定制的ISO镜像中。安装好系统自动启动iscm服务，在图形界面使用网页配置网络和服务。第一次在本地配置网络和服务，后期可以远程管理网络和服务。
iscm可以作为我github另一个程序（ratel）的子模块。

运行步骤：
1、安装python和tornado。
2、python2.6 iscm.py。
