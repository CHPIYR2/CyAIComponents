# 使用Ubuntu 20.04 LTS 作為基本映像檔
FROM ubuntu:20.04

# 避免安裝過程中的問題提示
ARG DEBIAN_FRONTEND=noninteractive

# 設定時區和本地化
RUN apt-get update && apt-get install -y locales && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8 
ENV LANGUAGE en_US:en 
ENV LC_ALL en_US.UTF-8

# 更新套件列表並安裝所需要的依賴
RUN apt-get update && apt-get install -y \
    sudo \
    vim \
    python3-pip \
    cmake \
    ninja-build \
    libpcap-dev \
    unzip \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# 設定工作目錄
WORKDIR /HyperVision

# 使用 git clone 從GitHub下載 HyperVision 專案
RUN git clone https://github.com/YuCheng1122/HyperVision .

# 安裝依賴、建構和執行腳本
# 注意: 確保這些腳本可以在無人工介入的環境下自動執行
RUN ./env/install_all.sh && \
    ./script/rebuild.sh && \
    ./script/expand.sh && \
    cd build && \
    set -eux && \
    ninja