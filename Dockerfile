FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install prerequisites and add Zeek repository
RUN apt-get update && \
    apt-get install -y \
        curl \
        gnupg2 \
        ca-certificates \
        git \
        build-essential \
        autoconf \
        automake \
        libtool \
        libpcap-dev \
        libjson-c-dev \
        libnuma-dev \
        libgcrypt20-dev \
        libgpg-error-dev && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg && \
    echo 'deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/zeek.list > /dev/null && \
    apt-get update && \
    apt-get install -y \
        tshark \
        zeek \
        p0f \
        python3 \
        python3-pip \
        tcpdump && \
    pip3 install pandas && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build and install nDPI 5.0
RUN cd /tmp && \
    git clone --depth 1 --branch 5.0 https://github.com/ntop/nDPI.git && \
    cd nDPI && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd / && \
    rm -rf /tmp/nDPI

# Ensure Zeek is in PATH (it might be installed in /opt/zeek/bin or /usr/bin)
RUN if [ -d "/opt/zeek/bin" ]; then \
        echo 'export PATH=/opt/zeek/bin:$PATH' >> /etc/profile.d/zeek.sh; \
    fi && \
    if [ -d "/usr/local/zeek/bin" ]; then \
        echo 'export PATH=/usr/local/zeek/bin:$PATH' >> /etc/profile.d/zeek.sh; \
    fi

# Add Zeek to PATH for non-interactive shells
ENV PATH="${PATH}:/opt/zeek/bin:/usr/local/zeek/bin:/usr/bin"

WORKDIR /workspace

# Copy scripts into the image
COPY analyze_pcap.sh /usr/local/bin/analyze_pcap.sh
COPY enrich_pcap.py /usr/local/bin/enrich_pcap.py
COPY mac_oui_lookup.py /usr/local/bin/mac_oui_lookup.py
COPY device_fingerprint.py /usr/local/bin/device_fingerprint.py

RUN chmod +x /usr/local/bin/analyze_pcap.sh /usr/local/bin/mac_oui_lookup.py /usr/local/bin/device_fingerprint.py

ENTRYPOINT ["/bin/bash"]

