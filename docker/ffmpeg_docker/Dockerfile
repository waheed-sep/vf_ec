FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Dependencies
# Keeps all your existing libs + rsync/yasm for FFmpeg
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    yasm \
    nasm \
    git \
    python3 \
    linux-tools-common \
    libslang2 \
    libunwind8 \
    liblzma5 \
    libnuma1 \
    libelf1 \
    libdw1 \
    libzstd1 \
    libdebuginfod1 \
    libpfm4 \
    libpython3.12 \
    libperl5.38 \
    libtraceevent1 \
    libbabeltrace1 \
    rsync \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Setup paths
WORKDIR /app
RUN mkdir -p /app/inputs \
    && mkdir -p /app/output

# 3. Git fix
RUN git config --global --add safe.directory '*'

# 4. Remove default perf wrapper
RUN rm -f /usr/bin/perf

# ------------------------------------------------------------------
# DOWNLOAD RESOURCES (Pre-seeding the image)
# ------------------------------------------------------------------

# A. Download FFmpeg Repo
RUN git clone https://github.com/FFmpeg/FFmpeg.git /app/inputs/FFmpeg

# B. Download FATE Samples 
# (Doing this here saves time every time you run the container)
RUN rsync -aL rsync://fate-suite.ffmpeg.org/fate-suite/ /app/inputs/fate-samples/

# ------------------------------------------------------------------
# COPY MODULAR SCRIPTS
# ------------------------------------------------------------------

COPY docker/vfec_init.py /app/
COPY docker/vfec_output.py /app/

# Copy the Project-Specific Plugin (From Subdir)
# It lands in /app/ so it can easily import the others
COPY docker/ffmpeg_docker/ffmpeg_engine.py /app/

# ------------------------------------------------------------------

# Set Default Env Variable
ENV REPO_NAME=FFmpeg

# Run the Orchestrator
CMD ["python3", "vfec_init.py"]