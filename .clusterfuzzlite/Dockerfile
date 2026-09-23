# Copyright 2026 the rustbgpd authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04
# crates/cli's build script compiles the gRPC protos, so the rbgp fuzz crate
# needs protoc. Same pinned archive and digest as the CI installer
# (.github/pinned-archives.sha256).
RUN curl -sSfL --connect-timeout 10 --max-time 120 \
        --retry 5 --retry-all-errors --retry-delay 5 --retry-max-time 180 \
        -o /tmp/protoc.zip \
        https://github.com/protocolbuffers/protobuf/releases/download/v25.3/protoc-25.3-linux-x86_64.zip \
    && echo "f853e691868d0557425ea290bf7ba6384eef2fa9b04c323afab49a770ba9da80  /tmp/protoc.zip" | sha256sum -c - \
    && unzip -q -o /tmp/protoc.zip -d /usr/local bin/protoc 'include/*' \
    && rm -f /tmp/protoc.zip \
    && test "$(protoc --version)" = "libprotoc 25.3"
ENV PROTOC=/usr/local/bin/protoc
COPY . $SRC/rustbgpd
WORKDIR $SRC/rustbgpd
RUN toolchain="$(cat fuzz/rust-nightly.txt)" \
    && rustup toolchain install "$toolchain" --profile minimal --target x86_64-unknown-linux-gnu \
    && cargo "+$toolchain" install cargo-fuzz --version 0.13.2 --locked
COPY .clusterfuzzlite/build.sh $SRC/
